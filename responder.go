//go:build linux

// Package ndpresponder answers IPv6 neighbor solicitations for every address in a prefix on
// one interface, so the prefix can be used as source addresses without assigning them, and
// announces addresses to the default gateway before they are used.
package ndpresponder

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"sync"
	"time"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/afpacket"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

// Config holds the configuration for the NDP responder.
type Config struct {
	// Interface is the network interface to listen on, e.g. "eth0".
	Interface string

	// Prefix is the IPv6 prefix to answer for.
	Prefix netip.Prefix

	// Logger is the structured logger. Defaults to slog.Default().
	Logger *slog.Logger

	// AddLocalRoute adds `local <prefix> dev lo table local` on Start, so the kernel accepts
	// traffic for every address in the prefix, and removes it again on Close.
	AddLocalRoute bool

	// PinGateway waits on Start for the default gateway's neighbor entry to resolve and then
	// marks it NOARP, so the kernel stops probing it.
	PinGateway bool

	// GatewayTimeout bounds how long Start waits for the gateway when PinGateway is set.
	// Defaults to 30s.
	GatewayTimeout time.Duration
}

// Responder answers neighbor solicitations for Config.Prefix. Create it with New.
type Responder struct {
	config  Config
	iface   *net.Interface
	logger  *slog.Logger
	gateway netip.Addr // invalid if the interface has no IPv6 default route

	handle     *afpacket.TPacket
	routeAdded *netlink.Route

	ctx       context.Context
	cancel    context.CancelFunc
	wg        sync.WaitGroup
	closeOnce sync.Once
}

// pollTimeout bounds how long the capture loop blocks before checking for Close.
const pollTimeout = 500 * time.Millisecond

// New validates config and looks up the interface. Call Start to begin responding.
func New(config Config) (*Responder, error) {
	if config.Interface == "" {
		return nil, errors.New("ndpresponder: interface name is required")
	}
	if !config.Prefix.IsValid() || !config.Prefix.Addr().Is6() || config.Prefix.Addr().Is4In6() {
		return nil, fmt.Errorf("ndpresponder: prefix %s is not an IPv6 prefix", config.Prefix)
	}
	config.Prefix = config.Prefix.Masked()
	if config.Logger == nil {
		config.Logger = slog.Default()
	}
	if config.GatewayTimeout <= 0 {
		config.GatewayTimeout = 30 * time.Second
	}

	iface, err := net.InterfaceByName(config.Interface)
	if err != nil {
		return nil, fmt.Errorf("ndpresponder: interface %s: %w", config.Interface, err)
	}
	if len(iface.HardwareAddr) != 6 {
		return nil, fmt.Errorf("ndpresponder: interface %s has no Ethernet address", config.Interface)
	}

	ctx, cancel := context.WithCancel(context.Background())
	return &Responder{
		config: config,
		iface:  iface,
		logger: config.Logger.With(slog.String("component", "ndpresponder")),
		ctx:    ctx,
		cancel: cancel,
	}, nil
}

// Start sets up routes and the gateway, opens the capture socket and starts answering
// solicitations in the background. On error, call Close to undo partial setup.
func (r *Responder) Start() error {
	r.logger.Info("starting",
		slog.String("interface", r.iface.Name),
		slog.String("mac", r.iface.HardwareAddr.String()),
		slog.String("prefix", r.config.Prefix.String()))

	nl, err := netlink.NewHandle()
	if err != nil {
		return fmt.Errorf("ndpresponder: netlink: %w", err)
	}
	defer nl.Close()

	if r.config.AddLocalRoute {
		if err := r.addLocalRoute(nl); err != nil {
			return err
		}
	}

	link, err := nl.LinkByIndex(r.iface.Index)
	if err != nil {
		return fmt.Errorf("ndpresponder: link %s: %w", r.iface.Name, err)
	}
	if r.gateway, err = defaultGateway(nl, link); err != nil {
		return fmt.Errorf("ndpresponder: %w", err)
	}
	if r.gateway.IsValid() {
		r.logger.Info("found gateway", slog.String("gateway", r.gateway.String()))
		if r.config.PinGateway {
			ctx, cancel := context.WithTimeout(r.ctx, r.config.GatewayTimeout)
			err := pinGateway(ctx, nl, r.iface, r.gateway, r.logger)
			cancel()
			if err != nil {
				return fmt.Errorf("ndpresponder: %w", err)
			}
		}
	} else {
		r.logger.Warn("no IPv6 default gateway; announcements will not solicit it")
	}

	r.handle, err = afpacket.NewTPacket(afpacket.OptInterface(r.iface.Name), afpacket.OptPollTimeout(pollTimeout))
	if err != nil {
		return fmt.Errorf("ndpresponder: capture on %s: %w", r.iface.Name, err)
	}
	if err := r.handle.SetBPF(bpfFilter); err != nil {
		return fmt.Errorf("ndpresponder: BPF filter: %w", err)
	}

	r.wg.Add(1)
	go r.listen()
	return nil
}

// Close stops answering and undoes what Start set up. It is safe to call more than once.
func (r *Responder) Close() error {
	var err error
	r.closeOnce.Do(func() {
		r.cancel()
		r.wg.Wait() // the capture loop must be gone before its handle is closed
		if r.handle != nil {
			r.handle.Close()
		}
		if r.routeAdded != nil {
			if e := netlink.RouteDel(r.routeAdded); e != nil {
				err = fmt.Errorf("ndpresponder: removing local route: %w", e)
			}
		}
		r.logger.Info("stopped")
	})
	return err
}

// Announce tells the link that ip, which must be in the prefix, is about to be used as a
// source address: an unsolicited advertisement to all nodes, and a solicitation of the
// gateway from ip so the gateway creates a neighbor entry for it. Safe for concurrent use.
func (r *Responder) Announce(ip netip.Addr) error {
	if !r.config.Prefix.Contains(ip) {
		return fmt.Errorf("ndpresponder: %s is not in %s", ip, r.config.Prefix)
	}
	if r.handle == nil {
		return errors.New("ndpresponder: not started")
	}
	buf := gopacket.NewSerializeBuffer()
	if err := writeUnsolicitedAdvert(buf, r.iface.HardwareAddr, ip); err != nil {
		return fmt.Errorf("ndpresponder: building advertisement: %w", err)
	}
	if err := r.handle.WritePacketData(buf.Bytes()); err != nil {
		return fmt.Errorf("ndpresponder: sending advertisement: %w", err)
	}
	if r.gateway.IsValid() {
		if err := writeSolicit(buf, r.iface.HardwareAddr, ip, r.gateway); err != nil {
			return fmt.Errorf("ndpresponder: building solicitation: %w", err)
		}
		if err := r.handle.WritePacketData(buf.Bytes()); err != nil {
			return fmt.Errorf("ndpresponder: sending solicitation: %w", err)
		}
	}
	r.logger.Debug("announced", slog.String("ip", ip.String()), slog.String("gateway", r.gateway.String()))
	return nil
}

func (r *Responder) addLocalRoute(nl *netlink.Handle) error {
	lo, err := nl.LinkByName("lo")
	if err != nil {
		return fmt.Errorf("ndpresponder: loopback: %w", err)
	}
	route := &netlink.Route{
		LinkIndex: lo.Attrs().Index,
		Dst:       &net.IPNet{IP: r.config.Prefix.Addr().AsSlice(), Mask: net.CIDRMask(r.config.Prefix.Bits(), 128)},
		Type:      unix.RTN_LOCAL,
		Table:     unix.RT_TABLE_LOCAL,
		Protocol:  unix.RTPROT_BOOT,
		Scope:     unix.RT_SCOPE_HOST,
	}
	if err := nl.RouteAdd(route); err != nil {
		if errors.Is(err, unix.EEXIST) {
			r.logger.Info("local route already present", slog.String("prefix", r.config.Prefix.String()))
			return nil
		}
		return fmt.Errorf("ndpresponder: adding local route: %w", err)
	}
	r.routeAdded = route
	r.logger.Info("added local route", slog.String("prefix", r.config.Prefix.String()))
	return nil
}

func (r *Responder) listen() {
	defer r.wg.Done()
	parser := newSolicitationParser()
	buf := gopacket.NewSerializeBuffer()
	for r.ctx.Err() == nil {
		frame, _, err := r.handle.ZeroCopyReadPacketData()
		if err != nil {
			if !errors.Is(err, afpacket.ErrTimeout) {
				r.logger.Warn("capture error", slog.String("error", err.Error()))
				time.Sleep(pollTimeout)
			}
			continue
		}
		ns, ok := parser.parse(frame)
		if !ok || !r.config.Prefix.Contains(ns.TargetIP) {
			continue
		}
		log := r.logger.With(slog.String("ns", ns.String()))
		if err := writeAdvert(buf, ns, r.iface.HardwareAddr); err != nil {
			log.Warn("building advertisement", slog.String("error", err.Error()))
			continue
		}
		if err := r.handle.WritePacketData(buf.Bytes()); err != nil {
			log.Warn("sending advertisement", slog.String("error", err.Error()))
			continue
		}
		log.Debug("answered")
	}
}
