//go:build linux

package ndpresponder

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"time"

	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

// defaultGateway returns the IPv6 default gateway on the interface, or an invalid
// Addr if there is none.
func defaultGateway(nl *netlink.Handle, link netlink.Link) (netip.Addr, error) {
	routes, err := nl.RouteList(link, unix.AF_INET6)
	if err != nil {
		return netip.Addr{}, fmt.Errorf("listing routes: %w", err)
	}
	for _, route := range routes {
		if route.Dst != nil {
			if ones, _ := route.Dst.Mask.Size(); ones != 0 {
				continue
			}
		}
		if gw, ok := netip.AddrFromSlice(route.Gw); ok {
			return gw, nil
		}
	}
	return netip.Addr{}, nil
}

// pinGateway waits for the gateway's neighbor entry to resolve, then marks it NOARP so the
// kernel stops probing it. Answers to our solicitations come back from the gateway to
// addresses the kernel does not own, which would otherwise keep the entry flapping.
// A permanent entry is left alone.
func pinGateway(ctx context.Context, nl *netlink.Handle, iface *net.Interface, gw netip.Addr, logger *slog.Logger) error {
	for {
		neighs, err := nl.NeighList(iface.Index, unix.AF_INET6)
		if err != nil {
			return fmt.Errorf("listing neighbors: %w", err)
		}
		for _, neigh := range neighs {
			ip, _ := netip.AddrFromSlice(neigh.IP)
			if ip != gw || len(neigh.HardwareAddr) != 6 {
				continue
			}
			switch neigh.State {
			case unix.NUD_PERMANENT, unix.NUD_NOARP:
				return nil
			case unix.NUD_REACHABLE:
				neigh.State = unix.NUD_NOARP
				if err := nl.NeighSet(&neigh); err != nil {
					return fmt.Errorf("pinning gateway neighbor: %w", err)
				}
				logger.Info("pinned gateway neighbor",
					slog.String("gateway", gw.String()),
					slog.String("lladdr", neigh.HardwareAddr.String()))
				return nil
			}
		}

		pokeNeighbor(iface, gw)
		logger.Debug("waiting for gateway neighbor entry", slog.String("gateway", gw.String()))
		select {
		case <-ctx.Done():
			return fmt.Errorf("gateway %s did not become reachable: %w", gw, ctx.Err())
		case <-time.After(time.Second):
		}
	}
}

// pokeNeighbor sends a throwaway datagram to ip so the kernel resolves its link-layer address.
func pokeNeighbor(iface *net.Interface, ip netip.Addr) {
	zone := ""
	if ip.IsLinkLocalUnicast() {
		zone = iface.Name
	}
	conn, err := net.DialUDP("udp6", nil, &net.UDPAddr{IP: ip.AsSlice(), Port: 9, Zone: zone})
	if err != nil {
		return
	}
	defer conn.Close()
	conn.Write([]byte{0})
}
