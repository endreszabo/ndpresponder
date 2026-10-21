package ndpresponder

import (
	"fmt"
	"net"
	"net/netip"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
	"golang.org/x/net/bpf"
)

// bpfFilter is the output of tcpdump -dd 'icmp6 && ip6[40]==135'.
var bpfFilter = []bpf.RawInstruction{
	{Op: 0x28, Jt: 0, Jf: 0, K: 0x0000000c},
	{Op: 0x15, Jt: 0, Jf: 8, K: 0x000086dd},
	{Op: 0x30, Jt: 0, Jf: 0, K: 0x00000014},
	{Op: 0x15, Jt: 3, Jf: 0, K: 0x0000003a},
	{Op: 0x15, Jt: 0, Jf: 5, K: 0x0000002c},
	{Op: 0x30, Jt: 0, Jf: 0, K: 0x00000036},
	{Op: 0x15, Jt: 0, Jf: 3, K: 0x0000003a},
	{Op: 0x30, Jt: 0, Jf: 0, K: 0x00000036},
	{Op: 0x15, Jt: 0, Jf: 1, K: 0x00000087},
	{Op: 0x6, Jt: 0, Jf: 0, K: 0x00040000},
	{Op: 0x6, Jt: 0, Jf: 0, K: 0x00000000},
}

var packetSerializeOpts = gopacket.SerializeOptions{
	FixLengths:       true,
	ComputeChecksums: true,
}

var (
	solicitTypeCode = layers.CreateICMPv6TypeCode(layers.ICMPv6TypeNeighborSolicitation, 0)
	advertTypeCode  = layers.CreateICMPv6TypeCode(layers.ICMPv6TypeNeighborAdvertisement, 0)

	allNodesIP  = netip.MustParseAddr("ff02::1")
	allNodesMAC = net.HardwareAddr{0x33, 0x33, 0x00, 0x00, 0x00, 0x01}
)

// NA flag bits (RFC 4861 section 4.4). The router flag is never set: we answer as a host.
const (
	naFlagSolicited = 0x40
	naFlagOverride  = 0x20
)

// ndpHopLimit is the only hop limit a valid NDP packet may carry (RFC 4861 section 7.1.1).
const ndpHopLimit = 255

// solicitedNode returns the solicited-node multicast address of ip (RFC 4291 section 2.7.1).
func solicitedNode(ip netip.Addr) netip.Addr {
	a := ip.As16()
	return netip.AddrFrom16([16]byte{0: 0xff, 1: 0x02, 11: 0x01, 12: 0xff, 13: a[13], 14: a[14], 15: a[15]})
}

// multicastMAC returns the Ethernet address that IPv6 multicast group ip maps to (RFC 2464 section 7).
func multicastMAC(ip netip.Addr) net.HardwareAddr {
	a := ip.As16()
	return net.HardwareAddr{0x33, 0x33, a[12], a[13], a[14], a[15]}
}

// NeighSolicitation contains information from an ICMPv6 neighbor solicitation packet.
type NeighSolicitation struct {
	SrcMAC   net.HardwareAddr
	SrcIP    netip.Addr // unspecified for duplicate address detection probes
	DstIP    netip.Addr
	TargetIP netip.Addr
}

func (ns NeighSolicitation) String() string {
	switch {
	case ns.SrcIP.IsUnspecified():
		return fmt.Sprintf("dad %s", ns.TargetIP)
	case ns.DstIP.IsMulticast():
		return fmt.Sprintf("who-has %s tell %s", ns.TargetIP, ns.SrcIP)
	}
	return fmt.Sprintf("is-alive %s tell %s", ns.TargetIP, ns.SrcIP)
}

// solicitationParser decodes neighbor solicitations from raw Ethernet frames.
type solicitationParser struct {
	eth     layers.Ethernet
	ip6     layers.IPv6
	icmp6   layers.ICMPv6
	solicit layers.ICMPv6NeighborSolicitation
	parser  *gopacket.DecodingLayerParser
	decoded []gopacket.LayerType
}

func newSolicitationParser() *solicitationParser {
	p := &solicitationParser{}
	p.parser = gopacket.NewDecodingLayerParser(layers.LayerTypeEthernet, &p.eth, &p.ip6, &p.icmp6, &p.solicit)
	return p
}

// parse returns the solicitation in frame, or false if frame is not a valid neighbor solicitation.
func (p *solicitationParser) parse(frame []byte) (NeighSolicitation, bool) {
	if err := p.parser.DecodeLayers(frame, &p.decoded); err != nil {
		return NeighSolicitation{}, false
	}
	if len(p.decoded) != 4 || p.decoded[3] != layers.LayerTypeICMPv6NeighborSolicitation {
		return NeighSolicitation{}, false
	}
	if p.ip6.HopLimit != ndpHopLimit || p.icmp6.TypeCode != solicitTypeCode {
		return NeighSolicitation{}, false
	}
	var ns NeighSolicitation
	var ok1, ok2, ok3 bool
	ns.SrcMAC = append(net.HardwareAddr(nil), p.eth.SrcMAC...)
	ns.SrcIP, ok1 = netip.AddrFromSlice(p.ip6.SrcIP)
	ns.DstIP, ok2 = netip.AddrFromSlice(p.ip6.DstIP)
	ns.TargetIP, ok3 = netip.AddrFromSlice(p.solicit.TargetAddress)
	if !ok1 || !ok2 || !ok3 || ns.TargetIP.IsMulticast() {
		return NeighSolicitation{}, false
	}
	return ns, true
}

// writeAdvert serializes a neighbor advertisement for ns into w, sent from hostMAC.
// Duplicate address detection probes are answered to all-nodes, as RFC 4861 section 7.2.4 requires.
func writeAdvert(w gopacket.SerializeBuffer, ns NeighSolicitation, hostMAC net.HardwareAddr) error {
	if ns.SrcIP.IsUnspecified() {
		return writeNA(w, hostMAC, allNodesMAC, allNodesIP, ns.TargetIP, naFlagOverride)
	}
	return writeNA(w, hostMAC, ns.SrcMAC, ns.SrcIP, ns.TargetIP, naFlagSolicited|naFlagOverride)
}

// writeUnsolicitedAdvert serializes an unsolicited neighbor advertisement for target to all-nodes.
func writeUnsolicitedAdvert(w gopacket.SerializeBuffer, hostMAC net.HardwareAddr, target netip.Addr) error {
	return writeNA(w, hostMAC, allNodesMAC, allNodesIP, target, naFlagOverride)
}

func writeNA(w gopacket.SerializeBuffer, srcMAC, dstMAC net.HardwareAddr, dstIP, target netip.Addr, flags uint8) error {
	eth := layers.Ethernet{
		SrcMAC:       srcMAC,
		DstMAC:       dstMAC,
		EthernetType: layers.EthernetTypeIPv6,
	}
	ip6 := layers.IPv6{
		Version:    6,
		SrcIP:      target.AsSlice(),
		DstIP:      dstIP.AsSlice(),
		NextHeader: layers.IPProtocolICMPv6,
		HopLimit:   ndpHopLimit,
	}
	icmp6 := layers.ICMPv6{TypeCode: advertTypeCode}
	icmp6.SetNetworkLayerForChecksum(&ip6)
	advert := layers.ICMPv6NeighborAdvertisement{
		Flags:         flags,
		TargetAddress: target.AsSlice(),
		Options: layers.ICMPv6Options{
			{Type: layers.ICMPv6OptTargetAddress, Data: srcMAC},
		},
	}
	return gopacket.SerializeLayers(w, packetSerializeOpts, &eth, &ip6, &icmp6, &advert)
}

// writeSolicit serializes a neighbor solicitation for target, sent from srcIP to target's
// solicited-node group. It carries our link-layer address, so the target creates a neighbor
// entry for srcIP (RFC 4861 section 7.2.3); routers ignore unsolicited advertisements for
// addresses they have no entry for.
func writeSolicit(w gopacket.SerializeBuffer, hostMAC net.HardwareAddr, srcIP, target netip.Addr) error {
	group := solicitedNode(target)
	eth := layers.Ethernet{
		SrcMAC:       hostMAC,
		DstMAC:       multicastMAC(group),
		EthernetType: layers.EthernetTypeIPv6,
	}
	ip6 := layers.IPv6{
		Version:    6,
		SrcIP:      srcIP.AsSlice(),
		DstIP:      group.AsSlice(),
		NextHeader: layers.IPProtocolICMPv6,
		HopLimit:   ndpHopLimit,
	}
	icmp6 := layers.ICMPv6{TypeCode: solicitTypeCode}
	icmp6.SetNetworkLayerForChecksum(&ip6)
	solicit := layers.ICMPv6NeighborSolicitation{
		TargetAddress: target.AsSlice(),
		Options: layers.ICMPv6Options{
			{Type: layers.ICMPv6OptSourceAddress, Data: hostMAC},
		},
	}
	return gopacket.SerializeLayers(w, packetSerializeOpts, &eth, &ip6, &icmp6, &solicit)
}
