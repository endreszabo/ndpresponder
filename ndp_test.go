package ndpresponder

import (
	"bytes"
	"net"
	"net/netip"
	"testing"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
)

var (
	hostMAC   = net.HardwareAddr{0x02, 0x00, 0x00, 0x00, 0x00, 0x01}
	routerMAC = net.HardwareAddr{0x02, 0x00, 0x00, 0x00, 0x00, 0xfe}
	routerIP  = netip.MustParseAddr("fe80::abcd:12ff:fe34:5678")
	targetIP  = netip.MustParseAddr("2001:db8:1:2::c000:201")
)

// decoded is a serialized NDP packet parsed back, with its ICMPv6 checksum verified.
type decoded struct {
	eth     *layers.Ethernet
	ip6     *layers.IPv6
	icmp6   *layers.ICMPv6
	advert  *layers.ICMPv6NeighborAdvertisement
	solicit *layers.ICMPv6NeighborSolicitation
}

func decode(t *testing.T, frame []byte) decoded {
	t.Helper()
	pkt := gopacket.NewPacket(frame, layers.LayerTypeEthernet, gopacket.Default)
	if el := pkt.ErrorLayer(); el != nil {
		t.Fatalf("decoding: %v", el.Error())
	}
	var d decoded
	d.eth, _ = pkt.Layer(layers.LayerTypeEthernet).(*layers.Ethernet)
	d.ip6, _ = pkt.Layer(layers.LayerTypeIPv6).(*layers.IPv6)
	d.icmp6, _ = pkt.Layer(layers.LayerTypeICMPv6).(*layers.ICMPv6)
	d.advert, _ = pkt.Layer(layers.LayerTypeICMPv6NeighborAdvertisement).(*layers.ICMPv6NeighborAdvertisement)
	d.solicit, _ = pkt.Layer(layers.LayerTypeICMPv6NeighborSolicitation).(*layers.ICMPv6NeighborSolicitation)
	if d.eth == nil || d.ip6 == nil || d.icmp6 == nil {
		t.Fatal("missing layers")
	}
	if d.ip6.HopLimit != ndpHopLimit {
		t.Errorf("hop limit = %d", d.ip6.HopLimit)
	}
	if int(d.ip6.Length) != len(d.ip6.Payload) {
		t.Errorf("IPv6 payload length = %d, actual %d", d.ip6.Length, len(d.ip6.Payload))
	}
	d.icmp6.SetNetworkLayerForChecksum(d.ip6)
	if err, v := d.icmp6.VerifyChecksum(); err != nil || !v.Valid {
		t.Errorf("ICMPv6 checksum invalid: %+v %v", v, err)
	}
	return d
}

// checkLinkLayerOption asserts opts holds exactly one well-formed 8-byte link-layer address option.
func checkLinkLayerOption(t *testing.T, raw []byte, opts layers.ICMPv6Options, typ layers.ICMPv6Opt) {
	t.Helper()
	if len(opts) != 1 || opts[0].Type != typ || !bytes.Equal(opts[0].Data, hostMAC) {
		t.Fatalf("options = %+v", opts)
	}
	// The option is the last 8 bytes of the ICMPv6 message: type, length in 8-octet units, MAC.
	opt := raw[len(raw)-8:]
	if opt[0] != byte(typ) || opt[1] != 1 || !bytes.Equal(opt[2:], hostMAC) {
		t.Errorf("raw option = % x", opt)
	}
}

func TestSolicitedNode(t *testing.T) {
	cases := map[string]string{
		"fe80::1":                   "ff02::1:ff00:1",
		"fe80::abcd:12ff:fe34:5678": "ff02::1:ff34:5678",
		"2001:db8::c000:201":        "ff02::1:ff00:201",
	}
	for in, want := range cases {
		got := solicitedNode(netip.MustParseAddr(in))
		if got.String() != want {
			t.Errorf("solicitedNode(%s) = %s, want %s", in, got, want)
		}
	}
	if mac := multicastMAC(netip.MustParseAddr("ff02::1:ff34:5678")); mac.String() != "33:33:ff:34:56:78" {
		t.Errorf("multicastMAC = %s", mac)
	}
}

func TestWriteAdvertSolicited(t *testing.T) {
	buf := gopacket.NewSerializeBuffer()
	ns := NeighSolicitation{SrcMAC: routerMAC, SrcIP: routerIP, DstIP: solicitedNode(targetIP), TargetIP: targetIP}
	if err := writeAdvert(buf, ns, hostMAC); err != nil {
		t.Fatal(err)
	}
	d := decode(t, buf.Bytes())
	if d.advert == nil {
		t.Fatal("not an advertisement")
	}
	if !bytes.Equal(d.eth.SrcMAC, hostMAC) || !bytes.Equal(d.eth.DstMAC, routerMAC) {
		t.Errorf("eth = %s -> %s", d.eth.SrcMAC, d.eth.DstMAC)
	}
	if !d.ip6.SrcIP.Equal(targetIP.AsSlice()) || !d.ip6.DstIP.Equal(routerIP.AsSlice()) {
		t.Errorf("ip = %s -> %s", d.ip6.SrcIP, d.ip6.DstIP)
	}
	if d.advert.Flags != naFlagSolicited|naFlagOverride || d.advert.Router() {
		t.Errorf("flags = %#x", d.advert.Flags)
	}
	if !d.advert.TargetAddress.Equal(targetIP.AsSlice()) {
		t.Errorf("target = %s", d.advert.TargetAddress)
	}
	checkLinkLayerOption(t, d.ip6.Payload, d.advert.Options, layers.ICMPv6OptTargetAddress)
}

func TestWriteAdvertDAD(t *testing.T) {
	buf := gopacket.NewSerializeBuffer()
	ns := NeighSolicitation{SrcMAC: routerMAC, SrcIP: netip.IPv6Unspecified(), DstIP: solicitedNode(targetIP), TargetIP: targetIP}
	if err := writeAdvert(buf, ns, hostMAC); err != nil {
		t.Fatal(err)
	}
	d := decode(t, buf.Bytes())
	if !d.ip6.DstIP.Equal(allNodesIP.AsSlice()) || !bytes.Equal(d.eth.DstMAC, allNodesMAC) {
		t.Errorf("DAD reply to %s / %s, want all-nodes", d.ip6.DstIP, d.eth.DstMAC)
	}
	if d.advert.Solicited() || !d.advert.Override() {
		t.Errorf("flags = %#x", d.advert.Flags)
	}
}

func TestWriteUnsolicitedAdvert(t *testing.T) {
	buf := gopacket.NewSerializeBuffer()
	if err := writeUnsolicitedAdvert(buf, hostMAC, targetIP); err != nil {
		t.Fatal(err)
	}
	d := decode(t, buf.Bytes())
	if !d.ip6.DstIP.Equal(allNodesIP.AsSlice()) || !bytes.Equal(d.eth.DstMAC, allNodesMAC) {
		t.Errorf("dst = %s / %s", d.ip6.DstIP, d.eth.DstMAC)
	}
	if d.advert.Flags != naFlagOverride {
		t.Errorf("flags = %#x, want override only", d.advert.Flags)
	}
	checkLinkLayerOption(t, d.ip6.Payload, d.advert.Options, layers.ICMPv6OptTargetAddress)
}

func TestWriteSolicit(t *testing.T) {
	buf := gopacket.NewSerializeBuffer()
	if err := writeSolicit(buf, hostMAC, targetIP, routerIP); err != nil {
		t.Fatal(err)
	}
	d := decode(t, buf.Bytes())
	if d.solicit == nil {
		t.Fatal("not a solicitation")
	}
	if d.ip6.DstIP.String() != "ff02::1:ff34:5678" || d.eth.DstMAC.String() != "33:33:ff:34:56:78" {
		t.Errorf("dst = %s / %s", d.ip6.DstIP, d.eth.DstMAC)
	}
	if !d.ip6.SrcIP.Equal(targetIP.AsSlice()) || !d.solicit.TargetAddress.Equal(routerIP.AsSlice()) {
		t.Errorf("src %s target %s", d.ip6.SrcIP, d.solicit.TargetAddress)
	}
	checkLinkLayerOption(t, d.ip6.Payload, d.solicit.Options, layers.ICMPv6OptSourceAddress)
}

func TestParse(t *testing.T) {
	// A solicitation as the router would send it, built with writeSolicit from the router's side.
	buf := gopacket.NewSerializeBuffer()
	if err := writeSolicit(buf, routerMAC, routerIP, targetIP); err != nil {
		t.Fatal(err)
	}
	frame := append([]byte(nil), buf.Bytes()...)

	p := newSolicitationParser()
	ns, ok := p.parse(frame)
	if !ok {
		t.Fatal("valid solicitation rejected")
	}
	if ns.SrcIP != routerIP || ns.TargetIP != targetIP || ns.DstIP != solicitedNode(targetIP) || !bytes.Equal(ns.SrcMAC, routerMAC) {
		t.Errorf("parsed %+v", ns)
	}
	if ns.String() != "who-has 2001:db8:1:2::c000:201 tell fe80::abcd:12ff:fe34:5678" {
		t.Errorf("String() = %q", ns.String())
	}

	// Ethernet 14 + IPv6 hop limit at offset 7.
	frame[14+7] = 64
	if _, ok := p.parse(frame); ok {
		t.Error("solicitation with hop limit 64 accepted")
	}

	buf = gopacket.NewSerializeBuffer()
	if err := writeUnsolicitedAdvert(buf, routerMAC, targetIP); err != nil {
		t.Fatal(err)
	}
	if _, ok := p.parse(buf.Bytes()); ok {
		t.Error("advertisement accepted as solicitation")
	}
}
