# ndpresponder

Package `ndpresponder` answers IPv6 neighbor solicitations ([RFC 4861](https://www.rfc-editor.org/rfc/rfc4861)) for every address in a prefix on one Ethernet interface. sni-proxy uses it so it can bind outgoing connections to any address in an on-link prefix without assigning each one to the host. It can also announce an address to the default gateway just before that address is first used.

It is Linux-only: capture uses `AF_PACKET`, and routes and neighbor entries are managed over netlink. The packet-building code in `ndp.go` has no build tag, so it can be tested on any platform.

## Origin

This package is derived from [yoursunny/ndpresponder](https://github.com/yoursunny/ndpresponder) by Junxiao Shi, ISC License (see [LICENSE](LICENSE)). Like upstream, it sends each advertisement *from the target address itself* rather than from a link-local address. Upstream explains why in its [blog post](https://yoursunny.com/t/2021/ndpresponder/): some KVM hosts drop link-local traffic leaving a guest. Upstream is a standalone program with static and Docker-network modes. This package is a library with a lifecycle API, and only covers static-prefix responding plus announcements. See [Differences from upstream](#differences-from-upstream).

## Usage

```go
r, err := ndpresponder.New(ndpresponder.Config{
	Interface:     "eth0",
	Prefix:        netip.MustParsePrefix("2001:db8:1:2::/96"),
	Logger:        logger,
	AddLocalRoute: true,
	PinGateway:    true,
})
if err != nil {
	return err
}
if err := r.Start(); err != nil {
	r.Close() // undoes partial setup
	return err
}
defer r.Close()

// Before connecting from a fresh source address in the prefix:
if err := r.Announce(srcAddr); err != nil {
	logger.Warn("announce failed", "error", err)
}
```

`Announce` is safe to call from many goroutines at once, for example from a `net.Dialer` `Control` hook. `Close` is safe to call more than once.

### Config

| Field | Default | Meaning |
|---|---|---|
| `Interface` | required | Ethernet interface to answer on, e.g. `eth0` |
| `Prefix` | required | IPv6 prefix to answer for; it is masked to its network address |
| `Logger` | `slog.Default()` | Structured logger; per-packet events are logged at debug level |
| `AddLocalRoute` | `false` | On `Start`, add `local <prefix> dev lo table local` so the kernel accepts traffic for every address in the prefix. On `Close`, remove it, but only if `Start` added it |
| `PinGateway` | `false` | On `Start`, wait for the default gateway's neighbor entry to become reachable, then mark it `NOARP` so the kernel stops probing it |
| `GatewayTimeout` | `30s` | How long `Start` waits for the gateway when `PinGateway` is set; `Start` fails after that |

### Privileges

- **`CAP_NET_RAW`** for the packet socket.
- **`CAP_NET_ADMIN`** for `AddLocalRoute` and `PinGateway`.

## Behaviour

**Answering.** A classic BPF filter (`icmp6 && ip6[40]==135`) passes only neighbor solicitations to userspace. A solicitation is ignored unless:
- its hop limit is 255 (RFC 4861 §7.1.1),
- its ICMPv6 code is 0, and
- its target address is in the prefix.

Each accepted solicitation gets a neighbor advertisement:

| Solicitation | Advertisement sent to | Flags |
|---|---|---|
| Multicast "who-has", or unicast reachability probe | Sender's IP and MAC | Solicited, Override |
| Duplicate address detection (source `::`) | `ff02::1` (all nodes) | Override |

The advertisement's IPv6 source is the target address. It always carries a Target Link-Layer Address option with the interface's MAC. The Router flag is never set.

**Announcing.** `Announce(ip)` sends two packets:
1. An unsolicited advertisement for `ip` to `ff02::1`, with the Override flag only. This updates caches that already hold an entry for `ip`.
2. If the interface has an IPv6 default route, a solicitation for the gateway, sent *from* `ip` to the gateway's solicited-node multicast group. It carries a Source Link-Layer Address option. Under RFC 4861 §7.2.3 this makes the gateway create a neighbor entry for `ip`. Unsolicited advertisements alone don't, because routers discard them for addresses they have no entry for (§7.2.5).

**Gateway pinning.** The gateway is found from the interface's IPv6 default route. With `PinGateway`, `Start` does three things:
- It prompts the kernel to resolve the gateway by sending a throwaway UDP datagram to it.
- Once the entry is `REACHABLE`, it sets the entry to `NOARP`.
- If the entry is already `PERMANENT` or `NOARP`, it leaves it alone.

**Shutdown.** The capture loop polls with a 500 ms timeout. `Close` cancels the loop and waits for it to exit before closing the socket, so there is no close-while-reading race.

## Differences from upstream

Compared with upstream at commit `dbc3ce8`:

- **Library instead of a program.** It has a `New`/`Start`/`Announce`/`Close` lifecycle and takes `netip.Prefix`. There is no CLI or Docker-network mode.
- **Gateway solicitation address.** Upstream sends it to a hardcoded `ff02::1:ff00:1`, which only reaches gateways whose address ends in `::1`. This package derives the solicited-node group from the actual gateway address.
- **Router flag.** Upstream sets it on every advertisement. This package never sets it, since it answers as a host.
- **Unicast probes.** In static mode upstream answers only multicast solicitations. This package also answers unicast reachability probes, so router cache entries don't expire to `FAILED`.
- **Duplicate address detection.** Probes are answered to all nodes, as §7.2.4 requires, instead of to `::`.
- **Validation.** Solicitations without hop limit 255 are dropped.
- **Announcement.** Upstream sends a DAD-style solicitation (source `::`, nonce option), which announces nothing. This package sends an unsolicited advertisement instead.
- **Gateway wait.** Upstream waits forever and shells out to `/usr/bin/ping`. This package's wait is bounded, optional and in-process.
- **Local route.** Optional `AddLocalRoute` setup and teardown; upstream has no equivalent.

Several of these are plain bugs that also affect upstream and could be offered back as separate fixes: the solicited-node address, the hop-limit check, and DAD replies.

## Testing

```bash
go test ./ndpresponder/
```

The tests serialize each packet type, decode it again with gopacket and check four things:
- the ICMPv6 checksum,
- the IPv6 payload length,
- the flags,
- the exact bytes of the 8-byte link-layer address option.

They also check how the solicited-node address and multicast MAC are derived, and that the parser rejects bad hop limits and non-solicitations.

The tests don't cover the Linux socket and netlink code. To check that by hand, use a veth pair with a "router" network namespace on the peer end:
- `ndisc6 <addr-in-prefix> <peer-if>` should return the host's MAC.
- `ping -6` to an address in the prefix should work while `AddLocalRoute` is set.
- `tcpdump -vv icmp6` on the peer should show a well-formed advertisement and gateway solicitation after `Announce`.
