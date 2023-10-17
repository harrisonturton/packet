# packets

Fast, safe network packet parsing.

This crate never allocates heap memory. It exclusively uses references to
pre-allocated byte slices. This means it can read and write to the *exact* same
buffers used by network devices, making it suitable as part of a zero-copy
networking stack. Packet fields are only parsed and written when they're used,
meaning that callers only pay for the protocol features they actually use.

## Examples

### Packet parser

The [`examples/parser.rs`](examples/parser.rs) example pretty-prints a binary
packet dump. It only works for IPv4 over Ethernet. You can create your own
binary files using the "Export packet bytes" feature in Wireshark.

```
> cargo run --example parser -- resources/enet-ipv4.bin
[enet]
length/type = Type(Ipv4)
source = bc:d0:74:0d:9c:12
dest = ac:17:c8:cc:96:af
payload = 72

[ipv4]
protocol = Udp
source = 10.0.53.7
dest = 104.17.239.159
payload = 52
```

### Packet sniffer

The [`examples/sniffer.rs`](examples/sniffer.rs) example logs IPv4 over Ethernet
messages that arrive on any network interface. This only works on Linux because
it uses raw `AF_PACKET` sockets.

```
> cargo build --example sniffer
> sudo ./target/debug/examples/sniffer
[enet] source=00:00:00:00:00:00 dest=00:00:00:00:00:00 len=59 type=Type(Ipv4)
[ipv4] protocol=Tcp source=127.0.0.1 dest=127.0.0.1 len=59

[enet] source=00:00:00:00:00:00 dest=00:00:00:00:00:00 len=59 type=Type(Ipv4)
[ipv4] protocol=Tcp source=127.0.0.1 dest=127.0.0.1 len=59

[enet] source=00:00:00:00:00:00 dest=00:00:00:00:00:00 len=84 type=Type(Ipv4)
[ipv4] protocol=Icmp source=127.0.0.1 dest=127.0.0.1 len=84
...
```

### ARP packet octet printer

[`examples/print-arp.rs`](examples/print-arp.rs) prints the octets that make up
an ARP packet.

```
> cargo run --example print-arp
ff ff ff ff ff ff ff ff ff ff
ff ff 08 06 00 00 00 00 06 04
00 00 ff ff ff ff ff ff 00 00
00 00 ff ff ff ff ff ff 00 00
00 00
```

## Roadmap

- [x] Ethernet frames
- [X] IP packets
- [X] UDP packets
- [X] ARP packets
- [ ] ICMP packets (Partially done)
- [ ] TCP segments (Partially done)
- [ ] QUIC packets