# packets

Fast, safe network packet parsing.

This crate never allocates heap memory. It exclusively uses references to
pre-allocated byte slices. This means it can read and write to the *exact* same
buffers used by network devices, making it suitable as part of a zero-copy
networking stack. Packet fields are only parsed and written when they're used,
meaning that callers only pay for the protocol features they actually use.

## Roadmap

- [x] Ethernet frames
- [X] IP packets
- [X] UDP packets
- [X] ARP packets
- [ ] ICMP packets (Partially done)
- [ ] TCP segments (Partially done)
- [ ] QUIC packets