use packet::{enet, ipv4, udp};
use std::{error::Error, io::Cursor, net::Ipv4Addr};

const HELLO_WORLD: &'static [u8] = include_bytes!("../resources/enet-udp-hello-world.bin");

#[test]
fn test_frame_has_expected_values() -> Result<(), Box<dyn Error>> {
    use enet::{EtherType, Frame, MacAddr, HEADER_LEN};

    let mut buf = vec![0; HEADER_LEN];
    let actual_frame = Frame::<&[u8]>::builder(&mut buf)?
        .source(MacAddr::zero())
        .dest(MacAddr::zero())
        .ethertype(EtherType::Ipv4)
        .payload(&vec![])?
        .build();

    let expected_frame = Frame::new(HELLO_WORLD)?;
    assert_eq!(actual_frame.source(), expected_frame.source());
    assert_eq!(actual_frame.dest(), expected_frame.dest());
    assert_eq!(actual_frame.length_type(), expected_frame.length_type());
    Ok(())
}

#[test]
fn test_packet_has_expected_values() -> Result<(), Box<dyn Error>> {
    use ipv4::{Dscp, Ecn, Flags, Packet, Protocol, HEADER_LEN};

    let localhost_ip = Ipv4Addr::new(127, 0, 0, 1);
    let mut buf = vec![0; HEADER_LEN];
    let actual_packet = Packet::<&[u8]>::builder(&mut buf)?
        .version(4)
        .header_len(20)
        .dscp(Dscp::new(0, 0)?)
        .ecn(Ecn::new(false, false))
        .len(40)
        .id(51512)
        .flags(Flags::new(true, false))
        .fragment_offset(0)
        .protocol(Protocol::Udp)
        .source(localhost_ip)
        .dest(localhost_ip)
        .payload(Cursor::new(vec![]), 0)?
        .build();

    let expected_frame = enet::Frame::new(HELLO_WORLD)?;
    let expected_packet = ipv4::Packet::new(expected_frame.payload())?;
    assert_eq!(actual_packet.version(), expected_packet.version());
    assert_eq!(actual_packet.source(), expected_packet.source());
    assert_eq!(actual_packet.dest(), expected_packet.dest());
    assert_eq!(actual_packet.id(), expected_packet.id());
    assert_eq!(actual_packet.len(), expected_packet.len());
    // assert_eq!(actual_packet.flags(), expected_packet.flags());
    // assert_eq!(actual_packet.header_len(), expected_packet.header_len());
    Ok(())
}

#[test]
fn test_datagram_has_expected_values() -> Result<(), Box<dyn Error>> {
    let expected_frame = enet::Frame::new(HELLO_WORLD)?;
    let expected_packet = ipv4::Packet::new(expected_frame.payload())?;
    let expected_datagram = udp::Datagram::new(expected_packet.payload())?;

    let data = "hello world\n".as_bytes();
    let mut buf = vec![0; udp::HEADER_LEN + data.len()];
    let actual_datagram = udp::Datagram::<&[u8]>::builder(&mut buf)?
        .dest(expected_datagram.dest())
        .source(expected_datagram.source())
        .len(expected_datagram.len())
        .payload(Cursor::new(expected_datagram.payload()))?
        .checksum(0)
        .gen_checksum(expected_packet.source(), expected_packet.dest())
        .build();

    assert_eq!(actual_datagram.source(), expected_datagram.source());
    assert_eq!(actual_datagram.dest(), expected_datagram.dest());
    assert_eq!(actual_datagram.len(), expected_datagram.len());
    assert_eq!(actual_datagram.payload(), expected_datagram.payload());
    assert_eq!(actual_datagram.checksum(), expected_datagram.checksum());
    Ok(())
}
