use byteorder::{ByteOrder, NetworkEndian};
use packet::enet::{self, Frame, MacAddr};
use packet::ipv4::{self, Dscp, Ecn, Flags, Packet};
use packet::udp::{self, Datagram};
use std::error::Error;
use std::io::Cursor;
use std::net::Ipv4Addr;

// [enet]
//   len_type=Type(Ipv4)
//   src=00:00:00:00:00:00
//   dst=00:00:00:00:00:00
// [packet]
//   version=4
//   header_len=20
//   dscp=Dscp { class: 0, drop: 0 }
//   ecn=Ecn { congested: false, capable: false }
//   len=40
//   id=61037
//   flags=Flags { do_not_fragment: true, more_fragments: false }
//   fragment_offset=0
//   ttl=64
//   protocol=Udp
//   src=127.0.0.1
//   dst=127.0.0.1
//   checksum=20053
// [udp]
//   src_port=54796
//   dst_port=2000

pub const ETH_IPV4_UDP: &'static [u8] = include_bytes!("hello-world.bin");

fn main() -> Result<(), Box<dyn Error>> {
    let frame = Frame::new(ETH_IPV4_UDP)?;
    let packet = Packet::new(frame.payload())?;
    let datagram = Datagram::new(packet.payload())?;

    println!("{frame:?}");
    println!("{packet:?}");
    println!("{datagram:?}");

    println!("[expected]");
    println!("  [enet]");
    println!("    len_type={:?}", frame.length_type());
    println!("    src={:?}", frame.source());
    println!("    dst={:?}", frame.dest());
    println!("  [packet]");
    println!("    version={}", packet.version());
    println!("    header_len={}", packet.header_len());
    println!("    dscp={:?}", packet.dscp());
    println!("    ecn={:?}", packet.ecn());
    println!("    len={}", packet.len());
    println!("    id={}", packet.id());
    println!("    flags={:?}", packet.flags());
    println!("    fragment_offset={}", packet.fragment_offset());
    println!("    ttl={}", packet.ttl());
    println!("    protocol={:?}", packet.protocol());
    println!("    src={:?}", packet.source());
    println!("    dst={:?}", packet.dest());
    println!("    checksum={}", packet.checksum());
    println!("  [udp]");
    println!("    src_port={}", datagram.source());
    println!("    dst_port={}", datagram.dest());
    println!(
        "    payload={:x?}",
        String::from_utf8_lossy(&datagram.payload())
    );

    let bytes = create_frame()?;
    let frame = Frame::new(bytes)?;
    let packet = Packet::new(frame.payload())?;
    let datagram = Datagram::new(packet.payload())?;

    println!("[actual]");
    println!("  [enet]");
    println!("    len_type={:?}", frame.length_type());
    println!("    src={:?}", frame.source());
    println!("    dst={:?}", frame.dest());
    println!("  [packet]");
    println!("    version={}", packet.version());
    println!("    header_len={}", packet.header_len());
    println!("    dscp={:?}", packet.dscp());
    println!("    ecn={:?}", packet.ecn());
    println!("    len={}", packet.len());
    println!("    id={}", packet.id());
    println!("    flags={:?}", packet.flags());
    println!("    fragment_offset={}", packet.fragment_offset());
    println!("    ttl={}", packet.ttl());
    println!("    protocol={:?}", packet.protocol());
    println!("    src={:?}", packet.source());
    println!("    dst={:?}", packet.dest());
    println!("    checksum={}", packet.checksum());
    println!("  [udp]");
    println!("    src_port={}", datagram.source());
    println!("    dst_port={}", datagram.dest());
    println!(
        "    payload={:x?}",
        String::from_utf8_lossy(&datagram.payload())
    );

    Ok(())
}

fn create_frame() -> Result<Vec<u8>, Box<dyn Error>> {
    let source_mac = MacAddr::new(0, 0, 0, 0, 0, 0);

    let payload = "hello WORLD\n".as_bytes();
    let len = payload.len();
    let payload = Cursor::new(payload);

    let mut udp_buf = vec![0; udp::HEADER_LEN];
    udp::Datagram::<&[u8]>::builder(&mut udp_buf)?
        .source(50506)
        .dest(2000)
        .len(len as u16)
        .payload(payload)?
        .build();

    let mut ipv4_buf = vec![0; ipv4::HEADER_LEN + udp_buf.len()];
    let len = ipv4_buf.len() as u16;
    ipv4::Packet::<&[u8]>::builder(&mut ipv4_buf)?
        .version(htons_u8(4))
        .header_len(htons_u8(5))
        .dscp(Dscp::new(0, 0)?)
        .ecn(Ecn::new(false, false))
        .len(len) // TODO: set len automatically
        .id(htons(61037))
        .flags(Flags::new(true, false))
        .fragment_offset(0)
        .ttl(64u8.to_be())
        .protocol(ipv4::Protocol::Udp)
        .source(Ipv4Addr::new(127, 0, 0, 1))
        .dest(Ipv4Addr::new(127, 0, 0, 1))
        .payload(Cursor::new(udp_buf), 0)?
        // .gen_checksum()
        .checksum(20053) // TODO: Generate checksum automatically
        .build();

    let mut enet_buf = vec![0; enet::HEADER_LEN + ipv4_buf.len()];
    enet::Frame::<&[u8]>::builder(&mut enet_buf)?
        .source(source_mac)
        .dest(source_mac)
        .ethertype(enet::EtherType::Ipv4)
        .payload(&ipv4_buf)?
        .build();

    println!("enet[{}]: {:x?}", enet_buf.len(), enet_buf);

    Ok(enet_buf)
}

fn htons(val: u16) -> u16 {
    let mut bytes = [0, 0];
    NetworkEndian::write_u16(&mut bytes, val);
    u16::from_le_bytes(bytes)
}

fn htons_u8(val: u8) -> u8 {
    val.to_be()
}

fn _htons_ipv4(val: Ipv4Addr) -> Ipv4Addr {
    let mut bytes = val.octets();
    bytes.reverse();
    let octets: [u8; 4] = bytes.try_into().unwrap();
    Ipv4Addr::new(octets[0], octets[1], octets[2], octets[3])
}

//     let source_mac = MacAddr::new(0, 0, 0, 0, 0, 0);
//     let broadcast_mac = MacAddr::new(255, 255, 255, 255, 255, 255);

//     let payload = "hello world".as_bytes();
//     let mut udp_buf = vec![0; udp::HEADER_LEN];
//     udp::Datagram::<&[u8]>::builder(&mut udp_buf)?
//         .source(5050)
//         .dest(2000)
//         .len(payload.len() as u16)
//         .payload(payload)?
//         .build();

//     println!("udp[{}] {:x?}", udp_buf.len(), udp_buf);

//     let mut ipv4_buf = vec![0; ipv4::HEADER_LEN + udp_buf.len()];
//     let len = ipv4_buf.len() as u16;
//     println!("{len}");
//     ipv4::Packet::<&[u8]>::builder(&mut ipv4_buf)?
//         .version(htons_u8(4))
//         .header_len(htons_u8(5))
//         .dscp(Dscp::new(0, 0)?)
//         .ecn(Ecn::new(false, false))
//         .len(htons(len))
//         .id(htons(54321))
//         .flags(Flags::new(false, false))
//         .fragment_offset(0)
//         .ttl(64u8.to_be())
//         .protocol(ipv4::Protocol::Udp)
//         .source(Ipv4Addr::new(127, 0, 0, 1))
//         .dest(Ipv4Addr::new(127, 0, 0, 1))
//         .payload(Cursor::new(udp_buf), 0)?
//         .checksum(0)
//         .build();

//     println!("ipv4[{}]: {:x?}", ipv4_buf.len(), ipv4_buf);

//     let mut enet_buf = vec![0; enet::HEADER_LEN + ipv4_buf.len()];
//     enet::Frame::<&[u8]>::builder(&mut enet_buf)?
//         .source(source_mac)
//         .dest(source_mac)
//         .ethertype(enet::EtherType::Ipv4)
//         .payload(&ipv4_buf)?
//         .build();

//     println!("enet[{}]: {:x?}", enet_buf.len(), enet_buf);

//     Ok(enet_buf)
// }

// fn htons(val: u16) -> u16 {
//     let mut bytes = [0, 0];
//     NetworkEndian::write_u16(&mut bytes, val);
//     u16::from_le_bytes(bytes)
// }

// fn htons_u8(val: u8) -> u8 {
//     val.to_be()
// }

// fn htons_ipv4(val: Ipv4Addr) -> Ipv4Addr {
//     let mut bytes = val.octets();
//     bytes.reverse();
//     let octets: [u8; 4] = bytes.try_into().unwrap();
//     Ipv4Addr::new(octets[0], octets[1], octets[2], octets[3])
// }
