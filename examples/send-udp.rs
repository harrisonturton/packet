use packet::enet::MacAddr;
use std::net::Ipv4Addr;

// The interface to send the ethernet frame to
pub const IFINDEX: usize = 2;

pub const ETHER_ADDR_LEN: u8 = 6;

#[cfg(target_os = "linux")]
fn main() {
    let ip_src = Ipv4Addr::new(192, 168, 20, 21);
    let ip_dst = Ipv4Addr::new(192, 168, 20, 14);

    let mac_src = MacAddr::new(0x98, 0x90, 0x96, 0xc6, 0xa8, 0x13);
    let mac_dst = MacAddr::new(0xA0, 0xE7, 0x0B, 0xD3, 0x8A, 0x2E);

    unsafe { sender::run(ip_src, ip_dst, mac_src, mac_dst).unwrap() };
}

#[cfg(not(target_os = "linux"))]
fn main() {
    println!("This example only works on Linux");
}

#[cfg(target_os = "linux")]
mod sender {
    use byteorder::{ByteOrder, NetworkEndian};
    use libc::{sendto, sockaddr_ll, socket, AF_PACKET, ETH_P_ALL, SOCK_RAW};
    use std::{error::Error, io::Cursor, mem::size_of, net::Ipv4Addr};

    use crate::{ETHER_ADDR_LEN, IFINDEX};
    use packet::enet::{self, MacAddr};
    use packet::ipv4::{self, Dscp, Ecn, Flags};
    use packet::udp;

    pub unsafe fn run(
        ip_src: Ipv4Addr,
        ip_dst: Ipv4Addr,
        mac_src: MacAddr,
        mac_dst: MacAddr,
    ) -> Result<(), Box<dyn Error>> {
        let sock = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL as u16) as i32);
        if sock < 0 {
            println!("socket failed with error {sock}");
            return Ok(());
        }

        let mut sll_addr = [0; 8];
        sll_addr[..ETHER_ADDR_LEN].copy_from_slice(&mac_dst.octets());

        let addr = sockaddr_ll {
            sll_family: AF_PACKET as u16,
            sll_protocol: htons(ETH_P_ALL as u16),
            sll_ifindex: IFINDEX as i32,
            sll_hatype: 0,
            sll_pkttype: 0,
            sll_halen: ETHER_ADDR_LEN,
            sll_addr,
        };

        let buf = frame(ip_src, ip_dst, mac_src, mac_dst)?;
        let sent = sendto(
            sock,
            buf.as_ptr() as _,
            buf.len(),
            0,
            &addr as *const _ as _,
            size_of::<sockaddr_ll>() as u32,
        );
        println!("Sent {sent} of {} bytes", buf.len());

        Ok(())
    }

    fn frame(
        ip_src: Ipv4Addr,
        ip_dst: Ipv4Addr,
        mac_src: MacAddr,
        mac_dst: MacAddr,
    ) -> Result<Vec<u8>, Box<dyn Error>> {
        let payload = "hello world\n".as_bytes();
        let mut udp_buf = vec![0; udp::HEADER_LEN + payload.len()];
        let len = udp_buf.len();
        udp::Datagram::<&[u8]>::builder(&mut udp_buf)?
            .source(50506)
            .dest(2000)
            .len(len as u16)
            .payload(payload)?
            .gen_checksum(ip_src, ip_dst)
            .build();

        let mut ipv4_buf = vec![0; ipv4::HEADER_LEN + udp_buf.len()];
        let len = ipv4_buf.len() as u16;
        ipv4::Packet::<&[u8]>::builder(&mut ipv4_buf)?
            .version(4)
            .header_len(5)
            .dscp(Dscp::new(0, 0)?)
            .ecn(Ecn::new(false, false))
            .len(len)
            .id(61037)
            .flags(Flags::new(false, false))
            .fragment_offset(0)
            .ttl(64u8)
            .protocol(ipv4::Protocol::Udp)
            .source(ip_src)
            .dest(ip_dst)
            .payload(Cursor::new(udp_buf), 0)?
            .gen_checksum()
            .build();

        let mut enet_buf = vec![0; enet::HEADER_LEN + ipv4_buf.len()];
        enet::Frame::<&[u8]>::builder(&mut enet_buf)?
            .source(mac_src)
            .dest(mac_dst)
            .ethertype(enet::EtherType::Ipv4)
            .payload(&ipv4_buf)?
            .build();

        Ok(enet_buf)
    }

    fn htons(val: u16) -> u16 {
        let mut bytes = [0, 0];
        NetworkEndian::write_u16(&mut bytes, val);
        u16::from_le_bytes(bytes)
    }
}
