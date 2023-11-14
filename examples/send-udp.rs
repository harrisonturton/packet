// The interface to send the ethernet frame to
pub const IFINDEX: usize = 1;

pub const ETHER_ADDR_LEN: u8 = 6;

#[cfg(target_os = "linux")]
fn main() {
    unsafe { sender::run().unwrap() };
}

#[cfg(not(target_os = "linux"))]
fn main() {
    println!("This example only works on Linux");
}

#[cfg(target_os = "linux")]
mod sender {
    use byteorder::{ByteOrder, NetworkEndian};
    use libc::{sendto, sockaddr_ll, socket, AF_PACKET, ETH_P_ALL, IPPROTO_RAW, SOCK_RAW};
    use packet::{
        enet::{self, MacAddr},
        ipv4::{self, Dscp, Ecn, Flags},
        udp,
    };
    use std::{error::Error, io::Cursor, mem::size_of, net::Ipv4Addr};

    use crate::{ETHER_ADDR_LEN, IFINDEX};

    pub unsafe fn run() -> Result<(), Box<dyn Error>> {
        let sock = socket(AF_PACKET, SOCK_RAW, htons(IPPROTO_RAW as u16) as i32);
        if sock < 0 {
            println!("socket failed with error {sock}");
            return Ok(());
        }

        let addr = sockaddr_ll {
            sll_family: AF_PACKET as u16,
            sll_protocol: htons(ETH_P_ALL as u16),
            sll_ifindex: IFINDEX as i32,
            sll_hatype: 0,
            sll_pkttype: 0,
            sll_halen: ETHER_ADDR_LEN,
            // Broadcast MAC address
            // sll_addr: [0, 0, 255, 255, 255, 255, 255, 255],
            // sll_addr: [ 0, 0, 0, 0, 0, 0, 0, 0 ],
            // sll_addr: [ 0x7e, 0x12, 0xac, 0xc4, 0x53, 0xd0, 0x0, 0x0 ],
            sll_addr: [0, 0, 0, 0, 0, 0, 0, 0],
        };

        let buf = frame()?;
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

    fn frame() -> Result<Vec<u8>, Box<dyn Error>> {
        // let source_mac = MacAddr::new(0x7e, 0x12, 0xac, 0xc4, 0x53, 0xd0);
        // let source_mac = MacAddr::new(0x06, 0x9e, 0xa4, 0xa6, 0xc0, 0x99);
        let source_mac = MacAddr::zero();
        let addr = Ipv4Addr::new(127, 0, 0, 1);

        let payload = "hello world".as_bytes();
        let mut udp_buf = vec![0; udp::HEADER_LEN];
        udp::Datagram::<&[u8]>::builder(&mut udp_buf)?
            .source(50506)
            .dest(2000)
            .len(payload.len() as u16)
            .payload(payload)?
            .gen_checksum(addr, addr)
            .build();

        println!("udp[{}] {:x?}", udp_buf.len(), udp_buf);

        let mut ipv4_buf = vec![0; ipv4::HEADER_LEN + udp_buf.len()];
        let len = ipv4_buf.len() as u16;
        println!("ipv4 len {len}");
        println!("{len}");
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
            .source(addr)
            .dest(addr)
            .payload(Cursor::new(udp_buf), 0)?
            .gen_checksum()
            .build();

        println!("ipv4[{}]: {:x?}", ipv4_buf.len(), ipv4_buf);

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

    fn htons_ipv4(val: Ipv4Addr) -> Ipv4Addr {
        let mut bytes = val.octets();
        bytes.reverse();
        let octets: [u8; 4] = bytes.try_into().unwrap();
        Ipv4Addr::new(octets[0], octets[1], octets[2], octets[3])
    }
}
