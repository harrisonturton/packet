// The interface to send the ethernet frame to
pub const IFINDEX: usize = 3;

pub const ETHER_ADDR_LEN: u8 = 6;

#[cfg(target_os = "linux")]
fn main() {
    unsafe { sender::run().unwrap() };
}

#[cfg(not(target_os = "linux"))]
fn main() {
    println!("This example only works on Linux");
}

mod sender {
    use byteorder::{ByteOrder, NetworkEndian};
    use libc::{sendto, sockaddr_ll, socket, AF_PACKET, ETH_P_ALL, ETH_P_ARP, SOCK_RAW};
    use packet::{
        arp::{self, HardwareType, Operation},
        enet::{self, EtherType, MacAddr},
    };
    use std::{error::Error, mem::size_of, net::Ipv4Addr};

    use crate::{ETHER_ADDR_LEN, IFINDEX};

    pub unsafe fn run() -> Result<(), Box<dyn Error>> {
        let sock = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL as u16) as i32);
        if sock < 0 {
            println!("socket failed with error {sock}");
            return Ok(());
        }

        let addr = sockaddr_ll {
            sll_family: AF_PACKET as u16,
            sll_protocol: htons(ETH_P_ARP as u16),
            sll_ifindex: IFINDEX as i32,
            sll_hatype: 0,
            sll_pkttype: 0,
            sll_halen: ETHER_ADDR_LEN,
            // Broadcast MAC address
            sll_addr: [0, 0, 255, 255, 255, 255, 255, 255],
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
        let source_mac = MacAddr::new(0x7e, 0x12, 0xac, 0xc4, 0x53, 0xd0);
        let broadcast_mac = MacAddr::new(255, 255, 255, 255, 255, 255);
        let target_mac = MacAddr::new(0, 0, 0, 0, 0, 0);

        let sender_ipv4 = Ipv4Addr::new(172, 0, 0, 1);
        let target_ipv4 = Ipv4Addr::new(8, 8, 8, 8);

        let mut arpbuf = vec![0; arp::HEADER_LEN];
        arp::Packet::<&[u8]>::builder(&mut arpbuf)?
            .hardware_type(HardwareType::Ethernet)
            .protocol_type(EtherType::Ipv4)
            .hardware_addr_len(6)
            .protocol_addr_len(4)
            .operation(Operation::Request)
            .sender_hardware_addr(&source_mac.octets())?
            .target_hardware_addr(&target_mac.octets())?
            .sender_protocol_addr(&sender_ipv4.octets())?
            .target_protocol_addr(&target_ipv4.octets())?
            .build();

        println!("arp: {:x?}", arpbuf);

        let mut enetbuf = vec![0; enet::HEADER_LEN + arp::HEADER_LEN];
        enet::Frame::<&[u8]>::builder(&mut enetbuf)?
            .source(source_mac)
            .dest(broadcast_mac)
            .ethertype(enet::EtherType::Arp)
            .payload(&arpbuf)?
            .build();

        println!("enet: {:x?}", enetbuf);

        Ok(enetbuf)
    }

    fn htons(val: u16) -> u16 {
        let mut bytes = [0, 0];
        NetworkEndian::write_u16(&mut bytes, val);
        u16::from_le_bytes(bytes)
    }
}
