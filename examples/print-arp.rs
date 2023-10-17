use packet::enet::MacAddr;
use packet::{arp, enet};
use std::error::Error;
use std::net::Ipv4Addr;

fn main() -> Result<(), Box<dyn Error>> {
    let broadcast_mac = MacAddr::new(255, 255, 255, 255, 255, 255);
    let broadcast_ipv4 = Ipv4Addr::new(0, 0, 0, 0);

    let mut arpbuf = vec![0; arp::HEADER_LEN];
    let _packet = arp::Packet::<&[u8]>::builder(&mut arpbuf)?
        .hardware_addr_len(6)
        .protocol_addr_len(4)
        .sender_hardware_addr(&broadcast_mac.octets())?
        .target_hardware_addr(&broadcast_mac.octets())?
        .sender_protocol_addr(&broadcast_ipv4.octets())?
        .target_protocol_addr(&broadcast_ipv4.octets())?
        .build();

    let mut enetbuf = vec![0; enet::HEADER_LEN + arp::HEADER_LEN];
    let _frame = enet::Frame::<&[u8]>::builder(&mut enetbuf)?
        .source(broadcast_mac)
        .dest(broadcast_mac)
        .ethertype(enet::EtherType::Arp)
        .payload(&arpbuf)?
        .build();

    for (i, octet) in enetbuf.iter().enumerate() {
        if i > 0 && i % 10 == 0 {
            print!("\n");
        }

        print!("{octet:02x}");

        if i % 10 != 9 {
            print!(" ");
        }
    }

    print!("\n");

    Ok(())
}
