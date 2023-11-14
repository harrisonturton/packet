#[cfg(target_os = "linux")]
fn main() {
    sniffer::run().unwrap();
}

#[cfg(not(target_os = "linux"))]
fn main() {
    println!("This example only works on Linux");
}

#[cfg(target_os = "linux")]
mod sniffer {
    use byteorder::{ByteOrder, NetworkEndian};
    use libc::{recv, socket, AF_PACKET, ETH_P_ALL, SOCK_RAW};
    use packet::{
        arp,
        enet::{self, EtherType, LengthType},
        ipv4,
    };
    use std::error::Error;

    pub fn run() -> Result<(), Box<dyn Error>> {
        unsafe {
            let sock = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL as u16) as i32);
            if sock < 0 {
                println!("socket() failed with error {sock}");
                return Ok(());
            }

            let buffer = &mut [0; 65536];
            loop {
                let read = recv(sock, buffer.as_mut_ptr() as _, buffer.len(), 0);

                if read < 0 {
                    println!("recv failed with error {read}");
                    return Ok(());
                }

                if read == 0 {
                    println!("recv returned 0");
                    return Ok(());
                }

                let frame = enet::Frame::new(&buffer[..read as usize])?;
                println!(
                    "[enet] source={:?} dest={:?} len={:?} type={:?}",
                    frame.source(),
                    frame.dest(),
                    frame.payload().len(),
                    frame.length_type(),
                );

                if let LengthType::Type(typ) = frame.length_type() {
                    match typ {
                        EtherType::Ipv4 => {
                            let packet = ipv4::Packet::new(frame.payload())?;
                            println!(
                                "[ipv4] protocol={:?} source={:?} dest={:?} len={:?}\n",
                                packet.protocol(),
                                packet.source(),
                                packet.dest(),
                                packet.len()
                            );
                        }
                        EtherType::Arp => {
                            let packet = arp::Packet::new(frame.payload())?;
                            println!(
                                "[arp] sender={:?} target={:?} sender={:?} target={:?}\n",
                                packet.sender_hardware_addr(),
                                packet.target_hardware_addr(),
                                packet.sender_protocol_addr(),
                                packet.target_protocol_addr()
                            );
                        }
                        EtherType::Ipv6 => {
                            println!("[ipv6] display not supported");
                        }
                        EtherType::Unknown(code) => {
                            println!("[unknown] unknown ethertype {code}");
                        }
                    }
                }
            }
        }
    }

    fn htons(val: u16) -> u16 {
        let mut bytes = [0, 0];
        NetworkEndian::write_u16(&mut bytes, val);
        u16::from_le_bytes(bytes)
    }
}
