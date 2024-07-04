use packet::{
    enet::{self, EtherType, LengthType},
    ipv4::{self, Protocol},
};
use std::error::Error;

/// parse packets
#[derive(argh::FromArgs, Debug)]
struct Args {
    /// path of the binary data to parse
    #[argh(positional)]
    path: String,
}

pub fn main() -> Result<(), Box<dyn Error>> {
    let Args { path } = argh::from_env::<Args>();

    let bytes = std::fs::read(path)?;
    let frame = enet::Frame::new(&bytes)?;

    println!("[enet]");
    println!("length/type = {:?}", frame.length_type());
    println!("source = {:?}", frame.source());
    println!("dest = {:?}", frame.dest());
    println!("payload = {:?}", frame.payload().len());
    println!("");

    if frame.length_type() != LengthType::Type(EtherType::Ipv4) {
        println!("This example only works for IPv4 over Ethernet.");
        return Ok(());
    }

    let payload = frame.payload();
    let packet = ipv4::Packet::new(payload)?;

    println!("[ipv4]");
    println!("protocol = {:?}", packet.protocol());
    println!("source = {:?}", packet.source());
    println!("dest = {:?}", packet.dest());
    println!("payload = {:?}", packet.payload().len());

    match packet.protocol() {
        Protocol::Tcp => {
            let segment = packet::tcp::Segment::new(packet.payload())?;
            println!();
            println!("[tcp]");
            println!("source = {:?}", segment.source());
            println!("dest = {:?}", segment.dest());
            println!("sequence = {:?}", segment.sequence());
            println!("acked = {:?}", segment.acked());
            println!("data_offset = {:?}", segment.data_offset());
            println!("flags = {:?}", segment.flags());
            println!("window = {:?}", segment.window());
            println!("checksum = {:?}", segment.checksum());
            println!("urgent = {:?}", segment.urgent());
        }
        Protocol::Udp => {
            let dgram = packet::udp::Datagram::new(packet.payload())?;
            println!();
            println!("[udp]");
            println!("source = {:?}", dgram.source());
            println!("dest = {:?}", dgram.dest());
            println!("sequence = {:?}", dgram.len());
            println!("acked = {:?}", dgram.checksum());
            println!("payload len = {:?}", dgram.payload().len());
        }
        protocol => {
            println!("protocol = {protocol:?}");
        }
    }

    Ok(())
}
