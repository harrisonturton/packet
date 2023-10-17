use packet::{
    enet::{self, EtherType, LengthType},
    ipv4,
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

    Ok(())
}
