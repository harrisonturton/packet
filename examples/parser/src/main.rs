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

    println!("Reading {path}");
    let bytes = std::fs::read(path)?;

    println!("ETHERNET FRAME");
    let frame = packet::ethernet::Frame::new(&bytes)?;

    println!(
        "dest: {:x?} src: {:x?} type: {:?} data: {:x?}",
        frame.dest(),
        frame.source(),
        frame.length_type(),
        frame.payload()
    );

    println!("IPv4 PACKET");
    let payload = frame.payload();
    let packet = packet::ipv4::Packet::new(payload)?;
    println!("{:?} {:?}", packet.source(), packet.dest());

    Ok(())
}
