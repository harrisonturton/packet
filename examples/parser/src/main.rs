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

    let packet = netlib::ethernet::Frame::new(&bytes)?;

    println!(
        "dest: {:x?} src: {:x?} type: {:?} data: {:x?}",
        packet.mac_dest(),
        packet.mac_src(),
        packet.length_type(),
        packet.client_data()
    );

    Ok(())
}
