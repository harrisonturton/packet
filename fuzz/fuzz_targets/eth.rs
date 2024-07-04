#![no_main]

use std::error::Error;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = fuzz_eth(data);
});

fn fuzz_eth(bytes: &[u8]) -> Result<(), Box<dyn Error>> {
    let frame = packet::enet::Frame::new(bytes)?;

    let _dst = frame.dest();
    let _src = frame.source();
    let _typ = frame.length_type();

    Ok(())
}
