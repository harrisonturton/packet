#![no_main]

use std::error::Error;

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = fuzz_tcp(data);
});

fn fuzz_tcp(bytes: &[u8]) -> Result<(), Box<dyn Error>> {
    let segment = packet::tcp::Segment::new(bytes)?;

    let _dst = segment.source();
    let _src = segment.dest();
    let _sequence = segment.sequence();
    let _acked = segment.acked();
    let _data_offset = segment.data_offset();
    let _flags = segment.flags();
    let _window = segment.window();
    let _checksum = segment.checksum();
    let _urgent = segment.urgent();

    Ok(())
}
