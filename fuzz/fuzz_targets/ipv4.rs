#![no_main]

use std::error::Error;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = fuzz_ipv4(data);
});

fn fuzz_ipv4(bytes: &[u8]) -> Result<(), Box<dyn Error>> {
    let packet = packet::ipv4::Packet::new(bytes)?;

    let _dst = packet.dest();
    let _src = packet.source();
    let _version = packet.version();
    let _hdrlen = packet.header_len();
    let _dscp = packet.dscp();
    let _ecn = packet.ecn();
    let _len = packet.len();
    let _id = packet.id();
    let _flags = packet.flags();
    let _ttl = packet.ttl();
    let _proto = packet.protocol();
    let _cksm = packet.checksum();
    let _options = packet.options().map(|bytes| bytes.map(|bytes| bytes.to_owned()));

    Ok(())
}
