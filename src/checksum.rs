/// Checksum for UDP datagrams and TCP segments.
pub struct Checksum {
    sum: u32,
}

impl Checksum {
    #[must_use]
    pub fn new() -> Self {
        Self { sum: 0 }
    }

    #[allow(clippy::cast_possible_truncation)]
    #[allow(clippy::cast_lossless)]
    pub fn add(mut self, buf: &[u8]) -> Self {
        if buf.len() == 1 {
            self.sum += buf[0] as u32;
            return self;
        }

        // This should never panic because chunks_exact guarantees 2 items are
        // returned in every iterat.
        for chunk in buf.chunks_exact(2) {
            let short = chunk
                .try_into()
                .expect("chunks_exact returned inexact result");
            self.sum += u16::from_be_bytes(short) as u32;
        }

        if buf.len() & 1 != 0 {
            self.sum += (buf[buf.len() - 1] as u32) << 8;
        }

        self
    }

    #[allow(clippy::cast_possible_truncation)]
    pub fn finish(self) -> u16 {
        let mut sum = self.sum;

        while sum >> 16 != 0 {
            sum = (sum & 0xFFFF) + (sum >> 16);
        }

        !sum as u16
    }
}
