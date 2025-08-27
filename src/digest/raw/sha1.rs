#![allow(deprecated)]

use crate::digest::{RawDigest, ResetableDigest};
use crate::traits::ByteArray;

#[deprecated = "SHA-1 is insecure and should not be used for security purposes. To disable this warning, enable the `insecure-sha1` feature"]
pub struct Sha1 {
    state: [u32; 5],
    byte_len: u64,
}

impl Sha1 {
    pub const fn new() -> Self {
        Self {
            state: [0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0],
            byte_len: 0,
        }
    }
}

impl RawDigest for Sha1 {
    type Output = [u8; 20];
    type Block = [u8; 64];

    fn raw_update(&mut self, block: &Self::Block) -> crate::error::Result<()> {
        self.byte_len += 64;
        let [mut a, mut b, mut c, mut d, mut e] = self.state;
        let mut w = [0u32; 16];

        for (i, b) in <[u8; 4]>::array_chunks(block).enumerate() {
            w[i] = u32::from_be_bytes(*b);
        }

        for i in 0..80 {
            let (f, k) = match i {
                0..20 => ((b & c) | ((!b) & d), 0x5A827999),
                20..40 => (b ^ c ^ d, 0x6ED9EBA1),
                40..60 => ((b & c) ^ (b & d) ^ (c & d), 0x8F1BBCDC),
                _ => (b ^ c ^ d, 0xCA62C1D6),
            };

            let temp = a
                .rotate_left(5)
                .wrapping_add(f)
                .wrapping_add(k)
                .wrapping_add(e)
                .wrapping_add(w[i & 15]);
            w[i] =
                (w[(i + 13) & 15] ^ w[(i + 8) & 15] ^ w[(i + 2) & 15] ^ w[i] & 15).rotate_left(1);
            e = d;
            d = c;
            c = b.rotate_left(30);
            b = a;
            a = temp;
        }

        for (s, h) in self.state.iter_mut().zip([a, b, c, d, e]) {
            *s = (*s).wrapping_add(h);
        }

        Ok(())
    }

    fn raw_update_final(&mut self, rest: &[u8]) -> crate::error::Result<()> {
        let final_size = const { Self::Block::LEN - 9 };
        let bitcount = (self.byte_len + rest.len() as u64) << 3;

        let mut fblock = if rest.len() < final_size {
            let mut fblock = Self::Block::extend(rest);

            fblock[rest.len()] = 0x80;
            fblock
        } else {
            let mut iblock: Self::Block = Self::Block::extend(rest);
            if rest.len() < Self::Block::LEN {
                iblock[rest.len()] = 0x80;
                self.raw_update(&iblock)?;
                bytemuck::zeroed()
            } else {
                let mut fblock: Self::Block = bytemuck::zeroed();
                fblock[0] = 0x80;
                fblock
            }
        };

        *fblock.last_chunk_mut() = bitcount.to_be_bytes();

        self.raw_update(&fblock)
    }

    fn finish(&mut self) -> crate::error::Result<Self::Output> {
        let map = self.state.map(|v| v.to_be_bytes());

        Ok(bytemuck::must_cast(map))
    }
}

impl ResetableDigest for Sha1 {
    fn reset(&mut self) -> crate::error::Result<()> {
        *self = Self::new();
        Ok(())
    }
}
