use core::convert::TryInto;

use zeroize::{Zeroize, Zeroizing};

use super::Digest;

#[cfg(target_arch = "x86_64")]
mod x86_64;

pub struct Sha1 {
    h: [u32; 5],
    size: u64,
}

impl Sha1 {
    pub const fn new() -> Self {
        Self {
            h: [0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0],
            size: 0,
        }
    }
}

impl Default for Sha1 {
    fn default() -> Self {
        Self::new()
    }
}

impl Digest for Sha1 {
    const OUTPUT_SIZE: usize = 20;
    const BLOCK_SIZE: usize = 64;

    fn init(&mut self) {
        *self = Self::new()
    }

    fn update(&mut self, block: &[u8]) {
        let block: Zeroizing<[[u8; 4]; 16]> = Zeroizing::new(
            bytemuck::cast_slice::<u8, [u8; 4]>(block)
                .try_into()
                .unwrap(),
        );
        self.size += 512;
        let mut words = [0; 80];
        for i in 0..16 {
            words[i] = u32::from_be_bytes((*block)[i]);
        }

        for i in 16..80 {
            words[i] = (words[i - 3] ^ words[i - 8] ^ words[i - 14] ^ words[i - 16]).rotate_left(1);
        }

        let mut a = self.h[0];
        let mut b = self.h[1];
        let mut c = self.h[2];
        let mut d = self.h[3];
        let mut e = self.h[4];
        for i in 0..80 {
            let (f, k) = match i {
                0..=19 => ((b & c) | ((!b) & d), 0x5A827999u32),
                20..=39 => (b ^ c ^ d, 0x6ED9EBA1u32),
                40..=59 => ((b & c) | (b & d) | (c & d), 0x8F1BBCDCu32),
                60..=79 => (b ^ c ^ d, 0xCA62C1D6u32),
                _ => unreachable!(),
            };
            let tmp = a
                .rotate_left(5)
                .wrapping_add(f)
                .wrapping_add(e)
                .wrapping_add(k)
                .wrapping_add(words[i]);
            e = d;
            d = c;
            c = b.rotate_left(30);
            b = a;
            a = tmp;
        }
        self.h[0] = self.h[0].wrapping_add(a);
        self.h[1] = self.h[1].wrapping_add(b);
        self.h[2] = self.h[2].wrapping_add(c);
        self.h[3] = self.h[3].wrapping_add(d);
        self.h[4] = self.h[4].wrapping_add(e);
    }

    fn do_final(&mut self, mut lblock: &[u8], out: &mut [u8]) {
        assert!(lblock.len() <= 64);
        if lblock.len() == 64 {
            self.update(lblock);
            lblock = &[];
        }
        let len = lblock.len();
        let mut bytes = [0u8; 64];
        bytes[..len].copy_from_slice(lblock);
        self.size += (lblock.len() as u64) * 8;
        let ml = self.size;
        bytes[len] = 0x80;
        if (64 - len) < 8 {
            self.update(&bytes);
            bytes = [0u8; 64];
        }
        let len = bytes.len() - 8;
        bytes[len..].copy_from_slice(&ml.to_be_bytes());
        self.update(&bytes);
        bytes.zeroize();
        let out = bytemuck::cast_slice_mut::<u8, [u8; 4]>(out);
        for i in 0..5 {
            out[i] = self.h[i].to_be_bytes();
        }
    }
}
