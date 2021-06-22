use zeroize::Zeroize;

use super::Digest;

fn do_sha32_block(block: &[u8], h: &mut [u32; 8]) {
    let k = [
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4,
        0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe,
        0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f,
        0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
        0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc,
        0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
        0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070, 0x19a4c116,
        0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7,
        0xc67178f2,
    ];
    let block = bytemuck::cast_slice::<u8, [u8; 4]>(block);
    let mut w = [0u32; 64];
    for i in 0..16 {
        w[i] = u32::from_be_bytes(block[i]);
    }

    for i in 16..64 {
        let s0 = w[i - 15].rotate_right(7) ^ w[i - 15].rotate_right(18) ^ (w[i - 15] >> 3);
        let s1 = w[i - 2].rotate_right(17) ^ w[i - 2].rotate_right(19) ^ (w[i - 2] >> 10);
        w[i] = w[i - 16]
            .wrapping_add(s0)
            .wrapping_add(w[i - 7])
            .wrapping_add(s1);
    }

    let mut a = h[0];
    let mut b = h[1];
    let mut c = h[2];
    let mut d = h[3];
    let mut e = h[4];
    let mut f = h[5];
    let mut g = h[6];
    let mut l = h[7];

    for i in 0..64 {
        let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
        let ch = (e & f) ^ ((!e) & g);
        let temp1 = l
            .wrapping_add(s1)
            .wrapping_add(ch)
            .wrapping_add(k[i])
            .wrapping_add(w[i]);
        let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
        let maj = (a & b) ^ (a & c) ^ (b & c);
        let temp2 = s0.wrapping_add(maj);

        l = g;
        g = f;
        f = e;
        e = d.wrapping_add(temp1);
        d = c;
        c = b;
        b = a;
        a = temp1.wrapping_add(temp2);
    }

    h[0] = h[0].wrapping_add(a);
    h[1] = h[1].wrapping_add(b);
    h[2] = h[2].wrapping_add(c);
    h[3] = h[3].wrapping_add(d);
    h[4] = h[4].wrapping_add(e);
    h[5] = h[5].wrapping_add(f);
    h[6] = h[6].wrapping_add(g);
    h[7] = h[7].wrapping_add(l);
}

pub struct Sha32<const BITS: usize> {
    h: [u32; 8],
    size: u64,
}

impl Sha32<224> {
    pub const fn new() -> Self {
        Self {
            h: [
                0xc1059ed8, 0x367cd507, 0x3070dd17, 0xf70e5939, 0xffc00b31, 0x68581511, 0x64f98fa7,
                0xbefa4fa4,
            ],
            size: 0,
        }
    }
}

impl Sha32<256> {
    pub const fn new() -> Self {
        Self {
            h: [
                0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab,
                0x5be0cd19,
            ],
            size: 0,
        }
    }
}

impl Default for Sha32<224> {
    fn default() -> Self {
        Self::new()
    }
}

impl Default for Sha32<256> {
    fn default() -> Self {
        Self::new()
    }
}

impl<const BITS: usize> Digest for Sha32<BITS> {
    const BLOCK_SIZE: usize = 64;
    const OUTPUT_SIZE: usize = BITS / 8;

    fn init(&mut self) {
        // This would work so well with specialization
        self.size = 0;
        self.h = match BITS {
            224 => [
                0xc1059ed8, 0x367cd507, 0x3070dd17, 0xf70e5939, 0xffc00b31, 0x68581511, 0x64f98fa7,
                0xbefa4fa4,
            ],
            256 => [
                0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab,
                0x5be0cd19,
            ],
            _ => unreachable!(),
        }
    }

    fn update(&mut self, block: &[u8]) {
        self.size = block.len() as u64 * 8;
        do_sha32_block(block, &mut self.h)
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
        for i in 0..(BITS / 32) {
            out[i] = self.h[i].to_be_bytes();
        }
    }
}

pub type Sha224 = Sha32<224>;
pub type Sha256 = Sha32<256>;
