use alloc::{boxed::Box, vec};
use zeroize::Zeroizing;

pub mod sha1;
pub mod sha2;

pub trait Digest {
    const OUTPUT_SIZE: usize;
    const BLOCK_SIZE: usize;

    fn init(&mut self);

    fn update(&mut self, block: &[u8]);

    fn do_final(&mut self, lblock: &[u8], out: &mut [u8]);
}

impl<D: Digest> Digest for &mut D {
    const OUTPUT_SIZE: usize = D::OUTPUT_SIZE;
    const BLOCK_SIZE: usize = D::BLOCK_SIZE;

    fn init(&mut self) {
        <D as Digest>::init(self)
    }

    fn update(&mut self, block: &[u8]) {
        <D as Digest>::update(self, block)
    }

    fn do_final(&mut self, lblock: &[u8], out: &mut [u8]) {
        <D as Digest>::do_final(self, lblock, out)
    }
}

impl<D: Digest> Digest for Box<D> {
    const OUTPUT_SIZE: usize = D::OUTPUT_SIZE;
    const BLOCK_SIZE: usize = D::BLOCK_SIZE;

    fn init(&mut self) {
        <D as Digest>::init(self)
    }

    fn update(&mut self, block: &[u8]) {
        <D as Digest>::update(self, block)
    }

    fn do_final(&mut self, lblock: &[u8], out: &mut [u8]) {
        <D as Digest>::do_final(self, lblock, out)
    }
}

pub fn digest<D: Digest>(mut digest: D, bytes: &[u8], out: &mut [u8]) {
    digest.init();
    let mut x = bytes.chunks(D::BLOCK_SIZE);
    let last = x.next_back();
    for block in x {
        digest.update(block)
    }

    digest.do_final(last.unwrap_or(&[]), out)
}

pub struct Hmac<D: Digest> {
    digest: D,
    key: Zeroizing<Box<[u8]>>,
}

impl<D: Digest> Hmac<D> {
    pub fn new(mut digest: D, key: &[u8]) -> Self {
        let mut inner_key = Zeroizing::new(vec![0u8; D::BLOCK_SIZE].into_boxed_slice());
        if key.len() <= inner_key.len() {
            let len = key.len();
            inner_key[..len].copy_from_slice(key);
        } else {
            self::digest(&mut digest, key, &mut inner_key[..D::OUTPUT_SIZE]);
        }
        Self {
            digest,
            key: inner_key,
        }
    }
}

impl<D: Digest> Digest for Hmac<D> {
    const OUTPUT_SIZE: usize = D::OUTPUT_SIZE;
    const BLOCK_SIZE: usize = D::BLOCK_SIZE;

    fn init(&mut self) {
        self.digest.init();
        for i in self.key.iter_mut() {
            *i ^= 0x36;
        }
        self.digest.update(&self.key);
        for i in self.key.iter_mut() {
            *i ^= 0x36 ^ 0x5c; // Undo the inner padding, and add the outer padding
        }
    }

    fn update(&mut self, block: &[u8]) {
        self.digest.update(block);
    }

    fn do_final(&mut self, lblock: &[u8], output: &mut [u8]) {
        let mut tmp_out = Zeroizing::new(vec![0u8; D::BLOCK_SIZE].into_boxed_slice());
        self.digest.do_final(lblock, &mut tmp_out);
        self.digest.init();
        let mut x = self
            .key
            .chunks(D::BLOCK_SIZE)
            .chain(tmp_out.chunks(D::BLOCK_SIZE));
        let last = x.next_back();
        for block in x {
            self.digest.update(block)
        }
        self.digest.do_final(last.unwrap_or(&[]), output);
        for i in self.key.iter_mut() {
            *i ^= 0x5c; // Undo the inner padding, and add the outer padding
        }
    }
}

#[cfg(test)]
mod test {
    use crate::digest::{
        sha1::Sha1,
        sha2::{Sha224, Sha256, Sha512, Sha512_224, Sha512_256},
        Hmac,
    };

    use super::sha2::Sha384;

    #[test]
    fn sha1_test_empty() {
        let expected: [u8; 20] = [
            0xda, 0x39, 0xa3, 0xee, 0x5e, 0x6b, 0x4b, 0x0d, 0x32, 0x55, 0xbf, 0xef, 0x95, 0x60,
            0x18, 0x90, 0xaf, 0xd8, 0x07, 0x09,
        ];
        let input = b"";
        let mut out = [0; 20];
        super::digest(Sha1::new(), input, &mut out);
        assert_eq!(out, expected);
    }

    #[test]
    fn sha1_test_longstr() {
        let input = b"The quick brown fox jumps over the lazy dog";
        let mut out = [0; 20];
        let expected: [u8; 20] = [
            0x2f, 0xd4, 0xe1, 0xc6, 0x7a, 0x2d, 0x28, 0xfc, 0xed, 0x84, 0x9e, 0xe1, 0xbb, 0x76,
            0xe7, 0x39, 0x1b, 0x93, 0xeb, 0x12,
        ];
        super::digest(Sha1::new(), input, &mut out);
        assert_eq!(out, expected);
    }

    #[test]
    fn sha1_test_longstr2() {
        let input = b"The quick brown fox jumps over the lazy cog";
        let mut out = [0; 20];
        let expected: [u8; 20] = [
            0xde, 0x9f, 0x2c, 0x7f, 0xd2, 0x5e, 0x1b, 0x3a, 0xfa, 0xd3, 0xe8, 0x5a, 0x0b, 0xd1,
            0x7d, 0x9b, 0x10, 0x0d, 0xb4, 0xb3,
        ];
        super::digest(Sha1::new(), input, &mut out);
        assert_eq!(out, expected);
    }

    #[test]
    fn sha224_test_empty() {
        let input = b"";
        let mut out = [0; 28];
        let expected: [u8; 28] = [
            0xd1, 0x4a, 0x02, 0x8c, 0x2a, 0x3a, 0x2b, 0xc9, 0x47, 0x61, 0x02, 0xbb, 0x28, 0x82,
            0x34, 0xc4, 0x15, 0xa2, 0xb0, 0x1f, 0x82, 0x8e, 0xa6, 0x2a, 0xc5, 0xb3, 0xe4, 0x2f,
        ];
        super::digest(Sha224::new(), input, &mut out);
        assert_eq!(out, expected);
    }

    #[test]
    fn sha256_test_empty() {
        let input = b"";
        let mut out = [0; 32];
        let expected = [
            0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14, 0x9a, 0xfb, 0xf4, 0xc8, 0x99, 0x6f,
            0xb9, 0x24, 0x27, 0xae, 0x41, 0xe4, 0x64, 0x9b, 0x93, 0x4c, 0xa4, 0x95, 0x99, 0x1b,
            0x78, 0x52, 0xb8, 0x55,
        ];

        super::digest(Sha256::new(), input, &mut out);
        assert_eq!(out, expected);
    }

    #[test]
    fn sha224_test_longstr() {
        let input = b"The quick brown fox jumps over the lazy dog";
        let mut out = [0; 28];
        let expected: [u8; 28] = [
            0x73, 0x0e, 0x10, 0x9b, 0xd7, 0xa8, 0xa3, 0x2b, 0x1c, 0xb9, 0xd9, 0xa0, 0x9a, 0xa2,
            0x32, 0x5d, 0x24, 0x30, 0x58, 0x7d, 0xdb, 0xc0, 0xc3, 0x8b, 0xad, 0x91, 0x15, 0x25,
        ];
        super::digest(Sha224::new(), input, &mut out);
        assert_eq!(out, expected);
    }

    #[test]
    fn sha256_test_longstr() {
        let input = b"The quick brown fox jumps over the lazy dog";
        let mut out = [0; 32];
        let expected = [
            0xd7, 0xa8, 0xfb, 0xb3, 0x07, 0xd7, 0x80, 0x94, 0x69, 0xca, 0x9a, 0xbc, 0xb0, 0x08,
            0x2e, 0x4f, 0x8d, 0x56, 0x51, 0xe4, 0x6d, 0x3c, 0xdb, 0x76, 0x2d, 0x02, 0xd0, 0xbf,
            0x37, 0xc9, 0xe5, 0x92,
        ];

        super::digest(Sha256::new(), input, &mut out);
        assert_eq!(out, expected);
    }

    #[test]
    fn sha384_test_empty() {
        let input = b"";
        let mut out = [0u8; 48];
        let expected = [
            0x38, 0xb0, 0x60, 0xa7, 0x51, 0xac, 0x96, 0x38, 0x4c, 0xd9, 0x32, 0x7e, 0xb1, 0xb1,
            0xe3, 0x6a, 0x21, 0xfd, 0xb7, 0x11, 0x14, 0xbe, 0x07, 0x43, 0x4c, 0x0c, 0xc7, 0xbf,
            0x63, 0xf6, 0xe1, 0xda, 0x27, 0x4e, 0xde, 0xbf, 0xe7, 0x6f, 0x65, 0xfb, 0xd5, 0x1a,
            0xd2, 0xf1, 0x48, 0x98, 0xb9, 0x5b,
        ];
        super::digest(Sha384::new(), input, &mut out);
        assert_eq!(out, expected);
    }

    #[test]
    fn sha512_test_empty() {
        let input = b"";
        let mut out = [0u8; 64];
        let expected = [
            0xcf, 0x83, 0xe1, 0x35, 0x7e, 0xef, 0xb8, 0xbd, 0xf1, 0x54, 0x28, 0x50, 0xd6, 0x6d,
            0x80, 0x07, 0xd6, 0x20, 0xe4, 0x05, 0x0b, 0x57, 0x15, 0xdc, 0x83, 0xf4, 0xa9, 0x21,
            0xd3, 0x6c, 0xe9, 0xce, 0x47, 0xd0, 0xd1, 0x3c, 0x5d, 0x85, 0xf2, 0xb0, 0xff, 0x83,
            0x18, 0xd2, 0x87, 0x7e, 0xec, 0x2f, 0x63, 0xb9, 0x31, 0xbd, 0x47, 0x41, 0x7a, 0x81,
            0xa5, 0x38, 0x32, 0x7a, 0xf9, 0x27, 0xda, 0x3e,
        ];
        super::digest(Sha512::new(), input, &mut out);
        assert_eq!(out, expected);
    }

    #[test]
    fn sha512_224_test_empty() {
        let input = b"";
        let mut out = [0u8; 28];
        let expected = [
            0x6e, 0xd0, 0xdd, 0x02, 0x80, 0x6f, 0xa8, 0x9e, 0x25, 0xde, 0x06, 0x0c, 0x19, 0xd3,
            0xac, 0x86, 0xca, 0xbb, 0x87, 0xd6, 0xa0, 0xdd, 0xd0, 0x5c, 0x33, 0x3b, 0x84, 0xf4,
        ];
        super::digest(Sha512_224::new(), input, &mut out);
        assert_eq!(out, expected);
    }

    #[test]
    fn sha512_256_test_empty() {
        let input = b"";
        let mut out = [0u8; 32];
        let expected = [
            0xc6, 0x72, 0xb8, 0xd1, 0xef, 0x56, 0xed, 0x28, 0xab, 0x87, 0xc3, 0x62, 0x2c, 0x51,
            0x14, 0x06, 0x9b, 0xdd, 0x3a, 0xd7, 0xb8, 0xf9, 0x73, 0x74, 0x98, 0xd0, 0xc0, 0x1e,
            0xce, 0xf0, 0x96, 0x7a,
        ];
        super::digest(Sha512_256::new(), input, &mut out);
        assert_eq!(out, expected);
    }

    #[test]
    fn hmac_sha1_test_smart() {
        let input = b"The quick brown fox jumps over the lazy dog";
        let key = b"key";
        let mut out = [0u8; 20];
        let expected = [
            0xde, 0x7c, 0x9b, 0x85, 0xb8, 0xb7, 0x8a, 0xa6, 0xbc, 0x8a, 0x7a, 0x36, 0xf7, 0x0a,
            0x90, 0x70, 0x1c, 0x9d, 0xb4, 0xd9,
        ];
        super::digest(Hmac::new(Sha1::new(), key), input, &mut out);
        assert_eq!(out, expected);
    }
}
