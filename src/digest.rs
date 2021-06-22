use alloc::boxed::Box;

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
    let mut x = bytes.chunks(D::BLOCK_SIZE);
    let last = x.next_back();
    for block in x {
        digest.update(block)
    }

    digest.do_final(last.unwrap_or(&[]), out)
}

#[cfg(test)]
mod test {
    use crate::digest::{
        sha1::Sha1,
        sha2::{Sha224, Sha256},
    };

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
}
