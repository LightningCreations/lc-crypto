pub mod sha1;

pub trait Digest {
    const OUTPUT_SIZE: usize;
    const BLOCK_SIZE: usize;
    fn new() -> Self;

    fn init(&mut self);

    fn update(&mut self, block: &[u8]);

    fn do_final(&mut self, lblock: &[u8], out: &mut [u8]);
}

pub fn digest<D: Digest>(bytes: &[u8], out: &mut [u8]) {
    let mut x = bytes.chunks(D::BLOCK_SIZE);
    let last = x.next_back();
    let mut digest = D::new();
    for block in x {
        digest.update(block)
    }

    digest.do_final(last.unwrap_or(&[]), out)
}

#[cfg(test)]
mod test {
    #[test]
    fn sha1_test_empty() {
        let expected: [u8; 20] = [
            0xda, 0x39, 0xa3, 0xee, 0x5e, 0x6b, 0x4b, 0x0d, 0x32, 0x55, 0xbf, 0xef, 0x95, 0x60,
            0x18, 0x90, 0xaf, 0xd8, 0x07, 0x09,
        ];
        let input = b"";
        let mut out = [0; 20];
        super::digest::<super::sha1::Sha1>(input, &mut out);
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
        super::digest::<super::sha1::Sha1>(input, &mut out);
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
        super::digest::<super::sha1::Sha1>(input, &mut out);
        assert_eq!(out, expected);
    }
}
