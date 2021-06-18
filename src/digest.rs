pub mod sha1;

pub trait Digest {
    const OUTPUT_SIZE: usize;
    fn new() -> Self;

    fn init(&mut self);

    fn update(&mut self, block: &[u8]);

    fn do_final(&mut self, out: &mut [u8]);
}
