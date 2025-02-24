use crate::rand::SecureRandom;

pub struct LinuxRand;

#[allow(unsafe_code)]
impl SecureRandom for LinuxRand {
    const STATE_SIZE: usize = 0;

    #[inline(always)]
    fn seed_dyn(&mut self, _: &mut dyn Iterator<Item = u64>) {}

    fn next_bytes(&mut self, out: &mut [u8]) {
        let out = out as *mut [u8];
        unsafe {
            libc::getrandom(out.cast(), out.len(), libc::GRND_RANDOM);
        }
    }
}
