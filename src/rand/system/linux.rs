#![allow(unsafe_code)]

use crate::rand::SecureRandom;

pub struct LinuxRand {
    inner: libc::c_int,
}

impl LinuxRand {
    pub fn new() -> Self {
        Self {
            inner: unsafe { libc::open((b"/dev/random\0" as *const [u8]).cast(), libc::O_RDONLY) },
        }
    }
}

impl SecureRandom for LinuxRand {
    const STATE_SIZE: usize = 0;

    fn seed<I: IntoIterator<Item = u64>>(&mut self, _: I) {}

    fn next_bytes(&mut self, mut out: &mut [u8]) {
        loop {
            while let b @ 1.. =
                unsafe { libc::read(self.inner, (out as *mut [u8]).cast(), out.size) }
            {
                out = out[(b as usize)..]
            }
        }
    }
}
