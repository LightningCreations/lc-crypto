use alloc::{boxed::Box, vec};
use zeroize::Zeroizing;

use crate::digest::Digest;

pub struct Seeds<'a, SR: ?Sized>(&'a mut SR);

impl<'a, SR: SecureRandom> Iterator for Seeds<'a, SR> {
    type Item = u64;
    fn next(&mut self) -> Option<u64> {
        let mut bytes = [0; 8];
        self.0.next_bytes(&mut bytes);
        Some(u64::from_le_bytes(bytes))
    }
}

pub trait SecureRandom {
    // The number of bytes in the state. This, divided by 8 and rounded up yields the maximum number of words consumed by seed
    const STATE_SIZE: usize;
    fn seed<I: IntoIterator<Item = u64>>(&mut self, seed: I);

    fn next_bytes(&mut self, out: &mut [u8]);

    fn seeds(&mut self) -> Seeds<Self>
    where
        Self: Sized,
    {
        Seeds(self)
    }
}

impl<SR: SecureRandom + ?Sized> SecureRandom for &mut SR {
    const STATE_SIZE: usize = SR::STATE_SIZE;
    fn seed<I: IntoIterator<Item = u64>>(&mut self, seed: I) {
        SR::seed(self, seed)
    }

    fn next_bytes(&mut self, out: &mut [u8]) {
        SR::next_bytes(self, out)
    }
}

impl<SR: SecureRandom + ?Sized> SecureRandom for Box<SR> {
    const STATE_SIZE: usize = SR::STATE_SIZE;
    fn seed<I: IntoIterator<Item = u64>>(&mut self, seed: I) {
        SR::seed(self, seed)
    }

    fn next_bytes(&mut self, out: &mut [u8]) {
        SR::next_bytes(self, out)
    }
}

pub struct DoubleDigestRandom<D1, D2> {
    update: D1,
    output: D2,
    state1: Zeroizing<Box<[u8]>>,
}

impl<D1: Digest, D2: Digest> DoubleDigestRandom<D1, D2> {
    pub fn new(update: D1, output: D2) -> Self {
        Self {
            update,
            output,
            state1: Zeroizing::new(vec![0; D1::OUTPUT_SIZE].into_boxed_slice()),
        }
    }

    fn update(&mut self, output: &mut [u8]) {
        let mut inter = Zeroizing::new(vec![0u8; D1::OUTPUT_SIZE].into_boxed_slice());
        crate::digest::digest(&mut self.update, &self.state1, &mut inter);
        self.state1.copy_from_slice(&inter);
        for i in inter.iter_mut() {
            // Mitigation for D1=D2
            *i ^= 0xa8;
        }
        crate::digest::digest(&mut self.output, &inter, output);
    }
}

impl<D1: Digest, D2: Digest> SecureRandom for DoubleDigestRandom<D1, D2> {
    const STATE_SIZE: usize = D1::OUTPUT_SIZE;
    fn seed<I: IntoIterator<Item = u64>>(&mut self, seed: I) {
        self.state1.fill(0);
        for (o, v) in self.state1.chunks_mut(8).zip(seed) {
            let bytes = v.to_le_bytes();
            let len = o.len();
            o.copy_from_slice(&bytes[..len])
        }
    }

    fn next_bytes(&mut self, out: &mut [u8]) {
        let mut r = out.chunks_mut(D2::OUTPUT_SIZE);
        let last = r.next_back().unwrap_or(&mut []);
        for block in r {
            self.update(block);
        }
        let mut fblock = Zeroizing::new(vec![0u8; D2::OUTPUT_SIZE].into_boxed_slice());
        self.update(&mut fblock);
        let len = last.len();
        last.copy_from_slice(&fblock[..len]);
    }
}

pub mod system;


