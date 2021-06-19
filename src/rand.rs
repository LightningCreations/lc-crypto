use alloc::boxed::Box;

pub trait SecureRandom {
    fn seed(&mut self);

    fn set_seed<I: IntoIterator<Item = u64>>(&mut self, seed: I);

    fn next_bytes(&mut self, out: &mut [u8]);
}

impl<SR: SecureRandom + ?Sized> SecureRandom for &mut SR {
    fn seed(&mut self) {
        SR::seed(self)
    }

    fn set_seed<I: IntoIterator<Item = u64>>(&mut self, seed: I) {
        SR::set_seed(self, seed)
    }

    fn next_bytes(&mut self, out: &mut [u8]) {
        SR::next_bytes(self, out)
    }
}

impl<SR: SecureRandom + ?Sized> SecureRandom for Box<SR> {
    fn seed(&mut self) {
        SR::seed(self)
    }

    fn set_seed<I: IntoIterator<Item = u64>>(&mut self, seed: I) {
        SR::set_seed(self, seed)
    }

    fn next_bytes(&mut self, out: &mut [u8]) {
        SR::next_bytes(self, out)
    }
}
