#![allow(unused_imports)]

use crate::rand::SecureRandom;

#[cfg(all(target_arch = "x86", not(target_arch = "x86_64")))]
use core::arch::x86 as arch;

#[cfg(all(target_arch = "x86_64"))]
use core::arch::x86_64 as arch;

pub struct X86Rand {
    _inner: (),
}

impl X86Rand {
    pub fn new() -> Self {
        Self { _inner: () }
    }
}

impl SecureRandom for X86Rand {
    const STATE_SIZE: usize = 0;

    fn seed<I: IntoIterator<Item = u64>>(&mut self, _: I) {}

    #[allow(unsafe_code, unreachable_code, unused_variables, unused_mut)] // AAAA cfg doesn't supress lints
    fn next_bytes(&mut self, out: &mut [u8]) {
        for i in out.chunks_mut(4) {
            let len = i.len();
            let mut value = 0u32;

            #[cfg(target_feature = "rdseed")]
            {
                while unsafe { arch::_rdseed32_step(&mut value) } != 1 {}
            }

            #[cfg(all(target_feature = "rdrand", not(target_feature = "rdseed")))]
            {
                while unsafe { arch::_rdrand32_step(&mut value) } != 1 {}
            }
            #[cfg(not(any(target_feature = "rdrand", target_feature = "rdseed")))]
            {
                panic!("X86Rand cannot be used without rdseed or rdrand");
            }
            let value = value.to_le_bytes();
            i.copy_from_slice(&value[..len]);
        }
    }
}
