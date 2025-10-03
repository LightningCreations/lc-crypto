use crate::{is_x86_feature_detected, rand::CsRand};

use crate::traits::ByteArray;

#[cfg(target_arch = "x86_64")]
use core::arch::x86_64 as arch;

#[cfg(target_arch = "x86")]
use core::arch::x86 as arch;

#[cfg(target_arch = "x86")]
type Word = u32;
#[cfg(target_arch = "x86_64")]
type Word = u64;

#[derive(Copy, Clone, Debug)]
enum RdRandMode {
    Absent,
    Rdrand,
    Rdseed,
}

#[derive(Copy, Clone, Debug)]
pub struct X86Rand(RdRandMode);

impl X86Rand {
    pub fn new() -> Self {
        match (
            is_x86_feature_detected!("rdseed"),
            is_x86_feature_detected!("rdrand"),
        ) {
            (true, _) => Self(RdRandMode::Rdseed),
            (false, true) => Self(RdRandMode::Rdrand),
            (false, false) => Self(RdRandMode::Absent),
        }
    }

    fn test(&self) -> crate::error::Result<()> {
        match self.0 {
            RdRandMode::Rdseed => Ok(()),
            #[cfg(all(feature = "use-insecure-hw-rng", allow_insecure_hw_rand))]
            RdRandMode::Rdrand => Ok(()),
            _ => Err(crate::error::Error::new_with_message(
                crate::error::ErrorKind::Unsupported,
                "X86Rand is not supported on hardware",
            )),
        }
    }

    fn inner_poll(&self) -> Option<u32> {
        let mut res = 0;
        let b = match self.0 {
            RdRandMode::Rdrand => unsafe { arch::_rdrand32_step(&mut res) },
            RdRandMode::Rdseed => unsafe { arch::_rdseed32_step(&mut res) },
            _ => 0,
        };

        if b != 0 { Some(res) } else { None }
    }

    fn poll(&self) -> u32 {
        loop {
            match self.inner_poll() {
                Some(val) => break val,
                None => continue,
            }
        }
    }
}

impl CsRand for X86Rand {
    fn raw_next_bytes(&mut self, bytes: &mut [u8]) -> crate::error::Result<()> {
        self.test()?;
        let mut chunks = <[u8; 4]>::array_chunks_mut(bytes);

        for chunk in &mut chunks {
            *chunk = self.poll().to_ne_bytes();
        }

        let rem = chunks.into_remainder();

        if rem.len() != 0 {
            rem.copy_from_slice(&self.poll().to_ne_bytes()[..rem.len()]);
        }

        Ok(())
    }
}
