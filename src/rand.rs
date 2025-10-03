#[cfg(feature = "digest")]
use core::ops::Mul;

#[cfg(feature = "digest")]
use crate::digest::{ContinuousOutputDigest, ResetableDigest, SecretDigest};
use crate::error::Result;

pub trait CsRand {
    fn raw_next_bytes(&mut self, bytes: &mut [u8]) -> Result<()>;
}

pub trait SecretRand: CsRand {
    fn next_bytes(&mut self, bytes: &mut Secret<[u8]>) -> Result<()> {
        self.raw_next_bytes(bytes.get_mut_nonsecret())
    }
}

pub trait SeedableRand: CsRand {
    type Seed: ByteArray;
    fn init_with_seed(&mut self, seed: Self::Seed) -> Result<()>;

    fn seed_from_generator<G: CsRand>(&mut self, g: &mut G) -> Result<()> {
        let mut bytes = bytemuck::zeroed::<Self::Seed>();

        g.raw_next_bytes(crate::mem::as_slice_mut(&mut bytes))?;

        self.init_with_seed(bytes)
    }
}

pub trait MultiseedRand: CsRand {
    type Seed: ByteArray;
    fn injest_seed(&mut self, seed: Self::Seed) -> Result<()>;
}

pub struct XofDigestRand<D>(D);

#[cfg(feature = "digest")]
impl<D: ContinuousOutputDigest> CsRand for XofDigestRand<D> {
    fn raw_next_bytes(&mut self, bytes: &mut [u8]) -> Result<()> {
        let mut arr_chunks = D::Output::array_chunks_mut(bytes);
        let rem = arr_chunks.take_remainder();
        for block in arr_chunks {
            *block = self.0.next_output()?;
        }
        if rem.len() != 0 {
            use crate::mem::copy_from_slice_truncate;

            let last = self.0.next_output()?;
            copy_from_slice_truncate(rem, crate::mem::as_slice(&last));
        }
        Ok(())
    }
}

#[cfg(feature = "digest")]
impl<D: ContinuousOutputDigest + SecretDigest> SecretRand for XofDigestRand<D> {}

#[cfg(feature = "digest")]
impl<D: ContinuousOutputDigest + ResetableDigest> SeedableRand for XofDigestRand<D> {
    type Seed = D::Block;

    fn init_with_seed(&mut self, seed: Self::Seed) -> Result<()> {
        self.0.reset()?;
        self.0.raw_update(&seed)?;
        self.0.raw_update_final(&[])
    }
}

#[cfg(feature = "digest")]
impl<D: ContinuousOutputDigest> MultiseedRand for XofDigestRand<D> {
    type Seed = D::Block;
    fn injest_seed(&mut self, seed: Self::Seed) -> Result<()> {
        self.0.raw_update(&seed)
    }
}

use crate::secret::Secret;
use crate::traits::ByteArray;

#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
pub mod x86;
