use crate::error::Result;

pub trait CsRand {
    fn next_bytes(&mut self, bytes: &mut [u8]) -> Result<()>;
}

use crate::secret::Secret;
use crate::traits::SecretTy;

/// The trait for producing new random numbers
pub trait Generate {
    fn new_from_sequence<R: CsRand>(rand: &mut R) -> Result<Self>
    where
        Self: Sized;

    fn fill_from_sequence<R: CsRand>(&mut self, rand: &mut R) -> Result<()>;
}

impl<S: SecretTy + ?Sized> Generate for Secret<S> {
    fn new_from_sequence<R: CsRand>(rand: &mut R) -> Result<Self>
    where
        Self: Sized,
    {
        let mut block: Self = unsafe { core::mem::zeroed() };
        block.fill_from_sequence(rand)?;

        Ok(block)
    }

    fn fill_from_sequence<R: CsRand>(&mut self, rand: &mut R) -> Result<()> {
        rand.next_bytes(self.as_byte_slice_mut().get_mut_nonsecret())
    }
}

impl<const N: usize> Generate for [u8; N] {
    fn fill_from_sequence<R: CsRand>(&mut self, rand: &mut R) -> Result<()> {
        rand.next_bytes(self)
    }

    fn new_from_sequence<R: CsRand>(rand: &mut R) -> Result<Self> {
        let mut bytes: Self = bytemuck::zeroed();
        rand.next_bytes(&mut bytes)?;

        Ok(bytes)
    }
}

impl Generate for [u8] {
    fn fill_from_sequence<R: CsRand>(&mut self, rand: &mut R) -> Result<()> {
        rand.next_bytes(self)
    }

    #[allow(dead_code)] // impl is invalid without this function
    fn new_from_sequence<R: CsRand>(rand: &mut R) -> Result<Self>
    where
        Self: Sized,
    {
        unreachable!()
    }
}

#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
pub mod x86;
