use crate::error::Result;

pub trait CsRand {
    fn next_bytes(&mut self, bytes: &mut [u8]) -> Result<()>;
}
