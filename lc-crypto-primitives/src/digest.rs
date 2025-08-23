use crate::error::Result;
use crate::traits::ByteArray;

pub trait RawDigest {
    type Block: ByteArray;
    type Output: ByteArray;

    fn raw_update(&mut self, block: &Self::Block) -> Result<()>;
    fn raw_update_final(&mut self, rest: &[u8]) -> Result<()>;
    fn finish(&self) -> Result<Self::Output>;
}

pub trait KeyedDigest: RawDigest {
    type Key: ByteArray;

    fn reset_with_key(&mut self, key: &Self::Key) -> Result<()>;
}

pub trait ResetableDigest: RawDigest {
    fn reset(&mut self) -> Result<()>;
}
