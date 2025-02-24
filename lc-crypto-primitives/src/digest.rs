use crate::error::Result;
use crate::traits::ByteArray;

pub trait PrimitiveDigest {
    type Output: ByteArray;
    type Block: ByteArray;

    fn update(&mut self, block: &Self::Block) -> Result<()>;
    fn do_final(&mut self, final_block: &[u8]) -> Result<Self::Output>;
}
