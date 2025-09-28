use crate::error::{self, Result};
use crate::secret::Secret;
use crate::traits::ByteArray;

pub trait RawDigest {
    type Block: ByteArray;
    type Output: ByteArray;

    fn raw_update(&mut self, block: &Self::Block) -> Result<()>;
    fn raw_update_final(&mut self, rest: &[u8]) -> Result<()>;
    fn finish(&mut self) -> Result<Self::Output>;
}

pub trait ContinuousOutputDigest: RawDigest {
    fn next_output(&mut self) -> Result<Self::Output> {
        self.finish()
    }
}

pub trait KeyedDigest: RawDigest {
    type Key: ByteArray;

    fn reset_with_key(&mut self, key: &Self::Key) -> Result<()>;
}

pub trait ResetableDigest: RawDigest {
    fn reset(&mut self) -> Result<()>;
}

/// Implemented for [`RawDigest`] types that are valid to pass secret values into.
/// Almost all [`RawDigest`] types can implement this trait
pub trait SecretDigest: RawDigest {
    fn update(&mut self, block: &Secret<Self::Block>) -> error::Result<()> {
        <Self as RawDigest>::raw_update(self, block.get_nonsecret())
    }
    fn update_final(&mut self, block: &Secret<[u8]>) -> error::Result<()> {
        <Self as RawDigest>::raw_update_final(self, block.get_nonsecret())
    }
}

pub mod raw;

pub fn digest<D: RawDigest>(mut digest: D, bytes: &[u8]) -> error::Result<D::Output> {
    let chunks = D::Block::array_chunks(bytes);
    let rem = chunks.remainder();
    for chunk in chunks {
        digest.raw_update(chunk)?;
    }
    digest.raw_update_final(rem)?;

    digest.finish()
}

pub fn digest_secret<D: SecretDigest>(
    mut digest: D,
    bytes: &Secret<[u8]>,
) -> error::Result<D::Output> {
    let chunks = bytes.array_chunks::<D::Block>();
    let rem = chunks.remainder();
    for chunk in chunks {
        digest.update(chunk)?;
    }
    digest.update_final(rem)?;

    digest.finish()
}
