use lc_crypto_primitives::{digest::RawDigest, error, traits::ByteArray};
use lc_crypto_secret::secret::Secret;

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

pub trait ExtendedKeyedDigest: RawDigest {
    fn reset_with_extended_key(&mut self, key: &[u8]) -> error::Result<()>;
}