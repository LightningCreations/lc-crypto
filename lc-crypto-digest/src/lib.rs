#![no_std]

use lc_crypto_primitives::{
    digest::RawDigest,
    traits::{ByteArray, SecretTy},
};
use lc_crypto_secret::secret::Secret;

use crate::traits::SecretDigest;

pub mod mac;
pub mod raw;
pub mod traits;

pub fn digest<D: SecretDigest, R: AsRef<Secret<[u8]>> + ?Sized>(
    mut digest: D,
    s: &R,
) -> lc_crypto_primitives::error::Result<D::Output> {
    // Security:
    // We're just using this to pass into a digest, which is assumed to respect secrecy
    let bytes = s.as_ref();
    let input = bytes.array_chunks::<D::Block>();

    let rem = input.remainder();

    for block in input {
        digest.update(block)?;
    }
    digest.update_final(rem)?;

    digest.finish()
}
