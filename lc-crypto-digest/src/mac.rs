use lc_crypto_primitives::{array::BaseArrayVec, digest::RawDigest};
use lc_crypto_secret::secret::Secret;

pub struct HMac<U: RawDigest> {
    inner: U,
    outer: U,
    key: BaseArrayVec<Secret<U::Block>>,
}

impl<U: RawDigest> HMac<U> {
    pub const fn new_with_key<S: AsRef<Secret<[u8]>>>(inner: U, outer: U, key: S) -> Self {

    }
}
