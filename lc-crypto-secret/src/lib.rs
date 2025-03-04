#![cfg_attr(not(any(test, feature = "std")), no_std)]
#![cfg_attr(feature = "nightly-allocator_api", feature(allocator_api))]
#![cfg_attr(feature = "nightly-docs", feature(doc_cfg))]

#[cfg(feature = "alloc")]
extern crate alloc;

pub mod secret;
pub mod traits;
