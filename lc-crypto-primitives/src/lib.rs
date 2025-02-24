#![cfg_attr(not(test), no_std)]
#![feature(array_chunks)]

#[cfg(feature = "alloc")]
extern crate alloc;

pub mod cmp;
pub mod digest;
pub mod error;
pub mod traits;
