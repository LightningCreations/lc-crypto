#![cfg_attr(not(any(test,feature="std")),no_std)]
#![deny(unsafe_code)]

extern crate alloc;

pub mod cmp;
pub mod digest;
pub mod rand;
pub mod symm;
