#![cfg_attr(not(test), no_std)]
#![feature(array_chunks)]
#![cfg_attr(doc, feature(intra_doc_pointers))]

#[cfg(feature = "alloc")]
extern crate alloc;

pub mod asm;
pub mod cmp;
pub mod digest;
pub mod error;
pub mod mem;
pub mod rand;
pub mod traits;
