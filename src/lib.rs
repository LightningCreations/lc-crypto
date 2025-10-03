#![cfg_attr(not(any(test, feature = "std", doc)), no_std)]
#![feature(bigint_helper_methods)]
#![cfg_attr(feature = "nightly-docs", feature(intra_doc_pointers, doc_cfg))]
#![cfg_attr(
    all(feature = "std", feature = "nightly-std-io_error_more"),
    feature(io_error_more, io_error_inprogress)
)]
#![cfg_attr(feature = "nightly-allocator_api", feature(allocator_api))]
#![feature(iter_advance_by, trivial_bounds)]
#![cfg_attr(test, feature(macro_metavar_expr_concat))]
//!
//! Crate for primitives used by lc-crypto
//!
//! # Feature Flags
//! The following feature flags are supported:
//! * `alloc`: Allow features that require allocation
//! * `std`: Allow features that require the standard library.
//! * `error-track_caller`: Causes [`error::Error`]'s constructors to track the location of their creation, to aid in debugging.
//! Note that this does not expose any additional APIs but the [`Location`][core::panic::Location] will be printed by the [`Debug`] impl.
//! It is possible for error locations to provide limited information about secret data. Therefore, the debug output
//!
//! ## Nightly Feature Flags
//! Feature flags starting with `nightly` only work with an unstable (nightly) compiler, and are exempt from semver.
//! A minor release may remove or rename them, or limit what they enable
//!
//! * nightly-std-io_error_more: Support When the `std` feature is enabled, support [`std::io::ErrorKind`]s behind the `io_error_more` feature gate.

#[cfg(feature = "alloc")]
extern crate alloc;

pub mod asm;

pub mod cmp;

pub mod array;

pub mod error;
pub mod mem;

pub mod traits;

#[cfg(feature = "rand")]
pub mod rand;

#[cfg(feature = "digest")]
pub mod digest;

#[cfg(feature = "bignum")]
pub mod bignum;

pub mod secret;

mod detect;

#[cfg(test)]
mod test;

mod util;
