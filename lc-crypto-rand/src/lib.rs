#![feature(trivial_bounds, array_chunks)]
#![cfg_attr(not(feature = "std"), no_std)]
//! Library for providing random number generators and generation routines
//!
//! # Features
//! * `alloc`: Enables operations that require the use of the `alloc` crate
//! * `std`: Enables operations that require use of the `std` crate
//! * `use-insecure-hw-rng`: Enables support for [`system::x86::X86Rand`] using the `rdrand` target_feature only (instead of `rdseed`) (but see below).
//!
//! # Insecure Hardware RNG Support
//! To limit potential security issues, certain hardware random number generators require the `use-insecure-hw-rng` feature to be available.
//! The feature gate controls the prescence of implementations of [`CsRand`][lc_crypto_primitives::rand::CsRand].
//! However, if the hardware RNG is not secure, calls to that generator will unconditionally fail by default.
//! To override this, you must set the cfg flag `lc_crypto_insecure_rng` on the command line (not via Cargo features!!!).
//! This can be done by setting `RUSTFLAGS`. Do this only after an audit of your system and use case is performed and either:
//! * You know the relevant hardware generator to not be affected by the relevant flaws, or
//! * It is acceptable in your particular use case to recieve lower-quality random numbers from the generator.
//!
//! Do not enable this cfg gate if you are not certain that it safe to do so.

#[cfg(feature = "alloc")]
extern crate alloc;

pub mod traits;

pub mod system;
