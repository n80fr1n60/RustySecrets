//! `RustySecrets` implements Shamir's secret sharing in Rust. It provides the possibility to sign shares.

#![deny(
    missing_docs,
    missing_debug_implementations,
    missing_copy_implementations,
    trivial_casts,
    trivial_numeric_casts,
    unsafe_code,
    unstable_features,
    unused_import_braces,
    unused_qualifications
)]
#![allow(clippy::doc_markdown, clippy::result_large_err)]

#[macro_use]
mod gf256;
mod lagrange;
mod poly;
mod share;
mod vol_hash;

pub mod errors;
pub mod proto;
pub mod sss;
pub mod wrapped_secrets;

#[cfg(feature = "dss")]
pub mod dss;
