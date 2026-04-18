//! Define the various error kinds specific to secret sharing.

#![allow(missing_docs)]

use std::collections::HashSet;
use std::fmt;

#[cfg(feature = "dss")]
use crate::dss::ss1;

/// Minimum allowed number of shares (n)
pub(crate) static MIN_SHARES: u8 = 2;
/// Minimum allowed threshold (k)
pub(crate) static MIN_THRESHOLD: u8 = 2;
/// Maximum allowed number of shares (k,n)
pub(crate) static MAX_SHARES: u8 = 255;
/// SSS Shares should be structured as k-n-data hence 3 parts
pub(crate) static SSS_SHARE_PARTS_COUNT: usize = 3;

/// The error type for rusty_secrets operations.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("Threshold k must be smaller than or equal to n, got: k = {0}, n = {1}.")]
    ThresholdTooBig(u8, u8),

    #[error("Threshold k must be bigger than or equal to 2, got: k = {0}")]
    ThresholdTooSmall(u8),

    #[error("The secret is too long, maximum allowed size = {1} bytes, got {0} bytes")]
    SecretTooBig(usize, usize),

    #[error("Number of shares must be smaller than or equal {1}, got: {0} shares.")]
    InvalidShareCountMax(u8, u8),

    #[error("Number of shares must be larger than or equal {1}, got: {0} shares.")]
    InvalidShareCountMin(u8, u8),

    #[error("The secret cannot be empty")]
    EmptySecret,

    #[error("No shares were provided.")]
    EmptyShares,

    #[error("The shares are incompatible with each other.")]
    IncompatibleSets(Vec<HashSet<u8>>),

    #[error("{1} shares are required to recover the secret, found only {0}.")]
    MissingShares(usize, u8),

    #[error("The signature of this share is not valid.")]
    InvalidSignature(u8, String),

    #[error("Signature is missing while shares are required to be signed.")]
    MissingSignature(u8),

    #[error("An issue was encountered deserializing the secret. Updating to the latest version of RustySecrets might help fix this.")]
    SecretDeserializationError,

    #[error("This share is incorrectly formatted. Reason: {0}")]
    ShareParsingError(String),

    #[error("Found empty share for share identifier ({0})")]
    ShareParsingErrorEmptyShare(u8),

    #[error("Found invalid share identifier ({0})")]
    ShareParsingInvalidShareId(u8),

    #[error(
        "Threshold k must be bigger than or equal to 2. Got k = {0} for share identifier {1}."
    )]
    ShareParsingInvalidShareThreshold(u8, u8),

    #[error("Invalid parameters for the SS1 sharing scheme: r = {0}, s = {1}.")]
    InvalidSS1Parameters(usize, usize),

    #[error("Parameters k and n must be greater than zero.")]
    InvalidSplitParametersZero(u8, u8),

    #[cfg(feature = "dss")]
    #[error("Share mismatch during verification of secret recovery.")]
    MismatchingShares(ss1::Share, ss1::Share),

    #[error("Cannot generate random numbers.")]
    CannotGenerateRandomNumbers,

    #[error("This share number ({0}) has already been used by a previous share.")]
    DuplicateShareId(u8),

    #[error("The share identifier {0} had secret length {1}, while the secret length {3} was found for share identifier(s): {ids}.", ids = no_more_than_five(.2))]
    InconsistentSecretLengths(u8, usize, Vec<u8>, usize),

    #[error("The shares are inconsistent")]
    InconsistentShares,

    #[error("The share identifier {0} had k = {1}, while k = {3} was found for share identifier(s): {ids}.", ids = no_more_than_five(.2))]
    InconsistentThresholds(u8, u8, Vec<u8>, u8),

    #[error(transparent)]
    Io(#[from] std::io::Error),

    #[error(transparent)]
    IntegerParsingError(#[from] std::num::ParseIntError),
}

/// Result type alias for rusty_secrets operations.
pub type Result<T> = std::result::Result<T, Error>;

/// Takes a `Vec<T>` and formats it like the normal `fmt::Debug` implementation, unless it has more
/// than five elements, in which case the rest are replaced by ellipsis.
fn no_more_than_five<T: fmt::Debug + fmt::Display>(vec: &Vec<T>) -> String {
    let len = vec.len();
    if len > 5 {
        let mut string = String::from("[");
        for item in vec.iter().take(5) {
            string += &format!("{}, ", item);
        }
        string.push_str("...]");
        string
    } else {
        format!("{:?}", vec)
    }
}
