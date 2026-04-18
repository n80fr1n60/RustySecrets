use crate::errors::*;
use crate::share::{IsShare, IsSignedShare};

// The order of validation that we think makes the most sense is the following:
// 1) Validate shares individually
// 2) Validate duplicate shares share num && data
// 2) Validate group consistency
// 3) Validate other properties, in no specific order

/// TODO: Doc
pub(crate) fn validate_signed_shares<S: IsSignedShare>(
    shares: &Vec<S>,
    verify_signatures: bool,
) -> Result<(u8, usize)> {
    let result = validate_shares(shares)?;

    if verify_signatures {
        S::verify_signatures(&shares)?;
    }

    Ok(result)
}

/// TODO: Doc
pub(crate) fn validate_shares<S: IsShare>(shares: &Vec<S>) -> Result<(u8, usize)> {
    if shares.is_empty() {
        return Err(Error::EmptyShares);
    }

    let shares_count = shares.len();

    let mut ids = Vec::with_capacity(shares_count);
    let mut threshold = 0;
    let mut slen = 0;

    for share in shares {
        let id = share.get_id();
        let threshold_ = share.get_threshold();
        let slen_ = share.get_data().len();

        if id < 1 {
            return Err(Error::ShareParsingInvalidShareId(id));
        } else if threshold_ < 2 {
            return Err(Error::ShareParsingInvalidShareThreshold(threshold, id));
        } else if slen_ < 1 {
            return Err(Error::ShareParsingErrorEmptyShare(id));
        }

        if ids.iter().any(|&x| x == id) {
            return Err(Error::DuplicateShareId(id));
        }

        if threshold == 0 {
            threshold = threshold_;
        } else if threshold_ != threshold {
            return Err(Error::InconsistentThresholds(
                id, threshold_, ids, threshold,
            ));
        }

        if slen == 0 {
            slen = slen_;
        } else if slen_ != slen {
            return Err(Error::InconsistentSecretLengths(id, slen_, ids, slen));
        }

        ids.push(id);
    }

    if shares_count < threshold as usize {
        return Err(Error::MissingShares(shares_count, threshold));
    }

    Ok((threshold, slen))
}

pub(crate) fn validate_share_count(threshold: u8, shares_count: u8) -> Result<(u8, u8)> {
    if threshold < MIN_THRESHOLD {
        return Err(Error::ThresholdTooSmall(threshold));
    }
    if shares_count > MAX_SHARES {
        return Err(Error::InvalidShareCountMax(shares_count, MAX_SHARES));
    }
    if shares_count < MIN_SHARES {
        return Err(Error::InvalidShareCountMin(shares_count, MIN_SHARES));
    }
    if threshold > shares_count {
        return Err(Error::ThresholdTooBig(threshold, shares_count));
    }

    Ok((threshold, shares_count))
}
