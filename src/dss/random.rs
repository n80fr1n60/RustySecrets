use crate::errors::*;

/// Crate-internal secure random source. Not implementable by external code.
/// Mirrors ring's sealing pattern — only trusted implementations exist.
pub(crate) trait RandomSource: std::fmt::Debug {
    /// Fills `dest` with random bytes.
    fn fill(&self, dest: &mut [u8]) -> std::result::Result<(), ()>;
}

/// Production random source: delegates to ring's OS CSPRNG.
#[derive(Clone, Debug)]
pub(crate) struct SecureSystemRandom(ring::rand::SystemRandom);

impl SecureSystemRandom {
    /// Constructs a new `SecureSystemRandom`.
    pub(crate) fn new() -> Self {
        Self(ring::rand::SystemRandom::new())
    }
}

impl RandomSource for SecureSystemRandom {
    fn fill(&self, dest: &mut [u8]) -> std::result::Result<(), ()> {
        ring::rand::SecureRandom::fill(&self.0, dest).map_err(|_| ())
    }
}

/// We bound the message size at about 16MB to avoid overflow in `random_bytes_count`.
/// Moreover, given the current performances, it is almost unpractical to run
/// the sharing scheme on message larger than that.
pub(crate) const MAX_MESSAGE_SIZE: usize = usize::MAX / (u8::MAX - 1) as usize;
/// Minimum allowed message size in bytes
pub(crate) static MIN_MESSAGE_SIZE: usize = 1;

/// Returns the number of random bytes to read from the secure random number generator.
/// As defined in section 3.1 of the 'New Directions in Secret Sharing' paper.
pub(crate) fn random_bytes_count(threshold: u8, message_size: usize) -> usize {
    assert!(threshold >= MIN_THRESHOLD);
    assert!(message_size >= MIN_MESSAGE_SIZE);
    assert!(message_size <= MAX_MESSAGE_SIZE);

    (threshold as usize - 1) * message_size
}

/// Attempts to read `count` random bytes from the given secure random generator.
pub(crate) fn random_bytes(random: &dyn RandomSource, count: usize) -> Result<Vec<u8>> {
    if count == 0 {
        return Ok(Vec::new());
    }

    let mut rl = vec![0; count];
    random
        .fill(&mut rl)
        .map_err(|_| Error::CannotGenerateRandomNumbers)?;

    Ok(rl)
}

/// A deterministic random source for reproducibility mode and testing.
/// Fills the output slice with bytes from `src`.
/// The length of `src` must be larger than any slice that we attempt to fill.
#[derive(Debug)]
pub(crate) struct FixedRandom {
    src: Vec<u8>,
}

impl FixedRandom {
    /// Create a new fixed random generator.
    /// The length of `src` must be larger than any slice that we attempt to fill.
    pub(crate) fn new(src: Vec<u8>) -> Self {
        if src.is_empty() {
            panic!("The source slice of FixedRandom cannot be empty!");
        }
        FixedRandom { src }
    }
}

impl RandomSource for FixedRandom {
    fn fill(&self, dst: &mut [u8]) -> std::result::Result<(), ()> {
        if dst.len() > self.src.len() {
            return Err(());
        }

        let len = dst.len();
        dst.copy_from_slice(&self.src[0..len]);
        Ok(())
    }
}
