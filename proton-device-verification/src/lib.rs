//! Implements Proton's proof of work feature for device verification to make API abuse more work intensive.
//!
//! The proton API server can issue proof-of-work challenges to a client.
//! The client has to solve the challenge to be able to use the API again.
//! To solve the challenge the client has to invest computational resources.
//!
//! This module provides APIs to solve challenges received from the server.
//!

mod errors;
use std::time::Duration;

pub use errors::*;

pub mod pow;

pub const MAX_SOLVE_TIME_SECONDS: u64 = 10;

/// A device verification challenge containing the base64 encoded challenge of a certain type .
#[derive(Debug, PartialEq, Eq, Hash, Clone)]
pub enum DeviceChallenge {
    Ecdlp(String),
    Argon2(String),
}

impl DeviceChallenge {
    /// Solves the device verification challenge and
    /// returns the base64 encoded solution.
    ///
    /// The max duration is set to 10 seconds.
    ///
    /// # Errors
    ///
    /// Returns [`crate::ProofOfWorkError`] if the deadline is exceeded or computing the solution fails.
    pub fn solve(&self) -> Result<String, ProofOfWorkError> {
        self.solve_with_custom_deadline(Duration::from_secs(MAX_SOLVE_TIME_SECONDS))
    }

    /// Solves the device verification challenge and
    /// returns the base64 encoded solution.
    ///
    /// # Parameters
    ///
    /// * `max_duration` - The maximum duration of this function, i.e., deadline
    ///
    /// # Errors
    ///
    /// Returns [`crate::ProofOfWorkError`] if the deadline is exceeded or computing the solution fails.
    pub fn solve_with_custom_deadline(
        &self,
        max_duration: Duration,
    ) -> Result<String, ProofOfWorkError> {
        match self {
            DeviceChallenge::Ecdlp(challenge) => {
                pow::solve_ecdlp_challenge(challenge, max_duration)
            }
            DeviceChallenge::Argon2(challenge) => {
                pow::solve_argon2_challenge(challenge, max_duration)
            }
        }
    }
}
