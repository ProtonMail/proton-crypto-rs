//! Provides functions to solve Proton's device verification challenges.

use argon2::{self, Argon2, ParamsBuilder};
use base64::{prelude::BASE64_STANDARD as BASE_64, Engine as _};
use curve25519_dalek::constants::X25519_BASEPOINT;
use curve25519_dalek::scalar::Scalar;
use hmac::{Hmac, Mac};
use sha2::Sha256;
use std::time::{Duration, Instant};

use crate::ProofOfWorkError;

const ECDLP_PRF_KEY_SIZE: usize = 32;
const ARGON2_PRF_KEY_SIZE: usize = 32;
const ARGON2_PARAMS_SIZE: usize = 16;

type HmacSha256 = Hmac<Sha256>;

/// Solves a Proton ECDLP proof-of-work client challenge from the server.
///
/// Returns the base64 encoded solution to this challenge if a solution is found.
///
/// # Parameters
///
/// * `b64_challenge`    - The base64 encoded challenge retrieved from the server.
/// * `max_duration`     - The maximum duration of this function, i.e., deadline
///
/// # Errors
///
/// Returns [`crate::ProofOfWorkError`] if the deadline is exceeded or computing the solution fails.
pub fn solve_ecdlp_challenge(
    b64_challenge: &str,
    max_duration: Duration,
) -> Result<String, ProofOfWorkError> {
    // Decode the challenge
    let challenge = BASE_64.decode(b64_challenge)?;
    if challenge.len() != 3 * ECDLP_PRF_KEY_SIZE {
        return Err(ProofOfWorkError::InvalidChallengeLength);
    }

    // Extract challenge parts for clarity
    let (prf_key_scalar, prf_key_challenge, challenge_solution) = (
        &challenge[..ECDLP_PRF_KEY_SIZE],
        &challenge[ECDLP_PRF_KEY_SIZE..2 * ECDLP_PRF_KEY_SIZE],
        &challenge[2 * ECDLP_PRF_KEY_SIZE..],
    );

    let mut challenge_index: u64 = 0;
    let start_time = Instant::now();

    loop {
        // Check if max duration has been exceeded
        if start_time.elapsed() > max_duration {
            return Err(ProofOfWorkError::DeadlineExceeded);
        }

        let scalar = ecdlp_prf_scalar(prf_key_scalar, challenge_index)?;
        let challenge_point = scalar * X25519_BASEPOINT;

        // Verify if the challenge is solved.
        let challenge_output = prf_challenge(prf_key_challenge, challenge_point.as_bytes())?;
        if challenge_output == challenge_solution {
            return Ok(construct_solution(
                challenge_index,
                challenge_point.as_bytes(),
            ));
        }

        challenge_index = challenge_index
            .checked_add(1)
            .ok_or(ProofOfWorkError::NoSolutionFound)?;
    }
}

/// Solves a Proton Argon2 proof-of-work client challenge from the server.
///
/// Returns the base64 encoded solution to this challenge if a solution is found.
///
/// # Parameters
///
/// * `b64_challenge`    - The base64 encoded challenge retrieved from the server.
/// * `max_duration`     - The maximum duration of this function, i.e., deadline
///
/// # Errors
///
/// Returns [`crate::ProofOfWorkError`] if the deadline is exceeded or computing the solution fails.
pub fn solve_argon2_challenge(
    b64_challenge: &str,
    max_duration: Duration,
) -> Result<String, ProofOfWorkError> {
    // Decode the challenge and validate
    let challenge = BASE_64.decode(b64_challenge)?;
    if challenge.len() != 4 * ARGON2_PRF_KEY_SIZE + ARGON2_PARAMS_SIZE {
        return Err(ProofOfWorkError::InvalidChallengeLength);
    }

    let (prf_keys, challenge_solution, argon2_param_bytes) = (
        &challenge[..3 * ARGON2_PRF_KEY_SIZE],
        &challenge[3 * ARGON2_PRF_KEY_SIZE..4 * ARGON2_PRF_KEY_SIZE],
        &challenge[4 * ARGON2_PRF_KEY_SIZE..],
    );

    // Extract salts and prf keys
    let (argon2_key_prf_key, argon2_salt, challenge_prf_key) = (
        &prf_keys[..ARGON2_PRF_KEY_SIZE],
        &prf_keys[ARGON2_PRF_KEY_SIZE..2 * ARGON2_PRF_KEY_SIZE],
        &prf_keys[2 * ARGON2_PRF_KEY_SIZE..],
    );

    let mut challenge_index: u64 = 0;
    let start_time = Instant::now();

    // Build argon2 handle based on the parameters in the challenge
    let (argon2_handle, mut argon2_output_buffer) = argon2_build_handle(argon2_param_bytes)?;

    // Solve the challenge
    loop {
        // Check if max duration has been exceeded
        if start_time.elapsed() > max_duration {
            return Err(ProofOfWorkError::DeadlineExceeded);
        }

        let challenge_index_bytes = challenge_index.to_le_bytes();

        // Compute the argon2 key
        let mut argon2_key_prf = HmacSha256::new_from_slice(argon2_key_prf_key)
            .map_err(|_| ProofOfWorkError::Unexpected)?;
        argon2_key_prf.update(&challenge_index_bytes);
        let argon2_key = argon2_key_prf.finalize().into_bytes();

        // Compute the argon2 hash
        argon2_handle
            .hash_password_into(&argon2_key, argon2_salt, &mut argon2_output_buffer)
            .map_err(|_| ProofOfWorkError::InvalidChallengeParams)?;

        // Compute the challenge hash and check if it is the final solution
        let challenge_output = prf_challenge(challenge_prf_key, &argon2_output_buffer)?;
        if challenge_output == challenge_solution {
            return Ok(construct_solution(challenge_index, &argon2_output_buffer));
        }

        challenge_index = challenge_index
            .checked_add(1)
            .ok_or(ProofOfWorkError::NoSolutionFound)?;
    }
}

fn ecdlp_prf_scalar(key: &[u8], index: u64) -> Result<Scalar, ProofOfWorkError> {
    let mut scalar_prf =
        HmacSha256::new_from_slice(key).map_err(|_| ProofOfWorkError::Unexpected)?;
    scalar_prf.update(&index.to_le_bytes());
    Ok(Scalar::from_bytes_mod_order(
        scalar_prf.finalize().into_bytes().into(),
    ))
}

fn prf_challenge(key: &[u8], solution_bytes: &[u8]) -> Result<Vec<u8>, ProofOfWorkError> {
    let mut challenge_prf =
        HmacSha256::new_from_slice(key).map_err(|_| ProofOfWorkError::Unexpected)?;
    challenge_prf.update(solution_bytes);
    Ok(challenge_prf.finalize().into_bytes().to_vec())
}

fn argon2_build_handle(argon2_params: &[u8]) -> Result<(Argon2, Box<[u8]>), ProofOfWorkError> {
    let (p_cost, output_len, m_cost, t_cost) = (
        u32::from_le_bytes(
            argon2_params[0..4]
                .try_into()
                .map_err(|_| ProofOfWorkError::Unexpected)?,
        ),
        u32::from_le_bytes(
            argon2_params[4..8]
                .try_into()
                .map_err(|_| ProofOfWorkError::Unexpected)?,
        ),
        u32::from_le_bytes(
            argon2_params[8..12]
                .try_into()
                .map_err(|_| ProofOfWorkError::Unexpected)?,
        ),
        u32::from_le_bytes(
            argon2_params[12..16]
                .try_into()
                .map_err(|_| ProofOfWorkError::Unexpected)?,
        ),
    );

    let output_size = usize::try_from(output_len).map_err(|_| ProofOfWorkError::Unexpected)?;
    let params = ParamsBuilder::new()
        .m_cost(m_cost)
        .t_cost(t_cost)
        .p_cost(p_cost)
        .output_len(output_size)
        .build()
        .map_err(|_| ProofOfWorkError::InvalidChallengeParams)?;

    let handle = Argon2::new(argon2::Algorithm::Argon2id, argon2::Version::V0x13, params);
    Ok((handle, vec![0; output_size].into_boxed_slice()))
}

fn construct_solution(challenge_index: u64, challenge_solution: &[u8]) -> String {
    let mut solution = Vec::with_capacity(8 + challenge_solution.len());
    solution.extend_from_slice(&challenge_index.to_le_bytes());
    solution.extend_from_slice(challenge_solution);
    BASE_64.encode(&solution)
}
