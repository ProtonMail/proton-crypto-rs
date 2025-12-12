//! This module implements logic for password hashing within Proton.
use sha2::{Digest, Sha512};

use crate::{
    srp::{SALT_LEN_BYTES, SRP_LEN_BYTES},
    MailboxHashError, SRPError, SrpVersion,
};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use base64::{prelude::BASE64_STANDARD as BASE_64, Engine as _};

/// The byte length of the expanded hash.
pub const EXPAND_HASH_LEN: usize = 256;

/// The byte length of part in the expanded hash.
pub const EXPAND_HASH_PART_LEN: usize = 64;

/// The proton suffix in the password hash.
pub const PROTON_SALT_SUFFIX: &[u8] = b"proton";

/// The salt length in bcrypt.
pub const SALT_BCRYPT_LEN: usize = 16;

/// The prefix length of the bcrypt hash.
///
/// i.e., `$2y$10[22 character salt]`
const BCRYPT_PREFIX_LEN: usize = 29;

/// Represent proton password hash of a passphrase.
///
/// Is automatically zeroed on drop.
/// Has the form `$2y$10[22 character salt][31 character hash]`.
#[derive(Clone, PartialEq, Eq, Zeroize, ZeroizeOnDrop)]
pub struct MailboxHashedPassword(Vec<u8>);

#[allow(clippy::must_use_candidate)]
impl MailboxHashedPassword {
    /// Returns a slice of the bcrypt prefix and hashed password in bytes.
    ///
    /// The whole hash has the form `$2y$10[22 character salt][31 character hash]`.
    pub fn as_bytes(&self) -> &[u8] {
        self.0.as_slice()
    }

    /// Returns the bcrypt hash prefix, formatted as `$2y$10[22-character salt]`.
    ///
    /// This prefix includes the bcrypt version (`$2y$`), the cost factor (`10`),
    /// and the 22-character salt used during hashing.
    pub fn prefix(&self) -> &[u8] {
        &self.0[..BCRYPT_PREFIX_LEN]
    }

    /// Returns the hashed password portion of the bcrypt hash, which is a 31-character string.
    ///
    /// This part follows the bcrypt prefix ([`Self::prefix`])
    /// and represents the hashed result of the user's password.
    pub fn hashed_password(&self) -> &[u8] {
        &self.0[BCRYPT_PREFIX_LEN..]
    }

    /// Returns the total length of the bcrypt prefix and hashed password in bytes.
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Returns whether the hashed password is empty.
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl AsRef<[u8]> for MailboxHashedPassword {
    fn as_ref(&self) -> &[u8] {
        self.as_bytes()
    }
}

/// Represents an expanded hashed password allocated on the heap.
///
/// Is automatically zeroed on drop.
#[derive(Clone, PartialEq, Eq, Zeroize, ZeroizeOnDrop)]
pub struct SRPHashedPassword(Box<[u8; EXPAND_HASH_LEN]>);

#[allow(clippy::must_use_candidate)]
impl SRPHashedPassword {
    /// Returns a slice of the hashed password in bytes.
    pub fn as_bytes(&self) -> &[u8] {
        self.0.as_slice()
    }

    /// Returns the length of the hashed password.
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Returns whether the hashed password is empty.
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl AsRef<[u8]> for SRPHashedPassword {
    fn as_ref(&self) -> &[u8] {
        self.as_bytes()
    }
}

/// Returns Sha512(data || 0) || Sha512(data || 1) || Sha512(data || 2) || Sha512(data || 3).
///
/// The return value is allocated on the heap to avoid copies if the output hash is sensitive and should be zeroed.
pub(crate) fn expand_hash(data: &[u8]) -> Box<[u8; EXPAND_HASH_LEN]> {
    let mut hash = Box::new([0_u8; EXPAND_HASH_LEN]);
    for (part_id, chunk) in hash.chunks_mut(EXPAND_HASH_PART_LEN).enumerate() {
        let mut hasher = Sha512::new_with_prefix(data);
        hasher.update([u8::try_from(part_id).unwrap_or_default()]);
        chunk.copy_from_slice(&hasher.finalize());
    }
    hash
}

/// Produces a Proton mailbox password hash.
///
/// # Parameters
///
/// * `password`         - The user password.
/// * `salt       `      - The 16 bytes salt for hashing the password.
///
/// # Errors
///
/// Returns `Err` if the `version` is not supported, `modulus` is invalid, or hashing fails.
pub fn mailbox_password_hash(
    password: &str,
    salt: &[u8],
) -> Result<MailboxHashedPassword, MailboxHashError> {
    let input_salt: [u8; SALT_BCRYPT_LEN] = salt
        .try_into()
        .map_err(|_err| MailboxHashError::InvalidSalt)?;
    bcrypt_hash(password, input_salt).map_err(MailboxHashError::BcryptError)
}

/// Hashes the password with Proton's SRP hash with the given version.
///
/// # Parameters
///
/// * `version`          - The SRP version.
/// * `username`         - The user name (Only used for versions 0, 1, and 2)
/// * `password`         - The user password.
/// * `salt       `      - The SRP salt for hashing the password.
/// * `modulus`          - The SRP modulus. (Only used for versions 3 and 4)
///
/// # Errors
///
/// Will return `Err` if the `version` is not supported, `modulus` is invalid, or hashing fails.
pub fn srp_password_hash(
    version: SrpVersion,
    username: Option<&str>,
    password: &str,
    salt: &[u8],
    modulus: &[u8],
) -> Result<SRPHashedPassword, SRPError> {
    let username = version.unpack_username(username)?;
    let modulus_bytes: &[u8; SRP_LEN_BYTES] = modulus
        .try_into()
        .map_err(|_err| SRPError::InvalidModulus("invalid modulus length"))?;
    match version {
        SrpVersion::V0 => srp_password_hash_version_zero(password, username, modulus_bytes),
        SrpVersion::V1 => srp_password_hash_version_one(password, username, modulus_bytes),
        SrpVersion::V2 => srp_password_hash_version_two(password, username, modulus_bytes),
        SrpVersion::V3 | SrpVersion::V4 => srp_password_hash_version_three_and_four(
            password,
            salt.try_into()
                .map_err(|_err| SRPError::InvalidSalt("wrong size"))?,
            modulus_bytes,
        ),
    }
}

fn bcrypt_hash(
    password: &str,
    salt: [u8; SALT_BCRYPT_LEN],
) -> Result<MailboxHashedPassword, bcrypt::BcryptError> {
    // Computes: H_pw(password, salt)
    let hashed_password = bcrypt::hash_with_salt(password, 10, salt)?
        .format_for_version(bcrypt::Version::TwoY)
        .into_bytes();
    Ok(MailboxHashedPassword(hashed_password))
}

/// Hashes the password with Proton's SRP version 4 hash.
///
/// Computes: `H(H_pw(password, (s || proton)) || N)`
fn srp_password_hash_version_three_and_four(
    password: &str,
    salt: &[u8; SALT_LEN_BYTES],
    modulus: &[u8; SRP_LEN_BYTES],
) -> Result<SRPHashedPassword, SRPError> {
    let mut extended_salt = [0; SALT_BCRYPT_LEN];
    // Salt 10 bytes || Proton 6 bytes
    extended_salt[..SALT_LEN_BYTES].copy_from_slice(salt);
    extended_salt[SALT_LEN_BYTES..].copy_from_slice(PROTON_SALT_SUFFIX);

    let hashed_pass_bytes = bcrypt_hash(password, extended_salt).map_err(SRPError::BcryptError)?;
    let mut input = Zeroizing::new(Vec::with_capacity(hashed_pass_bytes.len() + modulus.len()));
    input.extend_from_slice(hashed_pass_bytes.as_bytes());
    input.extend_from_slice(modulus);
    Ok(SRPHashedPassword(expand_hash(input.as_slice())))
}

fn srp_password_hash_version_two(
    password: &str,
    username: &str,
    modulus: &[u8; SRP_LEN_BYTES],
) -> Result<SRPHashedPassword, SRPError> {
    srp_password_hash_version_one(password, &clean_user_name(username), modulus)
}

fn srp_password_hash_version_one(
    password: &str,
    username: &str,
    modulus: &[u8; SRP_LEN_BYTES],
) -> Result<SRPHashedPassword, SRPError> {
    let prehashed = md5::Md5::digest(username.to_lowercase().as_bytes());

    // Legacy mistake.
    let magic_salt_decoding: [u8; SALT_BCRYPT_LEN] = bcrypt::BASE_64
        .decode(hex::encode(prehashed))?[..SALT_BCRYPT_LEN]
        .try_into()
        .map_err(|_| SRPError::PassordHashFailed("failed to decode salt"))?;

    let hashed_pass_bytes =
        bcrypt_hash(password, magic_salt_decoding).map_err(SRPError::BcryptError)?;
    let mut input = Zeroizing::new(Vec::with_capacity(hashed_pass_bytes.len() + modulus.len()));
    input.extend_from_slice(hashed_pass_bytes.as_bytes());
    input.extend_from_slice(modulus);
    Ok(SRPHashedPassword(expand_hash(input.as_slice())))
}

fn srp_password_hash_version_zero(
    password: &str,
    username: &str,
    modulus: &[u8; SRP_LEN_BYTES],
) -> Result<SRPHashedPassword, SRPError> {
    let username_lower = username.to_ascii_lowercase();
    let mut user_and_pass =
        Zeroizing::new(Vec::with_capacity(username_lower.len() + password.len()));
    user_and_pass.extend_from_slice(username_lower.as_bytes());
    user_and_pass.extend_from_slice(password.as_bytes());

    let prehashed = Zeroizing::new(Sha512::digest(&user_and_pass));
    let b64_hash = Zeroizing::new(BASE_64.encode(&prehashed));

    srp_password_hash_version_one(&b64_hash, username, modulus)
}

fn clean_user_name(user_name: &str) -> String {
    user_name
        .chars()
        .filter(|c| *c != '-' && *c != '.' && *c != '_')
        .flat_map(char::to_lowercase)
        .collect()
}
