//! Implements Proton's core client-side SRP protocol
//!
//! This is mostly as described in <https://eprint.iacr.org/2023/1457.pdf>, Fig. 2.
//! Any deviations will be made clear as and when they appear.
//!
//! ```ignore
//! I    An identifier for the user logging in to Proton's services.  This could be the customers username or email address
//! N    A large safe prime (N = 2q+1, where q is prime)
//!      All arithmetic is done modulo N.
//! g    A generator modulo N
//! k    Multiplier parameter
//! s    Salt
//! H()  One-way hash function
//! H_pw() A one-way password hashing function.  This is used at Proton because it allowed for migration to SRP without rehashing the already hashed user passwords.  At Proton, we use bcrypt for H_pw()
//! ^    (Modular) Exponentiation
//! ||   Concatenation
//! u    Random scrambling parameter
//! a,b  Secret ephemeral values client, server
//! A,B  Public ephemeral values client, server
//! x    Hashed password (derived from p and s)
//! v    Is the password verifier g^x stored by the server
//! p    Password
//! cp   A client proof supplied by the client to prove their possession of the shared key established by SRP to the server.
//! sp   A server proof supplied by the server to prove their possession of the shared key established by SRP to the client.
//!
//! |       Client            |   Data transfer   |      Server                     |
//! |-------------------------|-------------------|---------------------------------|
//! |`A = g^a`                | — `A`, `I` —>     | (lookup `s`, `v` for given `I`) |
//! |`k = H(g || N)`          |                   | `k = H(g || N)`                 |
//! |`x = H_pw(p, s)`         | <— `B`, `s` —     | `B = k*v + g^b`                 |
//! |`u = H(A ‖ B)`           |                   | `u = H(A ‖ B)`                  |
//! |`t = (B - k*g^x)^(a+u*x)`|                   | `t = (Av^u) ^ b`                |
//! |`K = H(t)`               |                   | `K = H(t)`                      |
//! |`cp = H(A ‖ B ‖ K)`      |— `client_proof` —>|  verify `client_proof`)         |
//! | verify `server_proof`   |<— `server_proof` —| `sp = H(A ‖ cp ‖ K)`            |
//!```
//!
//! - The client will abort if it receives B == 0 (mod N) or u == 0
//! - The server will abort if it detects A == 0 (mod N)
//! - The client must show its proof of K first. If the server detects that this
//!   proof is incorrect it must abort without showing its own proof of K

use crypto_bigint::modular::runtime_mod::{DynResidue, DynResidueParams};
use crypto_bigint::{Encoding, Integer, NonZero, RandomMod, U2048};
use rand::RngCore;
use zeroize::Zeroizing;

use crate::pmhash::expand_hash;
use crate::{srp_password_hash, MAX_SUPPORTED_VERSION, MIN_SUPPORTED_VERSION};

use super::{SRPError, SRPProof, SRPVerifier};

#[cfg(test)]
pub(super) const TEST_CLIENT_SECRET_LEN: usize = SRP_LEN_BYTES;

/// Internal constant which indicates the maximal number of retries
/// when creating a client ephemeral secret.
const MAX_RETRIES: i32 = 5;

/// The byte length of an encoded SRP element in the group.
pub const SRP_LEN_BYTES: usize = 256;

/// The byte length of a salt.
pub const SALT_LEN_BYTES: usize = 10;

/// Proton uses a hard coded generator for each provided group.
const HARDCODED_GENERATOR: BigUint = BigUint::from_u32(2);

type BigUint = U2048;

/// SRP client authentication data containing the group information,
/// the server reply, and the hashed password.
#[derive(Debug)]
pub struct SRPAuthData {
    /// Generator g.
    pub(super) g: BigUint,

    /// Group modulus N
    pub(super) n: NonZero<BigUint>,

    /// Group modulus minus one N -1.
    pub(super) n_minus_one: NonZero<BigUint>,

    /// The hashed password x.
    pub(super) hashed_pass: BigUint,

    /// The public ephemeral server value B.
    pub(super) b_pub: BigUint,

    // Allow to override the client ephemeral secret for tests.
    #[cfg(test)]
    pub(super) override_client_secret: Option<[u8; TEST_CLIENT_SECRET_LEN]>,
}

impl SRPAuthData {
    pub(super) fn new(
        version: u8,                            // protocol version
        modulus: &[u8; SRP_LEN_BYTES],          // N
        salt: &[u8; SALT_LEN_BYTES],            // s
        server_ephemeral: &[u8; SRP_LEN_BYTES], // B
        password: &str,                         // p
    ) -> Result<SRPAuthData, SRPError> {
        if version < MIN_SUPPORTED_VERSION || version > MAX_SUPPORTED_VERSION {
            return Err(SRPError::UnsupportedVersion);
        }
        // Generator g is hardcoded to 2
        let g = HARDCODED_GENERATOR;
        // Group modulus N
        let (n, n_minus_one) = extract_and_check_modulus(modulus)?;
        let params = DynResidueParams::new(&n);
        let g_residue = DynResidue::new(&g, params);
        // Validate modulus N
        // Check that 2^(N-1) % N == 1, N - 1 should be the order
        if g_residue.pow(&n_minus_one).retrieve() != BigUint::ONE {
            return Err(SRPError::InvalidModulus(
                "modulus minus one is not the order of the field",
            ));
        }

        // Validate server_ephemeral Bs
        // Server public ephemeral should not be 0 i.e., B % n != 0
        let b_pub = BigUint::from_le_slice(server_ephemeral);
        if b_pub.rem(&n) == BigUint::ZERO {
            return Err(SRPError::InvalidServerEphemeral);
        }

        // hashed_pass x = H(H_pw(password || s) || N)
        let hashed_pass =
            BigUint::from_le_slice(srp_password_hash(version, password, salt, modulus)?.as_bytes());

        Ok(SRPAuthData {
            g,
            n,
            n_minus_one,
            hashed_pass,
            b_pub,
            #[cfg(test)]
            override_client_secret: None,
        })
    }

    pub(super) fn generate_client_proof(&self) -> Result<SRPProof, SRPError> {
        let g = &self.g;
        let n = &self.n;
        let n_minus_one = self.n_minus_one;
        let b_pub = &self.b_pub;

        // k = H(g || N)
        let k = hash_two(g, n);
        let k_reduced = k.rem(n);
        // Check that the multiplier k is an element of the group
        if k_reduced < BigUint::ONE || &k_reduced >= n {
            return Err(SRPError::InvalidMultiplier);
        }

        // This allows to override client_item in test suites
        let client_secret = self.generate_client_secret()?;

        let modulus_param = DynResidueParams::new(n);
        let g_res = DynResidue::new(g, modulus_param);

        // Compute public client ephemeral A = g^a
        let a_pub = g_res.pow(&client_secret).retrieve();

        // Compute scrambling parameter u = H(A || B)
        let u = hash_two(&a_pub, b_pub);

        // The scrambling parameter u is not allowed to be 0
        if u.rem(n) == BigUint::ZERO {
            return Err(SRPError::InvalidScramblingParameter);
        }

        let k_residue = DynResidue::new(&k, modulus_param);

        // x = hashed_pass = H(H_pw(password, (s || proton)) || N)
        // base = B - kg^x
        let b_pub_residue = DynResidue::new(b_pub, modulus_param);
        let base = b_pub_residue.sub(&g_res.pow(&self.hashed_pass).mul(&k_residue));

        // exponent = (a + ux)
        let (ux, _) = BigUint::const_rem_wide(self.hashed_pass.mul_wide(&u), &n_minus_one);
        let exponent = client_secret.add_mod(&ux, &n_minus_one);

        // K = (B - kg^x) ^ (a + ux)
        let shared_session = base.pow(&exponent).retrieve();

        // client_proof = H (A || B || K)
        let client_proof = compute_client_proof(&a_pub, b_pub, &shared_session);

        // server_proof = H(A || client_proof || K)
        let server_proof = compute_server_proof(&a_pub, &client_proof, &shared_session);

        Ok(SRPProof {
            client_ephemeral: a_pub.to_le_bytes(),
            client_proof,
            expected_server_proof: server_proof,
        })
    }

    // Helper function to generate or retrieve the client secret
    fn generate_client_secret(&self) -> Result<BigUint, SRPError> {
        #[cfg(test)]
        {
            if let Some(client_item) = &self.override_client_secret {
                let mut extended = [0_u8; SRP_LEN_BYTES];
                extended[..TEST_CLIENT_SECRET_LEN].copy_from_slice(client_item);
                return Ok(BigUint::from_le_slice(&extended));
            }
        }
        generate_client_ephemeral_secret(self.n_minus_one)
    }
}

fn extract_and_check_modulus(
    modulus: &[u8; SRP_LEN_BYTES],
) -> Result<(NonZero<BigUint>, NonZero<BigUint>), SRPError> {
    let n_unchecked = BigUint::from_le_slice(modulus);
    if n_unchecked <= BigUint::ONE || n_unchecked.is_even().into() {
        return Err(SRPError::InvalidModulus("modulus is even or zero"));
    }
    if !(n_unchecked.bit(0).into() && n_unchecked.bit(1).into() && !bool::from(n_unchecked.bit(2)))
    {
        // By quadratic reciprocity, 2 is a square mod N if and only if
        // N is 1 or 7 mod 8. We want the generator, 2, to generate the
        // whole group, not just the prime-order subgroup, so it should
        // *not* be a square. In addition, since N should be prime, it
        // must not be even, and since (N-1)/2 should be prime, N must
        // not be 1 mod 4. This leaves 3 mod 8 as the only option.
        return Err(SRPError::InvalidModulus("modulus did not pass bit check"));
    }
    // We have to unwrap here due to CtOption not exposing the inner value.
    // We checked that they are non-zero above, so the or case should never happen.
    let n = NonZero::new(n_unchecked).unwrap_or(NonZero::MAX);
    let n_minus_one = NonZero::new(n.sub_mod(&BigUint::ONE, &n)).unwrap_or(NonZero::MAX);
    Ok((n, n_minus_one))
}

fn hash_two(first: &BigUint, second: &BigUint) -> BigUint {
    let mut data_to_hash = [0_u8; 2 * SRP_LEN_BYTES];
    data_to_hash[..SRP_LEN_BYTES].copy_from_slice(&first.to_le_bytes());
    data_to_hash[SRP_LEN_BYTES..].copy_from_slice(&second.to_le_bytes());
    BigUint::from_le_slice(expand_hash(data_to_hash.as_slice()).as_slice())
}

fn compute_client_proof(a_pub: &BigUint, b_pub: &BigUint, shared_session: &BigUint) -> [u8; 256] {
    // client_proof = H (A || B || K)
    let mut data_to_hash = Zeroizing::new([0_u8; 3 * SRP_LEN_BYTES]);
    data_to_hash[..SRP_LEN_BYTES].copy_from_slice(&a_pub.to_le_bytes());
    data_to_hash[SRP_LEN_BYTES..(2 * SRP_LEN_BYTES)].copy_from_slice(&b_pub.to_le_bytes());
    data_to_hash[(2 * SRP_LEN_BYTES)..].copy_from_slice(&shared_session.to_le_bytes());
    *expand_hash(data_to_hash.as_slice())
}

fn compute_server_proof(
    a_pub: &BigUint,
    client_proof: &[u8; 256],
    shared_session: &BigUint,
) -> [u8; 256] {
    // server_proof = H(A || client_proof || K)
    let mut data_to_hash = Zeroizing::new([0_u8; 3 * SRP_LEN_BYTES]);
    data_to_hash[..SRP_LEN_BYTES].copy_from_slice(&a_pub.to_le_bytes());
    data_to_hash[SRP_LEN_BYTES..(2 * SRP_LEN_BYTES)].copy_from_slice(client_proof);
    data_to_hash[(2 * SRP_LEN_BYTES)..].copy_from_slice(&shared_session.to_le_bytes());
    *expand_hash(data_to_hash.as_slice())
}

/// Generate a client ephemeral secret.
fn generate_client_ephemeral_secret(
    modulus_minus_one: NonZero<BigUint>,
) -> Result<BigUint, SRPError> {
    let mut rng = rand::thread_rng();
    for _ in 0..MAX_RETRIES {
        let possible_client_item = BigUint::random_mod(&mut rng, &modulus_minus_one);
        if possible_client_item > BigUint::ONE {
            return Ok(possible_client_item);
        }
    }
    Err(SRPError::CannotFindClientSecret)
}

/// Generates a random srp salt using a [`rand::rngs::ThreadRng`] as `CSPRNG`.
pub(super) fn generate_random_salt() -> Vec<u8> {
    let mut salt_bytes: Vec<u8> = vec![0; SALT_LEN_BYTES];
    let mut rng = rand::thread_rng();
    rng.fill_bytes(&mut salt_bytes);
    salt_bytes
}

/// Generates an srp verifier.
pub(super) fn generate_srp_verifier(
    version: u8,
    password: &str,
    salt_bytes: &[u8; SALT_LEN_BYTES],
    modulus_bytes: &[u8; SRP_LEN_BYTES],
) -> Result<SRPVerifier, SRPError> {
    // Generator g is hardcoded to 2
    let g = HARDCODED_GENERATOR;
    // Group modulus N
    let (n, _) = extract_and_check_modulus(modulus_bytes)?;
    let modulus_param = DynResidueParams::new(&n);
    let g_res = DynResidue::new(&g, modulus_param);

    // hashed_pass x = H(H_pw(password || s) || N)
    let hashed_pass = BigUint::from_le_slice(
        srp_password_hash(version, password, salt_bytes, modulus_bytes)?.as_bytes(),
    );
    // verifier = g^x
    let verifier = g_res.pow(&hashed_pass).retrieve();
    let verifier_bytes: [u8; SRP_LEN_BYTES] = verifier.to_le_bytes();

    Ok(SRPVerifier {
        version,
        salt: salt_bytes.to_owned(),
        verifier: verifier_bytes,
    })
}
