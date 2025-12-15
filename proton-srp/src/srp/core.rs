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
//! |`K = (B - k*g^x)^(a+u*x)`|                   | `K = (Av^u) ^ b`                |
//! |`cp = H(A ‖ B ‖ K)`      |— `client_proof` —>|  verify `client_proof`          |
//! | verify `server_proof`   |<— `server_proof` —| `sp = H(A ‖ cp ‖ K)`            |
//!```
//!
//! - The client will abort if it receives B == 0 (mod N) or u == 0
//! - The server will abort if it detects A == 0 (mod N)
//! - The client must show its proof of K first. If the server detects that this
//!   proof is incorrect it must abort without showing its own proof of K

use crypto_bigint::modular::runtime_mod::{DynResidue, DynResidueParams};
use crypto_bigint::subtle::ConstantTimeEq;
use crypto_bigint::{Encoding, Integer, NonZero, RandomMod, Zero, U2048};
use rand::{CryptoRng, RngCore};
use zeroize::Zeroizing;

use crate::pmhash::expand_hash;
use crate::{srp_password_hash, SrpHashVersion};

use super::{SRPError, SRPProof, SRPVerifier};

#[cfg(test)]
pub(crate) const TEST_CLIENT_SECRET_LEN: usize = SRP_LEN_BYTES;

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
    pub(crate) g: BigUint,

    /// Group modulus N
    pub(crate) n: NonZero<BigUint>,

    /// Group modulus minus one N -1.
    pub(crate) n_minus_one: NonZero<BigUint>,

    /// The hashed password x.
    pub(crate) hashed_pass: BigUint,

    /// The public ephemeral server value B.
    pub(crate) b_pub: BigUint,

    // Allow to override the client ephemeral secret for tests.
    #[cfg(test)]
    pub(crate) override_client_secret: Option<[u8; TEST_CLIENT_SECRET_LEN]>,
}

impl SRPAuthData {
    pub(crate) fn new(
        version: SrpHashVersion,                // protocol version
        username: Option<&str>,                 // username for version 0, 1, and 2
        modulus: &[u8; SRP_LEN_BYTES],          // N
        salt: &[u8; SALT_LEN_BYTES],            // s
        server_ephemeral: &[u8; SRP_LEN_BYTES], // B
        password: &str,                         // p
    ) -> Result<SRPAuthData, SRPError> {
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
        if b_pub.rem(&n).is_zero().into() {
            return Err(SRPError::InvalidServerEphemeral);
        }

        // hashed_pass x = H(H_pw(password || s) || N)
        let hashed_pass = BigUint::from_le_slice(
            srp_password_hash(version, username, password, salt, modulus)?.as_bytes(),
        );

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

    pub(crate) fn generate_client_proof<R>(&self, rng: &mut R) -> Result<SRPProof, SRPError>
    where
        R: CryptoRng + RngCore,
    {
        let g = &self.g;
        let n = &self.n;
        let n_minus_one = self.n_minus_one;
        let b_pub = &self.b_pub;

        // k = H(g || N)
        // The multiplier k must be non zero
        let Some(k) = NonZero::new(hash_two(g, n).rem(n)).into_option() else {
            return Err(SRPError::InvalidMultiplier);
        };

        let modulus_param = DynResidueParams::new(n);
        let g_res = DynResidue::new(g, modulus_param);

        let mut rounds = 0;
        let (client_secret, a_pub, u) = loop {
            if rounds >= MAX_RETRIES {
                return Err(SRPError::InvalidScramblingParameter);
            }
            // Client secret a
            let client_secret = self.generate_client_secret(rng)?;

            // Compute public client ephemeral A = g^a
            let a_pub = g_res.pow(&client_secret).retrieve();

            // Compute scrambling parameter u = H(A || B)
            let u = hash_two(&a_pub, b_pub);

            // The scrambling parameter u is not allowed to be 0
            if u.rem(&n_minus_one).is_zero().into() {
                // highly unlikely
                rounds += 1;
                continue;
            }
            break (client_secret, a_pub, u);
        };

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
    fn generate_client_secret<R>(&self, rng: &mut R) -> Result<BigUint, SRPError>
    where
        R: CryptoRng + RngCore,
    {
        #[cfg(test)]
        {
            if let Some(client_item) = &self.override_client_secret {
                let mut extended = [0_u8; SRP_LEN_BYTES];
                extended[..TEST_CLIENT_SECRET_LEN].copy_from_slice(client_item);
                return Ok(BigUint::from_le_slice(&extended));
            }
        }
        generate_ephemeral_secret(self.n_minus_one, rng)
    }
}

fn extract_and_check_modulus(
    modulus: &[u8; SRP_LEN_BYTES],
) -> Result<(NonZero<BigUint>, NonZero<BigUint>), SRPError> {
    let n_unchecked = BigUint::from_le_slice(modulus);
    let Some(n) = NonZero::new(n_unchecked).into_option() else {
        return Err(SRPError::InvalidModulus("modulus is zero"));
    };
    if n.is_even().into() {
        return Err(SRPError::InvalidModulus("modulus is even"));
    }
    if !(n.bit(0).into() && n.bit(1).into() && !bool::from(n.bit(2))) {
        // By quadratic reciprocity, 2 is a square mod N if and only if
        // N is 1 or 7 mod 8. We want the generator, 2, to generate the
        // whole group, not just the prime-order subgroup, so it should
        // *not* be a square. In addition, since N should be prime, it
        // must not be even, and since (N-1)/2 should be prime, N must
        // not be 1 mod 4. This leaves 3 mod 8 as the only option.
        return Err(SRPError::InvalidModulus("modulus did not pass bit check"));
    }
    // We have to unwrap here due to CtOption not exposing the inner value.
    let Some(n_minus_one) = NonZero::new(n.sub_mod(&BigUint::ONE, &n)).into_option() else {
        return Err(SRPError::InvalidModulus("modulus is invalid"));
    };
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

/// Generate an ephemeral secret.
fn generate_ephemeral_secret<R>(
    modulus_minus_one: NonZero<BigUint>,
    rng: &mut R,
) -> Result<BigUint, SRPError>
where
    R: CryptoRng + RngCore,
{
    for _ in 0..MAX_RETRIES {
        let possible_client_item = BigUint::random_mod(rng, &modulus_minus_one);
        if possible_client_item > BigUint::ONE {
            return Ok(possible_client_item);
        }
    }
    Err(SRPError::CannotFindClientSecret)
}

/// Generates a random srp salt.
pub(crate) fn generate_random_salt<R>(rng: &mut R) -> Vec<u8>
where
    R: CryptoRng + RngCore,
{
    let mut salt_bytes: Vec<u8> = vec![0; SALT_LEN_BYTES];
    rng.fill_bytes(&mut salt_bytes);
    salt_bytes
}

/// Generates an srp verifier.
pub(crate) fn generate_srp_verifier(
    version: SrpHashVersion,
    username: Option<&str>,
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
        srp_password_hash(version, username, password, salt_bytes, modulus_bytes)?.as_bytes(),
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

#[derive(Debug)]
pub struct ServerInteraction {
    /// Generator g.
    pub(crate) g: BigUint,

    /// Group modulus N
    pub(crate) n: NonZero<BigUint>,

    /// Group modulus N - 1
    pub(crate) n_minus_one: NonZero<BigUint>,

    /// Client verifier
    pub(crate) v: BigUint,

    /// The sever ephemeral secret b
    pub(crate) b: BigUint,

    /// The multiplier k.
    pub(crate) k: NonZero<BigUint>,

    /// The sever ephemeral B.
    pub(crate) server_ephemeral: Option<BigUint>,

    /// The shared session key K.
    pub(crate) shared_session: Option<BigUint>,
}

impl ServerInteraction {
    pub(crate) fn new<R>(
        modulus: &[u8; SRP_LEN_BYTES],  // N
        verifier: &[u8; SRP_LEN_BYTES], // v
        rng: &mut R,
    ) -> Result<Self, SRPError>
    where
        R: CryptoRng + RngCore,
    {
        // Generator g is hardcoded to 2
        let g = HARDCODED_GENERATOR;
        // Group modulus N
        let (n, n_minus_one) = extract_and_check_modulus(modulus)?;
        // k
        let Some(k) = NonZero::new(hash_two(&g, &n).rem(&n)).into_option() else {
            return Err(SRPError::InvalidMultiplier);
        };
        // b
        let server_secret = generate_ephemeral_secret(n_minus_one, rng)?;
        // v
        let v = BigUint::from_le_slice(verifier);

        Ok(Self {
            g,
            n,
            n_minus_one,
            v,
            b: server_secret,
            k,
            server_ephemeral: None,
            shared_session: None,
        })
    }

    pub(crate) fn restore(
        modulus: &[u8; SRP_LEN_BYTES],                  // N
        verifier: &[u8; SRP_LEN_BYTES],                 // v
        server_ephemeral_secret: &[u8; SRP_LEN_BYTES],  // b
        server_ephemeral: Option<&[u8; SRP_LEN_BYTES]>, // B
    ) -> Result<Self, SRPError> {
        // Generator g is hardcoded to 2
        let g = HARDCODED_GENERATOR;
        // Group modulus N
        let (n, n_minus_one) = extract_and_check_modulus(modulus)?;
        // k
        let Some(k) = NonZero::new(hash_two(&g, &n).rem(&n)).into_option() else {
            return Err(SRPError::InvalidMultiplier);
        };

        // b
        let server_secret = BigUint::from_le_slice(server_ephemeral_secret);

        // v
        let v = BigUint::from_le_slice(verifier);

        let mut interaction = Self {
            g,
            n,
            n_minus_one,
            v,
            b: server_secret,
            k,
            server_ephemeral: None,
            shared_session: None,
        };
        interaction.server_ephemeral = server_ephemeral.map(|data| BigUint::from_le_slice(data));
        Ok(interaction)
    }

    pub(crate) fn generate_challenge(&mut self) -> [u8; SRP_LEN_BYTES] {
        let params = DynResidueParams::new(&self.n);

        let g_residue = DynResidue::new(&self.g, params);
        let k_residue = DynResidue::new(&self.k, params);
        let v_residue = DynResidue::new(&self.v, params);

        // g^b
        let ephemeral_part = g_residue.pow(&self.b);

        // B = k*v + g^b
        let b_pub = ephemeral_part.add(&k_residue.mul(&v_residue)).retrieve();
        let server_ephemeral_encoded = b_pub.to_le_bytes();
        self.server_ephemeral = Some(b_pub);

        server_ephemeral_encoded
    }

    pub(crate) fn verify_proof(
        &mut self,
        client_ephemeral: &[u8; SRP_LEN_BYTES],
        client_proof: &[u8; SRP_LEN_BYTES],
    ) -> Result<[u8; SRP_LEN_BYTES], SRPError> {
        // B
        let Some(server_ephemeral) = &self.server_ephemeral else {
            return Err(SRPError::InvalidServerEphemeral);
        };

        // A
        let Some(client_ephemeral_num) =
            NonZero::new(BigUint::from_le_slice(client_ephemeral).rem(&self.n)).into_option()
        else {
            return Err(SRPError::InvalidClientEphemeral);
        };

        // u
        let Some(u) =
            NonZero::new(hash_two(&client_ephemeral_num, server_ephemeral).rem(&self.n_minus_one))
                .into_option()
        else {
            return Err(SRPError::InvalidScramblingParameter);
        };

        let params = DynResidueParams::new(&self.n);
        // v
        let v_residue = DynResidue::new(&self.v, params);
        // A
        let client_ephemeral_residue = DynResidue::new(&client_ephemeral_num, params);

        // K = (Av^u) ^ b
        let shared_session = v_residue
            .pow(&u)
            .mul(&client_ephemeral_residue)
            .pow(&self.b)
            .retrieve();

        // verify `client_proof`
        let expected_client_proof =
            compute_client_proof(&client_ephemeral_num, server_ephemeral, &shared_session);

        if expected_client_proof.ct_ne(client_proof).into() {
            return Err(SRPError::InvalidClientProof);
        }

        // sp = H(A ‖ cp ‖ K)
        let server_proof =
            compute_server_proof(&client_ephemeral_num, client_proof, &shared_session);

        self.shared_session = Some(shared_session);

        Ok(server_proof)
    }

    pub(crate) fn server_ephemeral(&self) -> Option<[u8; SRP_LEN_BYTES]> {
        self.server_ephemeral
            .map(|ephemeral| ephemeral.to_le_bytes())
    }

    pub(crate) fn server_ephemeral_secret(&self) -> Zeroizing<[u8; SRP_LEN_BYTES]> {
        Zeroizing::new(self.b.to_le_bytes())
    }
}
