use proton_crypto::crypto::{KeyGeneratorAlgorithm, PGPProviderSync};
use proton_crypto::srp::SRPProvider;
use proton_crypto::{ProtonPGP, ProtonSRP};
use proton_crypto_account::keys::{
    AddressKeys, ArmoredPrivateKey, KeyFlag, KeyId, LocalAddressKey, LockedKey,
    UnlockedAddressKeys, UnlockedUserKeys, UserKeys,
};
use proton_crypto_account::salts::{KeySalt, Salt, Salts};

// Locked user key retrieved from the API (e.g. GET /core/v4/keys).
// In this example the key was encrypted with a salted password derived from the user's password.
const LOCKED_USER_KEY: &str = "-----BEGIN PGP PRIVATE KEY BLOCK-----

xYYEZie3jRYJKwYBBAHaRw8BAQdAAp+4PE1Sf5V95XrIY/P2dUNk1TOojoEG
LuuOzULTa1v+CQMINYn0u3DCV01gjT+Noe2HzLxwP2hieZC1aoGCxSrLn0fs
LeShqv2pCPZ+SdrjXB5s5Rq7OP5Kr/2gN+0KS0yLGdyirFZWe6m5T8j20UQ5
0M07bm90X2Zvcl9lbWFpbF91c2VAZG9tYWluLnRsZCA8bm90X2Zvcl9lbWFp
bF91c2VAZG9tYWluLnRsZD7CjAQQFgoAPgWCZie3jQQLCQcICZA4nKgbRZBl
GQMVCAoEFgACAQIZAQKbAwIeARYhBOZJEArPLqrMMxX8fzicqBtFkGUZAADk
/AD+LA6NW1K+Z3IT66/DEtjH0cmw6HNqxkBdT7kaL2o5pAMA/j9b4JCurWk/
62MBM4I9RwXzSo8lmgPiYwPp4d/xgEsMx4sEZie3jRIKKwYBBAGXVQEFAQEH
QHvLC7RWIDsorX5ZmYwjZbUhbXnEcO2sYt8OFaIh5KtHAwEIB/4JAwhKivkG
shycUGA6wZtPR2HqO6+jvvSlRau/g2eZnWqhnvB4iIYTcD+CPpcPnWrrNgTz
AU+kQ5sVrP6OiKKHIkUvHT5+MwelTbcpievGx2zGwngEGBYKACoFgmYnt40J
kDicqBtFkGUZApsMFiEE5kkQCs8uqswzFfx/OJyoG0WQZRkAAJ6BAQDv4nBl
Nnj0W7XiAjiwRmVrY/sdybelB6j01p7UrcVAxQEAtEmT2cSIScVdWH1j3H9l
0gGE7amH+cm6CjXOA7+Uwwc=
=RGJ0
-----END PGP PRIVATE KEY BLOCK-----
";

const USER_KEY_ID: &str =
    "aTdvCsWuv2V_YQQ5nLKsWPkHWMrlHfUxL9aTWakz6blhwI0q_j4MKnxO29xMQ4slCRvo3lFLE8ljb3kvMP2PQQ==";
// Base64-encoded key salt as returned by the API (GET /core/v4/keys/salts).
const USER_KEY_SALT: &str = "6bIzN4A8bOwmsiEuCPj74g==";
const USER_KEY_PASSWORD: &str = "password";

fn main() {
    let pgp_provider = ProtonPGP::new_sync();
    let srp_provider = ProtonSRP::new_sync();
    unlock_and_select_keys(&pgp_provider, &srp_provider);
}

#[allow(clippy::print_stdout)]
fn unlock_and_select_keys<PGP: PGPProviderSync, SRP: SRPProvider>(
    pgp_provider: &PGP,
    srp_provider: &SRP,
) {
    // --- Unlock user keys ---

    // User keys are locked with a salted password derived from the user's password.
    // The salt comes from the API (GET /core/v4/keys/salts).
    let user_key_id = KeyId::from(USER_KEY_ID);
    let salts = Salts::new(vec![Salt {
        id: user_key_id.clone(),
        key_salt: Some(KeySalt::from(USER_KEY_SALT.to_owned())),
    }]);

    // Derive the key secret from the user's password and the matching key salt.
    let key_secret = salts
        .salt_for_key(srp_provider, &user_key_id, USER_KEY_PASSWORD.as_bytes())
        .expect("key salt must be found");

    // Build the locked user keys as returned by the API (GET /core/v4/keys).
    let user_keys = UserKeys::new(vec![LockedKey {
        id: user_key_id,
        version: 3,
        private_key: ArmoredPrivateKey::from(LOCKED_USER_KEY),
        token: None,
        signature: None,
        activation: None,
        primary: true,
        active: true,
        flags: None,
        recovery_secret: None,
        recovery_secret_signature: None,
        address_forwarding_id: None,
    }]);

    // Unlock the user keys with the derived key secret.
    let unlock_result = user_keys.unlock(pgp_provider, &key_secret);
    if !unlock_result.failed.is_empty() {
        println!(
            "Warning: {} user key(s) failed to unlock",
            unlock_result.failed.len()
        );
    }
    let unlocked_user_keys: UnlockedUserKeys<PGP> = unlock_result.unlocked_keys.into();
    println!("Unlocked {} user key(s)", unlocked_user_keys.len());

    // Create a selector from the unlocked user keys for OpenPGP operations.
    let user_key_selector = unlocked_user_keys.selector();
    let _signing_key = user_key_selector
        .for_signing()
        .expect("primary user key must be present");
    let _encryption_key = user_key_selector
        .for_encryption()
        .expect("primary user key must be present");
    let _decryption_keys = user_key_selector.for_decryption();
    let _verification_keys = user_key_selector.for_signature_verification();
    println!("User key selector ready (signing, encryption, decryption, verification)");

    // --- Unlock address keys ---

    // Address keys are encrypted with the user key via a randomly generated token.
    // Here we generate a fresh address key from the unlocked user key to show the full flow.
    let primary_user_key = user_key_selector
        .primary()
        .expect("primary user key must be present");
    let local_address_key = LocalAddressKey::generate(
        pgp_provider,
        "user@proton.me",
        KeyGeneratorAlgorithm::default(),
        KeyFlag::default(),
        true,
        primary_user_key,
    )
    .expect("address key generation must succeed");

    // Wrap the generated key in the LockedKey format as it would be returned by the API.
    let address_keys = AddressKeys::new(vec![LockedKey {
        id: KeyId::from("address-key-id"),
        version: 3,
        private_key: local_address_key.private_key,
        token: local_address_key.token,
        signature: local_address_key.signature,
        primary: true,
        active: true,
        flags: Some(KeyFlag::default()),
        activation: None,
        recovery_secret: None,
        recovery_secret_signature: None,
        address_forwarding_id: None,
    }]);

    // Unlock the address keys using the unlocked user keys.
    // The user keys decrypt the per-key token, which in turn decrypts the address key.
    // Pass None for the passphrase – only required for legacy address keys that were
    // encrypted directly with the key secret instead of a token.
    let unlock_result = address_keys.unlock(pgp_provider, unlocked_user_keys.as_slice(), None);
    if !unlock_result.failed.is_empty() {
        println!(
            "Warning: {} address key(s) failed to unlock",
            unlock_result.failed.len()
        );
    }
    let unlocked_address_keys: UnlockedAddressKeys<PGP> = unlock_result.unlocked_keys.into();
    println!("Unlocked {} address key(s)", unlocked_address_keys.len());

    // Create a selector from the unlocked address keys for OpenPGP operations.
    let address_key_selector = unlocked_address_keys.into_selector();
    let _signing_key = address_key_selector
        .for_signing()
        .expect("primary address key must be present");
    let _encryption_key = address_key_selector
        .for_encryption()
        .expect("primary address key must be present");
    let _decryption_keys = address_key_selector.for_decryption();
    let _verification_keys = address_key_selector.for_signature_verification();
}
