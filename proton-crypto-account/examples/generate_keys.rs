use proton_crypto::crypto::KeyGeneratorAlgorithm;
use proton_crypto::{ProtonPGP, ProtonSRP};
use proton_crypto_account::keys::{KeyFlag, KeyId, LocalAddressKey, LocalUserKey};
use proton_crypto_account::salts::KeySalt;

#[allow(clippy::print_stdout)]
fn main() {
    let pgp_provider = ProtonPGP::new_sync();
    let srp_provider = ProtonSRP::new_sync();

    // Derive the key secret from the password with a fresh key salt.
    let key_salt = KeySalt::generate();
    let key_secret = key_salt
        .salted_key_passphrase(&srp_provider, b"password")
        .expect("failed to derive key secret");

    // User key: locked with the key secret.
    let user_key = LocalUserKey::generate(&pgp_provider, KeyGeneratorAlgorithm::ECC, &key_secret)
        .expect("failed to generate user key");
    let unlocked_user_key = user_key
        .unlock_and_assign_key_id(&pgp_provider, KeyId::from("user-key-1"), &key_secret)
        .expect("failed to unlock user key");

    // Address key: locked with a random token encrypted and signed by the user key.
    let address_key = LocalAddressKey::generate(
        &pgp_provider,
        "alice@proton.test",
        KeyGeneratorAlgorithm::ECC,
        KeyFlag::default(),
        true,
        &unlocked_user_key,
    )
    .expect("failed to generate address key");

    println!("Key salt (base64): {key_salt}\n");
    println!("User key:\n{}\n", &*user_key.private_key);
    println!("Address key:\n{}\n", &*address_key.private_key);
    println!(
        "Address key token:\n{}\n",
        &**address_key.token.as_ref().expect("token")
    );
    println!(
        "Address key token signature:\n{}",
        &**address_key.signature.as_ref().expect("signature")
    );
}
