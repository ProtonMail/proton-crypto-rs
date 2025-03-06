use proton_crypto::new_pgp_provider;
// The crypto traits have to be imported to use their functionality.
use proton_crypto::crypto::{
    DataEncoding, Decryptor, DecryptorSync, Encryptor, EncryptorSync, KeyGenerator,
    KeyGeneratorSync, PGPMessage, PGPProviderSync, VerifiedData,
};

#[allow(clippy::print_stdout)]
fn main() {
    // Load the OpenPGP provider
    let pgp_provider = new_pgp_provider();

    // Generate OpenPGP keys.
    let (alice_priv, alice_pub) = generate_keys(&pgp_provider, "Alice", "alice@test.test");
    let (bob_priv, bob_pub) = generate_keys(&pgp_provider, "Bob", "bob@test.test");

    let message_to_bob = "Hi Bob!";

    println!("\nEncrypt OpenPGP message to Bob.");
    // Encrypt to Bob.
    let pgp_message_for_bob_struct = pgp_provider
        .new_encryptor()
        .with_encryption_key(&bob_pub)
        .with_signing_key(&alice_priv)
        .encrypt(message_to_bob)
        .expect("encryption to be sucessful");
    let armored = pgp_message_for_bob_struct
        .armor()
        .map(String::from_utf8)
        .unwrap()
        .expect("armor should succeed");
    println!("\nMessage for Bob:\n{armored}\n");

    println!("\nBob decrypts OpenPGP message.");
    // Bob decrypts the message and verifies its signature.
    let decrypted_message = pgp_provider
        .new_decryptor()
        .with_decryption_key(&bob_priv)
        .with_verification_key(&alice_pub)
        .decrypt(armored, DataEncoding::Armor)
        .expect("decryption to be successful");
    // Check the signature verification result
    if let Err(error) = decrypted_message.verification_result() {
        println!("Bob failed to verify the signature from Alice: {error}");
    } else {
        println!("Bob successfully verified the signature from Alice.");
    }
    let decrypted_message = String::from_utf8(decrypted_message.into_vec()).unwrap();
    println!("\nBob received the following message from Alice:\n{decrypted_message}");
}

#[allow(clippy::print_stdout)]
fn generate_keys<Provider: PGPProviderSync>(
    pgp_provider: &Provider,
    name: &str,
    email: &str,
) -> (Provider::PrivateKey, Provider::PublicKey) {
    let key_priv = pgp_provider
        .new_key_generator()
        .with_user_id(name, email)
        .generate()
        .expect("priv key gen must succeed");
    let key_pub = pgp_provider
        .private_key_to_public_key(&key_priv)
        .expect("pub key export must succeed");

    let armored_private_key = pgp_provider
        .private_key_export_unlocked(&key_priv, DataEncoding::Armor)
        .map(|value| String::from_utf8(value.as_ref().to_vec()))
        .unwrap()
        .expect("private key export must work");
    println!("\nThe unlocked private key of {name} is:\n{armored_private_key}");
    (key_priv, key_pub)
}
