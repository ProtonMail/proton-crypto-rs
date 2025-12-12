use proton_srp::{
    SRPAuth, SRPProofB64, SRPVerifierB64, ServerClientProof, ServerClientVerifier,
    ServerInteraction, SrpVersion,
};

const CLIENT_USERNAME: Option<&str> = None;
const CLIENT_PASSWORD: &str = "password";

const MODULUS: &str = "-----BEGIN PGP SIGNED MESSAGE-----\nHash: SHA256\n\nW2z5HBi8RvsfYzZTS7qBaUxxPhsfHJFZpu3Kd6s1JafNrCCH9rfvPLrfuqocxWPgWDH2R8neK7PkNvjxto9TStuY5z7jAzWRvFWN9cQhAKkdWgy0JY6ywVn22+HFpF4cYesHrqFIKUPDMSSIlWjBVmEJZ/MusD44ZT29xcPrOqeZvwtCffKtGAIjLYPZIEbZKnDM1Dm3q2K/xS5h+xdhjnndhsrkwm9U9oyA2wxzSXFL+pdfj2fOdRwuR5nW0J2NFrq3kJjkRmpO/Genq1UW+TEknIWAb6VzJJJA244K/H8cnSx2+nSNZO3bbo6Ys228ruV9A8m6DhxmS+bihN3ttQ==\n-----BEGIN PGP SIGNATURE-----\nVersion: ProtonMail\nComment: https://protonmail.com\n\nwl4EARYIABAFAlwB1j0JEDUFhcTpUY8mAAD8CgEAnsFnF4cF0uSHKkXa1GIa\nGO86yMV4zDZEZcDSJo0fgr8A/AlupGN9EdHlsrZLmTA1vhIx+rOgxdEff28N\nkvNM7qIK\n=q6vu\n-----END PGP SIGNATURE-----";

#[allow(clippy::print_stdout)]
fn main() {
    #[cfg(feature = "pgpinternal")]
    let modulus_verifier = proton_srp::RPGPVerifier::default();

    // This should not be used in production, and is only for illustration.
    // The modulus must be verified.
    #[cfg(not(feature = "pgpinternal"))]
    let modulus_verifier = nopgp::NoOpVerifier {};

    // nosemgrep: generic.secrets.gitleaks.generic-api-key.generic-api-key
    let client_verifier: SRPVerifierB64 =
        SRPAuth::generate_verifier(&modulus_verifier, CLIENT_PASSWORD, None, MODULUS)
            .expect("verifier generation must succeed")
            .into();

    println!("Client verifier: {client_verifier:?}\n");

    // Start dummy login with the verifier from the client above
    let server_client_verifier = ServerClientVerifier::try_from(&client_verifier).expect("failed");
    let mut server = ServerInteraction::new_with_modulus_extractor(
        &modulus_verifier,
        MODULUS,
        &server_client_verifier,
    )
    .expect("verifier generation failed");
    let server_challenge = server.generate_challenge();

    println!("Server challenge: {}\n", server_challenge.encode_b64());

    // Client login
    let client = SRPAuth::new(
        &modulus_verifier,
        CLIENT_USERNAME,
        CLIENT_PASSWORD,
        SrpVersion::V4,
        &client_verifier.salt,
        MODULUS,
        &server_challenge.encode_b64(),
    )
    .expect("client auth failed");

    let client_proof: SRPProofB64 = client
        .generate_proofs()
        .expect("client failed to generate a proof")
        .into();

    println!("Client proof: {client_proof:?}\n");

    // Server verification
    let server_client_proof =
        ServerClientProof::try_from(&client_proof).expect("failed to decode client message");
    let server_proof = server
        .verify_proof(&server_client_proof)
        .expect("server side verification failed");

    println!("Server proof: {}\n", server_proof.encode_b64());

    // Client verification
    assert!(client_proof.compare_server_proof(&server_proof.encode_b64()));
}

#[cfg(not(feature = "pgpinternal"))]
mod nopgp {
    use proton_srp::{ModulusVerifyError, RawSRPModulus};

    pub struct NoOpVerifier {}

    impl proton_srp::ModulusSignatureVerifier for NoOpVerifier {
        fn verify_and_extract_modulus(
            &self,
            modulus: &str,
            _server_key: &str,
        ) -> Result<String, ModulusVerifyError> {
            let raw_modulus = RawSRPModulus::new_with_pgp_modulus(modulus)
                .map_err(|_| ModulusVerifyError::CleartextParse("failed".to_owned()))?;
            Ok(raw_modulus.encode_b64())
        }
    }
}
