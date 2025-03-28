use proton_srp::{SRPAuth, SRPProofB64, SRPVerifierB64, ServerInteraction};

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

    let client_verifier: SRPVerifierB64 =
        SRPAuth::generate_verifier(&modulus_verifier, CLIENT_PASSWORD, None, MODULUS)
            .expect("verifier generation must succeed")
            .into();

    println!("Client verifier: {client_verifier:?}\n");

    // Start dummy login with the verifier from the client above
    let mut server = ServerInteraction::new_with_modulus_extractor(
        &modulus_verifier,
        MODULUS,
        &client_verifier.verifier,
    )
    .expect("verifier generation failed");
    let server_challenge = server.generate_challenge();

    println!("Server challenge: {}\n", server_challenge.encode_b64());

    // Client login
    let client = SRPAuth::new(
        &modulus_verifier,
        CLIENT_PASSWORD,
        4,
        &client_verifier.salt,
        MODULUS,
        &server_challenge.encode_b64(),
    )
    .expect("client auth failed");

    let proof: SRPProofB64 = client
        .generate_proofs()
        .expect("client failed to generate a proof")
        .into();

    println!("Client proof: {proof:?}\n");

    // Server verification
    let server_proof = server
        .verify_proof(&proof.client_ephemeral, &proof.client_proof)
        .expect("server side verification failed");

    println!("Server proof: {}\n", server_proof.encode_b64());

    // Client verification
    assert!(proof.compare_server_proof(&server_proof.encode_b64()));
}

#[cfg(not(feature = "pgpinternal"))]
mod nopgp {

    pub struct NoOpVerifier {}

    impl proton_srp::ModulusSignatureVerifier for NoOpVerifier {
        fn verify_and_extract_modulus(
            &self,
            modulus: &str,
            _server_key: &str,
        ) -> Result<String, proton_srp::ModulusVerifyError> {
            Ok(extract_pgp_body(modulus))
        }
    }

    fn extract_pgp_body(input: &str) -> String {
        let mut extracted_lines = Vec::new();
        let mut in_body = false;

        for line in input.lines() {
            if line.starts_with("-----BEGIN PGP SIGNED MESSAGE-----") {
                in_body = true;
            } else if line.starts_with("-----BEGIN PGP SIGNATURE-----") {
                break;
            } else if in_body {
                let trimmed = line.trim();
                if !trimmed.is_empty()
                    && trimmed
                        .chars()
                        .all(|c| c.is_ascii_alphanumeric() || "+/=".contains(c))
                {
                    extracted_lines.push(trimmed.to_string());
                }
            }
        }

        extracted_lines.join("")
    }
}
