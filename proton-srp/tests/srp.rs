use proton_srp::{
    SRPAuth, SRPProofB64, SRPVerifierB64, ServerClientProof, ServerClientVerifier,
    ServerInteraction, SrpHashVersion,
};

#[test]
#[cfg(feature = "pgpinternal")]
fn test_srp_call() {
    const TEST_SERVER_EPHEMERAL: &str = "l13IQSVFBEV0ZZREuRQ4ZgP6OpGiIfIjbSDYQG3Yp39FkT2B/k3n1ZhwqrAdy+qvPPFq/le0b7UDtayoX4aOTJihoRvifas8Hr3icd9nAHqd0TUBbkZkT6Iy6UpzmirCXQtEhvGQIdOLuwvy+vZWh24G2ahBM75dAqwkP961EJMh67/I5PA5hJdQZjdPT5luCyVa7BS1d9ZdmuR0/VCjUOdJbYjgtIH7BQoZs+KacjhUN8gybu+fsycvTK3eC+9mCN2Y6GdsuCMuR3pFB0RF9eKae7cA6RbJfF1bjm0nNfWLXzgKguKBOeF3GEAsnCgK68q82/pq9etiUDizUlUBcA==";
    const TEST_MODULUS_CLEAR_SIGN: &str = "-----BEGIN PGP SIGNED MESSAGE-----\nHash: SHA256\n\nW2z5HBi8RvsfYzZTS7qBaUxxPhsfHJFZpu3Kd6s1JafNrCCH9rfvPLrfuqocxWPgWDH2R8neK7PkNvjxto9TStuY5z7jAzWRvFWN9cQhAKkdWgy0JY6ywVn22+HFpF4cYesHrqFIKUPDMSSIlWjBVmEJZ/MusD44ZT29xcPrOqeZvwtCffKtGAIjLYPZIEbZKnDM1Dm3q2K/xS5h+xdhjnndhsrkwm9U9oyA2wxzSXFL+pdfj2fOdRwuR5nW0J2NFrq3kJjkRmpO/Genq1UW+TEknIWAb6VzJJJA244K/H8cnSx2+nSNZO3bbo6Ys228ruV9A8m6DhxmS+bihN3ttQ==\n-----BEGIN PGP SIGNATURE-----\nVersion: ProtonMail\nComment: https://protonmail.com\n\nwl4EARYIABAFAlwB1j0JEDUFhcTpUY8mAAD8CgEAnsFnF4cF0uSHKkXa1GIa\nGO86yMV4zDZEZcDSJo0fgr8A/AlupGN9EdHlsrZLmTA1vhIx+rOgxdEff28N\nkvNM7qIK\n=q6vu\n-----END PGP SIGNATURE-----";
    const TEST_SALT: &str = "yKlc5/CvObfoiw==";
    const TEST_PASSWORD: &str = "abc123";
    let client = SRPAuth::with_pgp(
        None,
        TEST_PASSWORD,
        SrpHashVersion::V4,
        TEST_SALT,
        TEST_MODULUS_CLEAR_SIGN,
        TEST_SERVER_EPHEMERAL,
    )
    .expect("parameters are valid");
    client.generate_proofs().expect("expected no error");
}

#[test]
#[cfg(feature = "pgpinternal")]
fn test_srp_error() {
    use proton_srp::SrpHashVersion;

    const TEST_SERVER_EPHEMERAL: &str = "vl0zIXo4bLPtYVoy3kIvhWQx3ObPMYTY0c5/TFHlmwgBW6Hz/p2XDJdDykF3rBfwrSUD4tfs1YRCfgGfvxegCIQhL419OPYgA+ApXUuS2ni86AXUfjPnvJju/inYQxER8nzEhM8DZYAiNM44qeepmXGrHmwjXAMzyaggqxmkTq4v+seKntFE5oH7iIFacgP52wnV/p6OLOMNS4t/vZ3haKaoEVoFyCVVoTJ/OVPp1ZoUovOoxwDvUAOjSEgswenR96xT+4CsPz9Dm+yF/bDugcWGQ4KB8KEzBrO0PqmCQWMYOKaILegtgTjg08eQTvGylSEZmbTeVzoPe/THqh2bJw==";
    const TEST_MODULUS_CLEAR_SIGN: &str = "-----BEGIN PGP SIGNED-----\nHash: SHA256\n\no4ycZ14/7LfHkuSKWNlpQEh6bwLMVKvo0MFqVq9wHXwkZ/zMcqYaVhqNvLyDB0WY5Uv/Bo23JQsox52lM+4jPydw9/A9saAj8erLCc3ZaZHxOl/a8tlYTq7FeDrbhSSgivwTKJ5Y9otla/U8FATZBxqi7nqDihS5/7x/yK3VRnEsBG1i5DcY1UQK3KD9i9v7N2QTuGFYnRCv0MFsHzrQZWvUa1NsUhozU5PSV5s7hZkb/p6J3B9ybD6+LzuLS9fyLMcVdxzn2WUXG7JLeBbqsoECUfq9KP2waTzVLELOenWUV1wbioceJsaiP97ViwNJdnKx1ICoYu2c+z8ctVcqlw==\n-----BEGIN PGP SIGNATURE-----\nVersion: ProtonMail\nComment: https://protonmail.com\n\nwl4EARYIABAFAlwB1j0JEDUFhcTpUY8mAAB02wD5AOhMNS/K6/nvaeRhTr5n\niDGMalQccYlb58XzUEhqf3sBAOcTsz0fP3PVdMQYBbqcBl9Y6LGIG9DF4B4H\nZeLCoyYN\n=cAxM\n-----END PGP SIGNATURE-----\ns";
    const TEST_SALT: &str = "CGhrAMJla9YHGQ==";
    const TEST_PASSWORD: &str = "123";
    SRPAuth::with_pgp(
        None,
        TEST_PASSWORD,
        SrpHashVersion::V4,
        TEST_SALT,
        TEST_MODULUS_CLEAR_SIGN,
        TEST_SERVER_EPHEMERAL,
    )
    .expect_err("expected an error");
}

struct TestVerifer {}

impl ModulusSignatureVerifier for TestVerifer {
    fn verify_and_extract_modulus(
        &self,
        modulus: &str,
        _public_key: &str,
    ) -> Result<String, ModulusVerifyError> {
        Ok(modulus.to_string())
    }
}

use proton_srp::{ModulusSignatureVerifier, ModulusVerifyError};

#[test]
fn test_srp_call_custom_verifier() {
    const TEST_SERVER_EPHEMERAL: &str = "l13IQSVFBEV0ZZREuRQ4ZgP6OpGiIfIjbSDYQG3Yp39FkT2B/k3n1ZhwqrAdy+qvPPFq/le0b7UDtayoX4aOTJihoRvifas8Hr3icd9nAHqd0TUBbkZkT6Iy6UpzmirCXQtEhvGQIdOLuwvy+vZWh24G2ahBM75dAqwkP961EJMh67/I5PA5hJdQZjdPT5luCyVa7BS1d9ZdmuR0/VCjUOdJbYjgtIH7BQoZs+KacjhUN8gybu+fsycvTK3eC+9mCN2Y6GdsuCMuR3pFB0RF9eKae7cA6RbJfF1bjm0nNfWLXzgKguKBOeF3GEAsnCgK68q82/pq9etiUDizUlUBcA==";
    const TEST_MODULUS_CLEAR_SIGN: &str = "W2z5HBi8RvsfYzZTS7qBaUxxPhsfHJFZpu3Kd6s1JafNrCCH9rfvPLrfuqocxWPgWDH2R8neK7PkNvjxto9TStuY5z7jAzWRvFWN9cQhAKkdWgy0JY6ywVn22+HFpF4cYesHrqFIKUPDMSSIlWjBVmEJZ/MusD44ZT29xcPrOqeZvwtCffKtGAIjLYPZIEbZKnDM1Dm3q2K/xS5h+xdhjnndhsrkwm9U9oyA2wxzSXFL+pdfj2fOdRwuR5nW0J2NFrq3kJjkRmpO/Genq1UW+TEknIWAb6VzJJJA244K/H8cnSx2+nSNZO3bbo6Ys228ruV9A8m6DhxmS+bihN3ttQ==";
    const TEST_SALT: &str = "yKlc5/CvObfoiw==";
    const TEST_PASSWORD: &str = "abc123";
    let client = SRPAuth::new(
        &TestVerifer {},
        None,
        TEST_PASSWORD,
        SrpHashVersion::V4,
        TEST_SALT,
        TEST_MODULUS_CLEAR_SIGN,
        TEST_SERVER_EPHEMERAL,
    )
    .expect("parameters are valid");
    client.generate_proofs().expect("expected no error");
}

#[test]
fn test_srp_round_trip_custom_verifier() {
    const TEST_MODULUS_CLEAR_SIGN: &str = "W2z5HBi8RvsfYzZTS7qBaUxxPhsfHJFZpu3Kd6s1JafNrCCH9rfvPLrfuqocxWPgWDH2R8neK7PkNvjxto9TStuY5z7jAzWRvFWN9cQhAKkdWgy0JY6ywVn22+HFpF4cYesHrqFIKUPDMSSIlWjBVmEJZ/MusD44ZT29xcPrOqeZvwtCffKtGAIjLYPZIEbZKnDM1Dm3q2K/xS5h+xdhjnndhsrkwm9U9oyA2wxzSXFL+pdfj2fOdRwuR5nW0J2NFrq3kJjkRmpO/Genq1UW+TEknIWAb6VzJJJA244K/H8cnSx2+nSNZO3bbo6Ys228ruV9A8m6DhxmS+bihN3ttQ==";
    const TEST_PASSWORD: &str = "password";
    srp_round_trip(&TestVerifer {}, TEST_PASSWORD, TEST_MODULUS_CLEAR_SIGN);
}

#[test]
#[cfg(feature = "pgpinternal")]
fn test_srp_round_trip() {
    use proton_srp::RPGPVerifier;
    const TEST_MODULUS_CLEAR_SIGN: &str = "-----BEGIN PGP SIGNED MESSAGE-----\nHash: SHA256\n\nW2z5HBi8RvsfYzZTS7qBaUxxPhsfHJFZpu3Kd6s1JafNrCCH9rfvPLrfuqocxWPgWDH2R8neK7PkNvjxto9TStuY5z7jAzWRvFWN9cQhAKkdWgy0JY6ywVn22+HFpF4cYesHrqFIKUPDMSSIlWjBVmEJZ/MusD44ZT29xcPrOqeZvwtCffKtGAIjLYPZIEbZKnDM1Dm3q2K/xS5h+xdhjnndhsrkwm9U9oyA2wxzSXFL+pdfj2fOdRwuR5nW0J2NFrq3kJjkRmpO/Genq1UW+TEknIWAb6VzJJJA244K/H8cnSx2+nSNZO3bbo6Ys228ruV9A8m6DhxmS+bihN3ttQ==\n-----BEGIN PGP SIGNATURE-----\nVersion: ProtonMail\nComment: https://protonmail.com\n\nwl4EARYIABAFAlwB1j0JEDUFhcTpUY8mAAD8CgEAnsFnF4cF0uSHKkXa1GIa\nGO86yMV4zDZEZcDSJo0fgr8A/AlupGN9EdHlsrZLmTA1vhIx+rOgxdEff28N\nkvNM7qIK\n=q6vu\n-----END PGP SIGNATURE-----";
    const TEST_PASSWORD: &str = "password";
    srp_round_trip(
        &RPGPVerifier::default(),
        TEST_PASSWORD,
        TEST_MODULUS_CLEAR_SIGN,
    );
}

fn srp_round_trip(verifier: &impl ModulusSignatureVerifier, password: &str, modulus: &str) {
    let client_verifier: SRPVerifierB64 =
        SRPAuth::generate_verifier(verifier, password, None, modulus)
            .expect("verifier generation must succeed")
            .into();

    // Start dummy login with the verifier from the client above
    let server_client_verifier = ServerClientVerifier::try_from(&client_verifier).expect("failed");
    let mut server =
        ServerInteraction::new_with_modulus_extractor(verifier, modulus, &server_client_verifier)
            .expect("verifier generation failed");
    let server_challenge = server.generate_challenge();

    // Client login
    let client = SRPAuth::new(
        verifier,
        None,
        password,
        SrpHashVersion::V4,
        &client_verifier.salt,
        modulus,
        &server_challenge.encode_b64(),
    )
    .expect("client auth failed");

    let proof: SRPProofB64 = client
        .generate_proofs()
        .expect("client failed to generate a proof")
        .into();

    // Server verification
    let server_client_proof =
        ServerClientProof::try_from(&proof).expect("failed to decode client message");
    let server_proof = server
        .verify_proof(&server_client_proof)
        .expect("server side verification failed");

    // Client verification
    assert!(proof.compare_server_proof(&server_proof.encode_b64()));
}
