use std::time::Duration;

use proton_device_verification::{DeviceChallenge, ProofOfWorkError};

#[test]
fn test_ecdlp_challenge() {
    const B64_CHALLENGE: &str = "qfGBXLcNQMRqs/Krzx+EL87++Unwy5PGlnWxK2/BRIckF+Zlqmo7eIczHzAfm66MIZk5hkRVDVXMmEfy7dB++pkn3Ht+4bm3UtbBws/R43xZn23E2rSvPACxnjGFxMar";
    const EXPECTED_RESULT: &str = "ewAAAAAAAACsasMixdYBr/9Fb4SMM8urvjPUEUCVOjGqzwQyRdUafg==";
    let challenge = DeviceChallenge::Ecdlp(B64_CHALLENGE.to_owned());

    let result = challenge
        .solve()
        .expect("Expected no error in processing challenge");

    assert_eq!(
        result, EXPECTED_RESULT,
        "Expected result to be {EXPECTED_RESULT}, but got {result}"
    );
}

#[test]
fn test_ecdlp_challenge_timeout() {
    let challenge = DeviceChallenge::Ecdlp("A".repeat(128));
    let deadline = Duration::from_millis(10);

    let result = challenge.solve_with_custom_deadline(deadline);

    assert!(matches!(result, Err(ProofOfWorkError::DeadlineExceeded)));
}

#[test]
fn test_argon2_preimage_challenge() {
    const B64_CHALLENGE: &str = "qbYJSn07JQGfol0u8MJTZ16fDRyFo2AR6phcgqlZCr44RBpz/odJc17EROMfMOpz2dE8oHW2JHeqoRax2ha4bpGusDBkEySSWJU+cmuWePzUC58fTY+VJMLBMDLhdqV9QKvozeqKcoPzqDoHZZYmyWQf4DIAKfgaha/WwzMikQMBAAAAIAAAAOEQAAABAAAA";
    const EXPECTED_RESULT: &str = "ewAAAAAAAABXe+n/4g0Hfz40eEw7h5d3XeiKdWilfCJvz0izj7p0YA==";
    let challenge = DeviceChallenge::Argon2(B64_CHALLENGE.to_owned());

    let result = challenge
        .solve()
        .expect("Expected no error in processing challenge");

    assert_eq!(
        result, EXPECTED_RESULT,
        "Expected result to be {EXPECTED_RESULT}, but got {result}"
    );
}

#[test]
fn test_argon2_preimage_challenge_timeout() {
    let challenge = DeviceChallenge::Argon2(format!("{}MBAAAAIAAAAOEQAAABAAAA", "A".repeat(170)));
    let deadline = Duration::from_millis(10);

    let result = challenge.solve_with_custom_deadline(deadline);

    assert!(matches!(result, Err(ProofOfWorkError::DeadlineExceeded)));
}
