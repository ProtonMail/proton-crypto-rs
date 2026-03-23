use proton_crypto::crypto::{DataEncoding, PGPProviderSync};
use proton_crypto_account::keys::{DecryptedUserKey, KeyId};

#[allow(dead_code)]
pub const TEST_USER_KEY: &str = "-----BEGIN PGP PRIVATE KEY BLOCK-----

xYYEZXrEuBYJKwYBBAHaRw8BAQdAd3SP+S82mvNYec99IYXXy02QlEtWOwCX
G+VRoWMTJgT+CQMIAuL1Bl1uoZBgAAAAAAAAAAAAAAAAAAAAAP8Kb+34nsOQ
jVlCUF4Rco6I2xectxdUsuCm6X+Emq+S+8JsPw/rwVxAmClvKJaeWIfZIV/u
yc07bm90X2Zvcl9lbWFpbF91c2VAZG9tYWluLnRsZCA8bm90X2Zvcl9lbWFp
bF91c2VAZG9tYWluLnRsZD7CjAQQFgoAPgWCZXrEuAQLCQcICZD98eusToQD
awMVCAoEFgACAQIZAQKbAwIeARYhBMZ9T6whFVji9dBihP3x66xOhANrAADW
1QEA4TDQcWcCskhIbAyLj3eFN9oO4cAv01QnTYuW5p5LvMYA/AyngETI6OGC
+/8UR3hKvmZMnThBMRfbzqg5B96KTIcBx4sEZXrEuBIKKwYBBAGXVQEFAQEH
QCmW61ll1IgTcm8TuNuh92qEGoIzYrRs0fb6ivPBz7YJAwEIB/4JAwh2VqMV
7EJ4WmAAAAAAAAAAAAAAAAAAAAAAjDFyvMguSeKDXNNvviwSK+nf7uqvbUNJ
EEuxjr48kR2A6Cc4OavQJbAAHIVwUG8UQ+PYW/PvwngEGBYKACoFgmV6xLgJ
kP3x66xOhANrApsMFiEExn1PrCEVWOL10GKE/fHrrE6EA2sAAIGYAQCzpA2U
R18gbFL3k6xUaUaRHxZoxBZQ2crLRO1GhgxTxQEAhYFyb7k/0S4XwcDpSgJO
YJWp7nLYBj9YSh4+qOa/5QM=
-----END PGP PRIVATE KEY BLOCK-----
";

#[allow(dead_code)]
pub const TEST_USER_KEY_CHANGED: &str = "-----BEGIN PGP PRIVATE KEY BLOCK-----

xYYEZkI9XRYJKwYBBAHaRw8BAQdAqWn9T/nEzBz31DqsXAUdtIGUnrIHNrfD
ZOuvtEIf8G/+CQMI8okkwdBKjuxgKBsLTTZH6cHgAlro1OnVNykZFiG6qASZ
Omwsl9FjZdozMlq/4AyPwDG2tkwzyEHKzn+4/Daw+FBs9ve/2Z2kOq9aEn6I
nc07bm90X2Zvcl9lbWFpbF91c2VAZG9tYWluLnRsZCA8bm90X2Zvcl9lbWFp
bF91c2VAZG9tYWluLnRsZD7CjAQQFgoAPgWCZkI9XQQLCQcICZBICuUpsYEG
ZQMVCAoEFgACAQIZAQKbAwIeARYhBCF533Bw13ukWKtNIUgK5SmxgQZlAADY
pAD+NXPfGC0v116+xHi9HIcdDUXrQpd8pRbKRcHHKZ94DF0BAOYorJa1OHzk
wzjxWQEz5Y82SLRYLNmlIVF+hHXlLtYAx4sEZkI9XRIKKwYBBAGXVQEFAQEH
QKm+vMMpfMo45etkNw3LR+jFgMrbe4hZ9zPVZCxJUZtRAwEIB/4JAwg+PXvg
gHJFA2ApL3+4HL9kuK3+HzOdTrWAGQ2dET1V4aV84gxW25FBTZbb+QqLhIym
+sYefVPntt6M/VNupYyXRs27abjPqm2YtH+rLnhwwngEGBYKACoFgmZCPV0J
kEgK5SmxgQZlApsMFiEEIXnfcHDXe6RYq00hSArlKbGBBmUAANN3AP9s1V6S
Lg9ogdrlmtTwuZhRXHQzUqC2AoLCv/lW0hz0ZQD+LBAeT7ymSyrwRtIvUh0b
qnK1SNfocPNfh//OecgiqA4=
=LMjL
-----END PGP PRIVATE KEY BLOCK-----
";

pub const TEST_KEY_PASSWORD: &str = "password";

#[allow(clippy::missing_panics_doc)]
pub fn get_test_decrypted_user_key<T: PGPProviderSync>(
    provider: &T,
    test_key: &str,
) -> Vec<DecryptedUserKey<T::PrivateKey, T::PublicKey>> {
    let private_key = provider
        .private_key_import(test_key, TEST_KEY_PASSWORD.as_bytes(), DataEncoding::Armor)
        .unwrap();
    let public_key = provider.private_key_to_public_key(&private_key).unwrap();
    vec![DecryptedUserKey {
        id: KeyId::from("G8URRzoYaBW6mSPQjbbo2yYgwI828DVcEs8dDRKxByd1A_qSRYF49TOtw_m4wvDGb76M-r3AVdXuDzSHObR5hQ=="),
        private_key,
        public_key,
    }]
}
