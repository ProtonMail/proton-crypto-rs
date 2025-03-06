/// This trait defines the `OpenPGP` armor operations.
pub trait ArmorerSync {
    /// Armors a PGP public key.
    fn armor_public_key(&self, public_key: impl AsRef<[u8]>) -> crate::Result<Vec<u8>>;

    /// Armors a PGP private key.
    fn armor_private_key(&self, private: impl AsRef<[u8]>) -> crate::Result<Vec<u8>>;

    /// Armors a PGP signature.
    fn armor_signature(&self, signature: impl AsRef<[u8]>) -> crate::Result<Vec<u8>>;

    /// Armors a PGP message.
    fn armor_message(&self, message: impl AsRef<[u8]>) -> crate::Result<Vec<u8>>;

    /// Unarmor PGP armored data.
    fn unarmor(&self, armored: impl AsRef<[u8]>) -> crate::Result<Vec<u8>>;
}
