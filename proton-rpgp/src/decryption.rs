use crate::{PrivateKey, Profile};

pub struct Decryptor {
    profile: Profile,
    decryption_keys: Vec<PrivateKey>,
}

impl Decryptor {
    fn new(profile: Profile) -> Self {
        Self {
            profile,
            decryption_keys: Vec::new(),
        }
    }

    fn with_decryption_key(mut self, key: PrivateKey) -> Self {
        self.decryption_keys.push(key);
        self
    }

    fn with_decryption_keys(mut self, keys: Vec<PrivateKey>) -> Self {
        self.decryption_keys.extend(keys);
        self
    }
}
