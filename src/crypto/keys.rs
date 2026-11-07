use sodiumoxide::crypto::box_::{self, PrecomputedKey, PublicKey, SecretKey};

pub struct KeyPair {
    pub public: PublicKey,
    pub secret: SecretKey,
}

impl KeyPair {
    pub fn generate() -> Self {
        sodiumoxide::init().expect("Failed to initialize sodiumoxide");
        let (public, secret) = box_::gen_keypair();
        KeyPair { public, secret }
    }

    pub fn public_key_hex(&self) -> String {
        hex::encode(self.public.as_ref())
    }
}

pub struct SharedSecret {
    pub key: PrecomputedKey,
}

impl SharedSecret {
    pub fn derive(our_secret: &SecretKey, their_public: &PublicKey) -> Self {
        let key = box_::precompute(their_public, our_secret);
        SharedSecret { key }
    }

    pub fn as_bytes(&self) -> &[u8] {
        self.key.as_ref()
    }
}
