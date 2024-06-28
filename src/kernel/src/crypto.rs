use p256::ecdsa::{
    signature,
    signature::{Signer, Verifier},
    Signature, SigningKey, VerifyingKey,
};
use sha2::{digest::generic_array::GenericArray, Digest, Sha256, Sha512};

pub fn sha256(input: impl AsRef<[u8]>) -> impl Iterator<Item = u8> {
    let mut hasher = Sha256::new();
    hasher.update(input);
    let res = hasher.finalize();
    res.into_iter()
}

pub fn sign(key: SigningKey, message: &[u8]) -> Signature {
    key.sign(message)
}

pub fn verify(key: VerifyingKey, message: &[u8], signature: Signature) -> signature::Result<()> {
    key.verify(message, &signature)
}
