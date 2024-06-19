extern crate twizzler_abi;
use std::io::Read;

use hex_literal::hex;
use p256::ecdsa::{signature::Signer, Signature, SigningKey};
use sha2::{Digest, Sha256, Sha512};
fn main() {
    println!("Hello, from crypto");

    println!("Testing hashing");
    let mut hasher = Sha256::new();
    let expected = hex!("09ca7e4eaa6e8ae9c7d261167129184883644d07dfba7cbfbc4c8a2e08360d5b");
    let actual = hasher.update(b"hello, world");
    let res = hasher.finalize();
    assert_eq!(res[..], expected);

    println!("Passed hashing test");

    println!("Testing Signature");
    let key = [
        168, 182, 114, 184, 168, 191, 237, 9, 90, 139, 135, 141, 26, 180, 247, 51, 86, 17, 197, 11,
        229, 2, 25, 252, 9, 84, 135, 246, 235, 97, 11, 60,
    ];
    let signing_key = SigningKey::from_slice(&key).unwrap();
    let message = b"ECDSA proves knowledge of a secret number in the context of a single message";
    let signature: Signature = signing_key.sign(message);

    // Verification
    use p256::ecdsa::{signature::Verifier, VerifyingKey};

    let verifying_key: VerifyingKey = signing_key.into(); // Serialize with `::to_encoded_point()`
    assert!(verifying_key.verify(message, &signature).is_ok());

    println!("Signature test passed!");

    println!("Crypto complete!");
}
