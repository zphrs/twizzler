use blake3::Hasher as Blake3Hasher;

use super::Hasher;

pub const BLAKE3_MD_SIZE: usize = 32;

pub struct Blake3(Blake3Hasher);

impl Hasher<BLAKE3_MD_SIZE> for Blake3 {
    fn new() -> Self {
        Self(Blake3Hasher::new())
    }

    fn update(&mut self, data: &[u8]) {
        self.0.update(data);
    }

    fn finish(self) -> [u8; BLAKE3_MD_SIZE] {
        self.0.finalize().into()
    }

    fn digest(data: &[u8]) -> [u8; BLAKE3_MD_SIZE] {
        let mut hasher = Self::new();
        hasher.update(data);
        hasher.finish()
    }
}

#[cfg(test)]
mod tests {
    use paste::paste;

    use super::*;

    macro_rules! hasher_test_impl {
        ($hasher:ident, $expected:literal) => {
            paste! {
                #[test]
                fn [<$hasher:lower>]() {
                    assert_eq!(
                        hex::encode($hasher::digest(b"abcd")),
                        $expected
                    )
                }
            }
        };
    }

    hasher_test_impl!(
        Blake3,
        "8c9c9881805d1a847102d7a42e58b990d088dd88a84f7314d71c838107571f2b"
    );
}
