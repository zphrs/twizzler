extern crate twizzler_abi;
use kms::{
    crypter::{aes::Aes256Ctr, ivs::SequentialIvg},
    hasher::sha3::{Sha3_256, SHA3_256_MD_SIZE},
    khf::Khf,
    StableKeyManagementScheme,
};

pub fn main() {
    let mut khf = Khf::<
        rand::rngs::ThreadRng,
        SequentialIvg,
        Aes256Ctr,
        Sha3_256,
        { SHA3_256_MD_SIZE },
    >::default();
    khf.derive(0).unwrap();
}
