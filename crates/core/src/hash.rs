use sha2::{Sha256,Digest};
use ripemd::{Ripemd160};

pub fn double_sha256(data: &[u8])->[u8;32]{
    let first_hash = Sha256::digest(data);
    let second_hash = Sha256::digest(&first_hash);
    second_hash.into()
}

pub fn hash160(data: &[u8]) ->[u8;20]{
    let sha = Sha256::digest(data);
    let ripemd = Ripemd160::digest(&sha);
    ripemd.into()
}

pub fn hash_to_hex_reversed(hash: &[u8; 32]) -> String {
    let mut reversed_hash = *hash;
    reversed_hash.reverse();
    hex::encode(reversed_hash)
}