use crate::hash::double_sha256;

pub fn derive_address(script_type: &str, script_bytes: &[u8]) -> Option<String> {
    match script_type {
        "p2pkh" => derive_p2pkh_address(script_bytes),
        "p2sh" => derive_p2sh_address(script_bytes),
        "p2wpkh" => derive_p2wpkh_address(script_bytes),
        "p2wsh" => derive_p2wsh_address(script_bytes),
        "p2tr" => derive_p2tr_address(script_bytes),
        _ => None,  // op_return and unknown have no address
    }
}

/// Derive P2PKH address (starts with '1')
/// Script: OP_DUP OP_HASH160 <20 bytes> OP_EQUALVERIFY OP_CHECKSIG
fn derive_p2pkh_address(script_bytes: &[u8]) -> Option<String> {
    // Extract the 20-byte hash (skip first 3 bytes: 76 a9 14)
    if script_bytes.len() != 25 {
        return None;
    }
    
    let hash = &script_bytes[3..23];
    
    // Build the payload: version + hash
    let mut payload = Vec::new();
    payload.push(0x00);  // P2PKH version byte
    payload.extend_from_slice(hash);
    
    // Compute checksum: first 4 bytes of double SHA256
    let checksum_full = double_sha256(&payload);
    let checksum = &checksum_full[0..4];
    
    // Append checksum
    payload.extend_from_slice(checksum);
    
    // Encode in Base58
    Some(bs58::encode(payload).into_string())
}

/// Derive P2SH address (starts with '3')
/// Script: OP_HASH160 <20 bytes> OP_EQUAL
fn derive_p2sh_address(script_bytes: &[u8]) -> Option<String> {
    // Extract the 20-byte hash (skip first 2 bytes: a9 14)
    if script_bytes.len() != 23 {
        return None;
    }
    
    let hash = &script_bytes[2..22];
    
    // Build the payload: version + hash
    let mut payload = Vec::new();
    payload.push(0x05);  // P2SH version byte
    payload.extend_from_slice(hash);
    
    // Compute checksum
    let checksum_full = double_sha256(&payload);
    let checksum = &checksum_full[0..4];
    
    // Append checksum
    payload.extend_from_slice(checksum);
    
    // Encode in Base58
    Some(bs58::encode(payload).into_string())
}

/// Derive P2WPKH address (starts with 'bc1q')
/// Script: OP_0 <20 bytes>
fn derive_p2wpkh_address(script_bytes: &[u8]) -> Option<String> {
    // Extract the 20-byte hash (skip first 2 bytes: 00 14)
    if script_bytes.len() != 22 {
        return None;
    }
    
    let witness_program = &script_bytes[2..22];
    
    // Encode using Bech32 (witness version 0)
    encode_bech32_address(0, witness_program)
}

/// Derive P2WSH address (starts with 'bc1q')
/// Script: OP_0 <32 bytes>
fn derive_p2wsh_address(script_bytes: &[u8]) -> Option<String> {
    // Extract the 32-byte hash (skip first 2 bytes: 00 20)
    if script_bytes.len() != 34 {
        return None;
    }
    
    let witness_program = &script_bytes[2..34];
    
    // Encode using Bech32 (witness version 0)
    encode_bech32_address(0, witness_program)
}

/// Derive P2TR address (starts with 'bc1p')
/// Script: OP_1 <32 bytes>
fn derive_p2tr_address(script_bytes: &[u8]) -> Option<String> {
    // Extract the 32-byte x-only pubkey (skip first 2 bytes: 51 20)
    if script_bytes.len() != 34 {
        return None;
    }
    
    let witness_program = &script_bytes[2..34];
    
    // Encode using Bech32m (witness version 1)
    // Note: Taproot uses Bech32m, not Bech32!
    encode_bech32m_address(1, witness_program)
}

/// Encode a SegWit address using Bech32 (for witness version 0)
fn encode_bech32_address(witness_version: u8, witness_program: &[u8]) -> Option<String> {
    use bech32::{Bech32, Hrp};
    
    // The bech32 crate expects the data as u8 where the first byte is the witness version
    // followed by the witness program converted to 5-bit encoding
    
    // Convert witness program from 8-bit to 5-bit groups
    let data_5bit = convert_bits(witness_program, 8, 5, true).ok()?;
    
    // Build full data: [version] + converted_program
    let mut full_data = vec![witness_version];
    full_data.extend(data_5bit);
    
    // Encode with HRP "bc" (mainnet)
    let hrp = Hrp::parse("bc").ok()?;
    bech32::encode::<Bech32>(hrp, &full_data).ok()
}

/// Encode a Taproot address using Bech32m (for witness version 1)
fn encode_bech32m_address(witness_version: u8, witness_program: &[u8]) -> Option<String> {
    use bech32::{Bech32m, Hrp};
    
    // Convert witness program from 8-bit to 5-bit groups
    let data_5bit = convert_bits(witness_program, 8, 5, true).ok()?;
    
    // Build full data: [version] + converted_program
    let mut full_data = vec![witness_version];
    full_data.extend(data_5bit);
    
    // Encode with HRP "bc" (mainnet)
    let hrp = Hrp::parse("bc").ok()?;
    bech32::encode::<Bech32m>(hrp, &full_data).ok()
}

/// Convert between bit groups (e.g., 8-bit to 5-bit for Bech32)
/// 
/// This is a helper function since the bech32 crate doesn't expose this directly
fn convert_bits(data: &[u8], from_bits: u32, to_bits: u32, pad: bool) -> Result<Vec<u8>, String> {
    let mut acc: u32 = 0;
    let mut bits: u32 = 0;
    let mut result = Vec::new();
    let maxv: u32 = (1 << to_bits) - 1;
    
    for &value in data {
        let value = value as u32;
        if value >> from_bits != 0 {
            return Err("Invalid input data".to_string());
        }
        acc = (acc << from_bits) | value;
        bits += from_bits;
        while bits >= to_bits {
            bits -= to_bits;
            result.push(((acc >> bits) & maxv) as u8);
        }
    }
    
    if pad {
        if bits > 0 {
            result.push(((acc << (to_bits - bits)) & maxv) as u8);
        }
    } else if bits >= from_bits || ((acc << (to_bits - bits)) & maxv) != 0 {
        return Err("Invalid padding".to_string());
    }
    
    Ok(result)
}