use crate::address::derive_address;
use crate::reader::{ByteReader, ReadError};
use crate::script::{classify_output_script, extract_op_return_data};
use crate::types::*;
use std::collections::HashMap;


#[derive(Debug)]
pub enum ParseError {
    InvalidHex(String),
    InvalidTransaction(String),
    MissingPrevout(String),
    DuplicatePrevout(String),
    ReadError(ReadError),
}
impl From<ReadError> for ParseError {
    fn from(err: ReadError) -> Self {
        ParseError::ReadError(err)
    }
}
impl From<hex::FromHexError> for ParseError {
    fn from(err: hex::FromHexError) -> Self {
        ParseError::InvalidHex(err.to_string())
    }
}
fn hex_to_bytes(hex_str: &str) -> Result<Vec<u8>, ParseError> {
    let cleaned = hex_str.trim();
    let bytes = hex::decode(cleaned)?;
    Ok(bytes)
}
fn build_prevout_map(
    prevouts_json: &[serde_json::Value],
) -> Result<HashMap<(String, u32), Prevout>, ParseError> {
    let mut map = HashMap::new();
    for prevout_json in prevouts_json {
        let txid = prevout_json["txid"]
            .as_str()
            .ok_or_else(|| ParseError::InvalidTransaction("Prevout missing txid".to_string()))?
            .to_string();
        let vout = prevout_json["vout"]
            .as_u64()
            .ok_or_else(|| ParseError::InvalidTransaction("Prevout missing vout".to_string()))?
            as u32;
        let value_sats = prevout_json["value_sats"].as_u64().ok_or_else(|| {
            ParseError::InvalidTransaction("Prevout missing value_sats".to_string())
        })?;
        let script_pubkey_hex = prevout_json["script_pubkey_hex"]
            .as_str()
            .ok_or_else(|| {
                ParseError::InvalidTransaction("Prevout missing script_pubkey_hex".to_string())
            })?
            .to_string();
        let prevout = Prevout {
            value_sats,
            script_pubkey_hex,
        };
        let key = (txid.clone(), vout);
        if map.contains_key(&key) {
            return Err(ParseError::DuplicatePrevout(format!(
                "Duplicate prevout for txid {} vout {}",
                txid, vout
            )));
        }
        map.insert(key, prevout);
    }
    Ok(map)
}

fn parse_input(reader: &mut ByteReader) -> Result<(String, u32, Vec<u8>, u32), ParseError> {
    let mut prev_txid_bytes = reader.read_bytes(32)?;
    prev_txid_bytes.reverse();
    let prev_txid = hex::encode(&prev_txid_bytes);
    let prev_vout = reader.read_u32_le()?;
    let script_sig_len = reader.read_varint()?;
    let script_sig = reader.read_bytes(script_sig_len as usize)?;
    let sequence = reader.read_u32_le()?;
    Ok((prev_txid, prev_vout, script_sig, sequence))
}

fn parse_output(reader: &mut ByteReader) -> Result<(u64, Vec<u8>), ParseError> {
    let value_sats = reader.read_u64_le()?;
    let script_pubkey_len = reader.read_varint()?;
    let script_pubkey = reader.read_bytes(script_pubkey_len as usize)?;
    Ok((value_sats, script_pubkey))
}


/// Parse witness data for a single input

fn parse_witness(reader: &mut ByteReader) -> Result<Vec<String>, ParseError> {
    // Read the number of witness items for this input
    let witness_count = reader.read_varint()?;

    let mut witness_items = Vec::new();

    for _ in 0..witness_count {
        // Read the length of this witness item
        let item_len = reader.read_varint()?;

        if item_len == 0 {
            // Empty witness item (possible and valid!)
            witness_items.push("".to_string());
        } else {
            // Read the witness item data
            let item_data = reader.read_bytes(item_len as usize)?;
            witness_items.push(hex::encode(item_data));
        }
    }

    Ok(witness_items)
}

pub fn parse_raw_transaction(
    raw_tx_hex: &str,
    prevouts_json: &[serde_json::Value],
) -> Result<Transaction, ParseError> {
    let tx_bytes = hex_to_bytes(raw_tx_hex)?;
    let prevout_map = build_prevout_map(prevouts_json)?;
    let mut reader = ByteReader::new(tx_bytes.clone());
    let version = reader.read_u32_le()?;
    

    let position_before_check = reader.position();

    let is_segwit = if reader.remaining() >= 2 {
        let marker = reader.read_u8()?;
        let flag = reader.read_u8()?;

        if marker == 0x00 && flag == 0x01 {
            // println!("SegWit transaction detected");
            true
        } else {
            reader.set_position(position_before_check);
            // println!("Legacy transaction detected");
            false
        }
    } else {
        return Err(ParseError::InvalidTransaction(
            "Transaction too short".to_string(),
        ));
    };

    let input_count = reader.read_varint()?;
    // println!("Input count: {}", input_count);

    let mut inputs = Vec::new();
    for _i in 0..input_count {
        let (txid, vout, script_sig, sequence) = parse_input(&mut reader)?;
        // println!("Input {}: txid={}, vout={}", i, txid, vout);
        inputs.push((txid, vout, script_sig, sequence));
    }

    let output_count = reader.read_varint()?;
    

    let mut outputs = Vec::new();
    for _i in 0..output_count {
        let (value_sats, script_pubkey) = parse_output(&mut reader)?;
     
        outputs.push((value_sats, script_pubkey));
    }

  
    // There is ONE witness per input, in the same order as inputs
    let witness_data: Vec<Vec<String>> = if is_segwit {
        let mut all_witnesses = Vec::new();

        for _i in 0..input_count {
            let witness = parse_witness(&mut reader)?;
            all_witnesses.push(witness);
        }

        all_witnesses
    } else {
        // Legacy transaction: all inputs have empty witness
        vec![vec![]; input_count as usize]
    };

    let locktime = reader.read_u32_le()?;


    // Serialize without witness for txid
    let non_witness_bytes = serialize_non_witness(version, &inputs, &outputs, locktime);
    let txid_hash = crate::hash::double_sha256(&non_witness_bytes);
    let txid = crate::hash::hash_to_hex_reversed(&txid_hash);

    // For SegWit: also compute wtxid
    let wtxid = if is_segwit {
        let full_bytes =
            serialize_with_witness(version, &inputs, &outputs, &witness_data, locktime);
        let wtxid_hash = crate::hash::double_sha256(&full_bytes);
        Some(crate::hash::hash_to_hex_reversed(&wtxid_hash))
    } else {
        None
    };

  

    

    let _size_bytes = tx_bytes.len();

    let mut total_output_sats: u64 = 0;
    for (value, _script) in &outputs {
        total_output_sats += value;
    }
    let mut vin = Vec::new();
    for (i, (txid, vout, script_sig, sequence)) in inputs.iter().enumerate() {
        let key = (txid.clone(), *vout);

       
        let prevout = prevout_map
            .get(&key)
            .ok_or_else(|| {
                ParseError::MissingPrevout(format!(
                    "Missing prevout for input {}: txid={} vout={}",
                    i, txid, vout
                ))
            })?
            .clone();    
        let input = TransactionInput {
            txid: txid.clone(),
            vout: *vout,
            sequence: *sequence,
            script_sig_hex: hex::encode(script_sig),
            script_asm: crate::script::disassemble_script(script_sig),
            witness: witness_data[i].clone(),
            script_type: crate::script::classify_input_script(
                &hex::decode(&prevout.script_pubkey_hex).unwrap(),
                script_sig,
                &witness_data[i],
            ), 
            address: crate::address::derive_address(
                &crate::script::classify_output_script(
                    &hex::decode(&prevout.script_pubkey_hex).unwrap(),
                ),
                &hex::decode(&prevout.script_pubkey_hex).unwrap(),
            ),
            prevout,
            relative_timelock: decode_relative_timelock(*sequence),
        };
        vin.push(input);
    }

    let mut rbf_signaling = false;
    for input in &vin {
        if input.sequence < 0xFFFFFFFE {
            rbf_signaling = true;
            break;
        }
    }
    // Calculate total input value
    let mut total_input_sats: u64 = 0;
    for input in &vin {
        total_input_sats += input.prevout.value_sats;
    }

    // Calculate fee
    let fee_sats = total_input_sats.saturating_sub(total_output_sats);


    let mut vout = Vec::new();
    for (i, (value, script_pubkey)) in outputs.iter().enumerate() {
        let script_type = classify_output_script(script_pubkey);



        // Derive the address based on script type
        let address = derive_address(&script_type, script_pubkey);

        // For OP_RETURN outputs, extract the data

        let (op_return_data_hex, op_return_data_utf8, op_return_protocol) =
            if script_type == "op_return" {
                extract_op_return_data(script_pubkey)
            } else {
                (None, None, None)
            };

        let output = TransactionOutput {
            n: i as u32,
            value_sats: *value,
            script_pubkey_hex: hex::encode(script_pubkey),
            script_asm: crate::script::disassemble_script(script_pubkey),
            script_type,
            address,
            op_return_data_hex,
            op_return_data_utf8,
            op_return_protocol,
        };
        vout.push(output);
    }
    let (locktime_type, locktime_value) = if locktime == 0 {
        ("none".to_string(), 0)
    } else if locktime < 500_000_000 {
        ("block_height".to_string(), locktime)
    } else {
        ("unix_timestamp".to_string(), locktime)
    };


    // Calculate size, weight, and vbytes
    let (size_bytes, weight, vbytes, witness_bytes, non_witness_byte_count) = if is_segwit {
       
        let full_size =
            serialize_with_witness(version, &inputs, &outputs, &witness_data, locktime).len();
        let non_wit_size = non_witness_bytes.len();
        
        let wit_size = full_size - non_wit_size; 
       
        let weight_val = (non_wit_size * 4) + wit_size;
        let vbytes_val = (weight_val + 3) / 4; 

        (full_size, weight_val, vbytes_val, wit_size, non_wit_size)
    } else {
        
        let size = non_witness_bytes.len();
        (size, size * 4, size, 0, size)
    };
    
    let fee_rate_sat_vb = if vbytes > 0 {
        fee_sats as f64 / vbytes as f64
    } else {
        0.0
    };

    let mut warnings = Vec::new();
    
    // HIGH_FEE warning
    if fee_sats > 1_000_000 || fee_rate_sat_vb > 200.0 {
        warnings.push(crate::types::Warning {
            code: "HIGH_FEE".to_string(),
        });
    }
    
    // DUST_OUTPUT warning
    for output in &vout {
        if output.script_type != "op_return" && output.value_sats < 546 {
            warnings.push(crate::types::Warning {
                code: "DUST_OUTPUT".to_string(),
            });
            break; 
        }
    }
    
    // UNKNOWN_OUTPUT_SCRIPT warning
    for output in &vout {
        if output.script_type == "unknown" {
            warnings.push(crate::types::Warning {
                code: "UNKNOWN_OUTPUT_SCRIPT".to_string(),
            });
            break;  // Only add warning once
        }
    }
    
    // RBF_SIGNALING warning
    if rbf_signaling {
        warnings.push(crate::types::Warning {
            code: "RBF_SIGNALING".to_string(),
        });
    }    
    let transaction = Transaction {
        ok: true,
        network: "mainnet".to_string(),
        segwit: is_segwit,
        txid,
        wtxid, // TODO: compute for SegWit
        version,
        locktime,
        size_bytes,
        weight,
        vbytes,
        total_input_sats,
        total_output_sats,
        fee_sats,
        fee_rate_sat_vb,
        rbf_signaling,
        locktime_type,
        locktime_value,
        segwit_savings: if is_segwit {
            let weight_if_legacy = size_bytes * 4;
            let savings_pct =
                ((weight_if_legacy - weight) as f64 / weight_if_legacy as f64) * 100.0;

            Some(SegwitSavings {
                witness_bytes,
                non_witness_bytes: non_witness_byte_count,
                total_bytes: size_bytes,
                weight_actual: weight,
                weight_if_legacy,
                savings_pct: (savings_pct * 100.0).round() / 100.0, // Round to 2 decimals
            })
        } else {
            None
        }, // TODO: compute for SegWit
        vin,
        vout,
        warnings, // TODO: detect warnings
    };

    
    Ok(transaction)
}


/// Serialize a u32 as little-endian bytes
fn serialize_u32_le(value: u32) -> Vec<u8> {
    value.to_le_bytes().to_vec()
}

/// Serialize a u64 as little-endian bytes
fn serialize_u64_le(value: u64) -> Vec<u8> {
    value.to_le_bytes().to_vec()
}

/// Serialize a varint
fn serialize_varint(value: u64) -> Vec<u8> {
    if value < 0xFD {
        vec![value as u8]
    } else if value <= 0xFFFF {
        let mut bytes = vec![0xFD];
        bytes.extend_from_slice(&(value as u16).to_le_bytes());
        bytes
    } else if value <= 0xFFFFFFFF {
        let mut bytes = vec![0xFE];
        bytes.extend_from_slice(&(value as u32).to_le_bytes());
        bytes
    } else {
        let mut bytes = vec![0xFF];
        bytes.extend_from_slice(&value.to_le_bytes());
        bytes
    }
}

/// Serialize transaction WITHOUT witness (for txid)
fn serialize_non_witness(
    version: u32,
    inputs: &[(String, u32, Vec<u8>, u32)],
    outputs: &[(u64, Vec<u8>)],
    locktime: u32,
) -> Vec<u8> {
    let mut bytes = Vec::new();

    // Version
    bytes.extend_from_slice(&serialize_u32_le(version));

    // Input count
    bytes.extend_from_slice(&serialize_varint(inputs.len() as u64));

    // Inputs
    for (txid, vout, script_sig, sequence) in inputs {
        // Previous txid (32 bytes, reversed back)
        let mut txid_bytes = hex::decode(txid).unwrap();
        txid_bytes.reverse();
        bytes.extend_from_slice(&txid_bytes);

        // Previous vout
        bytes.extend_from_slice(&serialize_u32_le(*vout));

        // Script sig
        bytes.extend_from_slice(&serialize_varint(script_sig.len() as u64));
        bytes.extend_from_slice(script_sig);

        // Sequence
        bytes.extend_from_slice(&serialize_u32_le(*sequence));
    }

    // Output count
    bytes.extend_from_slice(&serialize_varint(outputs.len() as u64));

    // Outputs
    for (value, script_pubkey) in outputs {
        // Value
        bytes.extend_from_slice(&serialize_u64_le(*value));

        // Script pubkey
        bytes.extend_from_slice(&serialize_varint(script_pubkey.len() as u64));
        bytes.extend_from_slice(script_pubkey);
    }

    // Locktime
    bytes.extend_from_slice(&serialize_u32_le(locktime));

    bytes
}

/// Serialize transaction WITH witness (for wtxid)
pub fn serialize_with_witness(
    version: u32,
    inputs: &[(String, u32, Vec<u8>, u32)],
    outputs: &[(u64, Vec<u8>)],
    witness_data: &[Vec<String>],
    locktime: u32,
) -> Vec<u8> {
    let mut bytes = Vec::new();

    // Version
    bytes.extend_from_slice(&serialize_u32_le(version));

    // Marker and flag
    bytes.push(0x00); // marker
    bytes.push(0x01); // flag

    // Input count
    bytes.extend_from_slice(&serialize_varint(inputs.len() as u64));

    // Inputs (same as non-witness)
    for (txid, vout, script_sig, sequence) in inputs {
        let mut txid_bytes = hex::decode(txid).unwrap();
        txid_bytes.reverse();
        bytes.extend_from_slice(&txid_bytes);
        bytes.extend_from_slice(&serialize_u32_le(*vout));
        bytes.extend_from_slice(&serialize_varint(script_sig.len() as u64));
        bytes.extend_from_slice(script_sig);
        bytes.extend_from_slice(&serialize_u32_le(*sequence));
    }

    // Output count
    bytes.extend_from_slice(&serialize_varint(outputs.len() as u64));

    // Outputs (same as non-witness)
    for (value, script_pubkey) in outputs {
        bytes.extend_from_slice(&serialize_u64_le(*value));
        bytes.extend_from_slice(&serialize_varint(script_pubkey.len() as u64));
        bytes.extend_from_slice(script_pubkey);
    }

    // Witness data
    for witness_items in witness_data {
        // Witness item count for this input
        bytes.extend_from_slice(&serialize_varint(witness_items.len() as u64));

        // Each witness item
        for item_hex in witness_items {
            if item_hex.is_empty() {
                // Empty item
                bytes.push(0x00);
            } else {
                let item_bytes = hex::decode(item_hex).unwrap();
                bytes.extend_from_slice(&serialize_varint(item_bytes.len() as u64));
                bytes.extend_from_slice(&item_bytes);
            }
        }
    }

    // Locktime
    bytes.extend_from_slice(&serialize_u32_le(locktime));

    bytes
}



/// Decode BIP68 relative timelock from sequence number

pub fn decode_relative_timelock(sequence: u32) -> crate::types::RelativeTimelock {
    // Check if relative timelock is disabled (bit 31 set)
    if (sequence & 0x80000000) != 0 {
        return crate::types::RelativeTimelock {
            enabled: false,
            lock_type: None,
            value: None,
        };
    }

    // Extract the value (lower 16 bits)
    let value = (sequence & 0x0000FFFF) as u32;

    // Check type flag (bit 22)
    if (sequence & 0x00400000) != 0 {
        // Time-based: value × 512 seconds
        crate::types::RelativeTimelock {
            enabled: true,
            lock_type: Some("time".to_string()),
            value: Some(value * 512),
        }
    } else {
        // Block-based
        crate::types::RelativeTimelock {
            enabled: true,
            lock_type: Some("blocks".to_string()),
            value: Some(value),
        }
    }
}
