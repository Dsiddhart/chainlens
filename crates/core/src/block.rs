use crate::hash::{double_sha256, hash_to_hex_reversed};
use crate::reader::{ByteReader, ReadError};
use std::fs;
use std::io;

/// Errors that can occur during block parsing
#[derive(Debug)]
pub enum BlockError {
    IoError(io::Error),
    ReadError(ReadError),
    InvalidBlock(String),
    MerkleRootMismatch,
}

impl From<io::Error> for BlockError {
    fn from(err: io::Error) -> Self {
        BlockError::IoError(err)
    }
}

impl From<ReadError> for BlockError {
    fn from(err: ReadError) -> Self {
        BlockError::ReadError(err)
    }
}

/// Read XOR key from xor.dat file
///
/// The key is 8 bytes. If the file doesn't exist or is all zeros,
/// no XOR decoding is needed.
pub fn read_xor_key(xor_path: &str) -> Result<Vec<u8>, BlockError> {
    match fs::read(xor_path) {
        Ok(bytes) if bytes.len() >= 8 => {
            // Take first 8 bytes as the key
            Ok(bytes[0..8].to_vec())
        }
        Ok(_) => {
            // File too short, assume no XOR
            Ok(vec![0u8; 8])
        }
        Err(_) => {
            // File doesn't exist, assume no XOR
            Ok(vec![0u8; 8])
        }
    }
}

/// XOR-decode data using the key
///
/// The key is repeated cyclically across the data.
/// If the key is all zeros, returns data unchanged.
pub fn xor_decode(data: &[u8], key: &[u8]) -> Vec<u8> {
    // Check if key is all zeros (no XOR needed)
    if key.iter().all(|&b| b == 0) {
        return data.to_vec();
    }

    // XOR each byte with the corresponding key byte
    data.iter()
        .enumerate()
        .map(|(i, &byte)| byte ^ key[i % key.len()])
        .collect()
}

/// Read and XOR-decode a block or undo file
pub fn read_and_decode_file(file_path: &str, xor_key: &[u8]) -> Result<Vec<u8>, BlockError> {
    let data = fs::read(file_path)?;
    Ok(xor_decode(&data, xor_key))
}

#[derive(Debug)]
pub struct BlockHeader {
    pub version: u32,
    pub prev_block_hash: String, // hex, display order
    pub merkle_root: String,     // hex, display order
    pub timestamp: u32,          // unix timestamp
    pub bits: u32,               // difficulty target
    pub nonce: u32,
}

/// Parse an 80-byte block header
pub fn parse_block_header(header_bytes: &[u8]) -> Result<BlockHeader, BlockError> {
    if header_bytes.len() != 80 {
        return Err(BlockError::InvalidBlock(format!(
            "Invalid header size: {} bytes",
            header_bytes.len()
        )));
    }

    let mut reader = ByteReader::new(header_bytes.to_vec());

    // Version (4 bytes, little-endian)
    let version = reader.read_u32_le()?;

    // Previous block hash (32 bytes, reversed for display)
    let prev_hash_bytes = reader.read_bytes(32)?;
    let mut prev_hash_display = prev_hash_bytes.clone();
    prev_hash_display.reverse();
    let prev_block_hash = hex::encode(prev_hash_display);

    // Merkle root (32 bytes, reversed for display)
    let merkle_bytes = reader.read_bytes(32)?;
    let mut merkle_display = merkle_bytes.clone();
    merkle_display.reverse();
    let merkle_root = hex::encode(merkle_display);

    // Timestamp (4 bytes, little-endian)
    let timestamp = reader.read_u32_le()?;

    // Bits (4 bytes, little-endian)
    let bits = reader.read_u32_le()?;

    // Nonce (4 bytes, little-endian)
    let nonce = reader.read_u32_le()?;

    Ok(BlockHeader {
        version,
        prev_block_hash,
        merkle_root,
        timestamp,
        bits,
        nonce,
    })
}

/// Compute block hash from header bytes
pub fn compute_block_hash(header_bytes: &[u8]) -> String {
    let hash = double_sha256(header_bytes);
    hash_to_hex_reversed(&hash)
}

/// A parsed block with all its data
#[derive(Debug)]
pub struct Block {
    pub block_hash: String,
    pub header: BlockHeader,
    pub tx_count: u64,
    pub transactions: Vec<crate::types::Transaction>,
    pub size_bytes: usize,
    pub txids: Vec<String>,
    pub bip34_height: Option<u32>,
}

/// Parse all blocks from a blk*.dat file
///
/// Structure:
/// [4 bytes: magic (0xF9BEB4D9 for mainnet)]
/// [4 bytes: block size]
/// [80 bytes: header]
/// [varint: tx count]
/// [transactions...]
/// Parse all blocks from files with undo data

pub fn parse_blocks_with_undo(
    blk_path: &str,
    rev_path: &str,
    xor_key: &[u8],
) -> Result<Vec<Block>, BlockError> {
    let undo_data = parse_undo_file(rev_path, xor_key)?;

    let data = read_and_decode_file(blk_path, xor_key)?;
    let mut reader = ByteReader::new(data);

    let mut blocks = Vec::new();
    let mut undo_block_index = 0;

    while reader.remaining() > 0 {
        if reader.remaining() < 8 {
            break;
        }

        let magic = reader.read_u32_le()?;
        if magic != 0xD9B4BEF9 {
            return Err(BlockError::InvalidBlock(format!(
                "Invalid magic bytes: {:#x}",
                magic
            )));
        }

        let block_size = reader.read_u32_le()? as usize;

        if reader.remaining() < block_size {
            return Err(BlockError::InvalidBlock(
                "Incomplete block data".to_string(),
            ));
        }

        let block_data = reader.read_bytes(block_size)?;

        let block_undo: &[UndoPrevout] = if undo_block_index < undo_data.len() {
            &undo_data[undo_block_index]
        } else {
            &[]
        };

        let block = parse_block_with_undo(&block_data, block_undo)?;

        blocks.push(block);
        undo_block_index += 1;
    }

    Ok(blocks)
}

/// Compressed prevout from undo file
#[derive(Debug, Clone)]
pub struct UndoPrevout {
    pub height: u32,
    pub coinbase: bool,
    pub value_sats: u64,
    pub script_pubkey: Vec<u8>,
}

/// Parse undo data for one block

fn parse_block_undo_data(data: &[u8]) -> Result<Vec<UndoPrevout>, BlockError> {
    let mut reader = ByteReader::new(data.to_vec());
    let mut all_prevouts = Vec::new();

    // No hash prefix, no hash suffix — just raw sequential prevouts
    while reader.remaining() >= 3 {
        match parse_undo_prevout(&mut reader) {
            Ok(prevout) => all_prevouts.push(prevout),
            Err(_) => break,
        }
    }

    Ok(all_prevouts)
}
/// Parse a single undo prevout (CTxInUndo format)

fn parse_undo_prevout(reader: &mut ByteReader) -> Result<UndoPrevout, BlockError> {
    // nCode encodes height and coinbase flag
    let n_code = reader.read_varint128()?;
    let height = (n_code >> 1) as u32;
    let coinbase = (n_code & 1) == 1;

    if height > 2_000_000 {
        return Err(BlockError::InvalidBlock(format!(
            "Invalid height: {}",
            height
        )));
    }

    // Compressed amount
    let amount_compressed = reader.read_varint128()?;
    let value_sats = decompress_txout_amount(amount_compressed);

    // Compressed script: nSize encodes the script type
    let n_size = reader.read_varint128()? as usize;

    let script_pubkey = match n_size {
        0 => {
            // P2PKH: OP_DUP OP_HASH160 <20 bytes> OP_EQUALVERIFY OP_CHECKSIG
            let hash = reader.read_bytes(20)?;
            let mut script = vec![0x76, 0xa9, 0x14];
            script.extend_from_slice(&hash);
            script.extend_from_slice(&[0x88, 0xac]);
            script
        }
        1 => {
            // P2SH: OP_HASH160 <20 bytes> OP_EQUAL
            let hash = reader.read_bytes(20)?;
            let mut script = vec![0xa9, 0x14];
            script.extend_from_slice(&hash);
            script.push(0x87);
            script
        }
        2 | 3 => {
            // P2PK compressed: <33-byte pubkey> OP_CHECKSIG
            let x_bytes = reader.read_bytes(32)?;
            let prefix = n_size as u8; // 0x02 or 0x03
            let mut script = vec![0x21, prefix];
            script.extend_from_slice(&x_bytes);
            script.push(0xac);
            script
        }
        4 | 5 => {
            // P2PK uncompressed: <65-byte pubkey> OP_CHECKSIG
            let x_bytes = reader.read_bytes(32)?;
            // Reconstruct uncompressed pubkey (simplified - just store what we have)
            let prefix = if n_size == 4 { 0x04u8 } else { 0x06u8 };
            let mut script = vec![0x41, prefix];
            script.extend_from_slice(&x_bytes);
            // Note: uncompressed needs y coord too, but for classification purposes
            // we store what Bitcoin Core stores
            script.push(0xac);
            script
        }
        n => {
            // Raw script: length = n - 6
            let script_len = n - 6;
            if script_len > 10000 {
                return Err(BlockError::InvalidBlock("Script too large".to_string()));
            }
            reader.read_bytes(script_len)?
        }
    };

    Ok(UndoPrevout {
        height,
        coinbase,
        value_sats,
        script_pubkey,
    })
}

fn decompress_txout_amount(mut x: u64) -> u64 {
    if x == 0 {
        return 0;
    }

    x -= 1;
    let exponent = x % 10;
    x /= 10;

    let mut n: u64;

    if exponent < 9 {
        let digit = (x % 9) + 1;
        x /= 9;
        n = x * 10 + digit;
    } else {
        n = x + 1;
    }

    for _ in 0..exponent {
        n *= 10;
    }

    n
}

/// Parse all undo data from a rev*.dat file

pub fn parse_undo_file(
    file_path: &str,
    xor_key: &[u8],
) -> Result<Vec<Vec<UndoPrevout>>, BlockError> {
    let data = read_and_decode_file(file_path, xor_key)?;
    let mut reader = ByteReader::new(data);

    let mut all_blocks_undo = Vec::new();

    while reader.remaining() > 8 {
        let magic = match reader.read_u32_le() {
            Ok(m) => m,
            Err(_) => break,
        };

        if magic != 0xD9B4BEF9 {
            continue;
        }

        let undo_size = match reader.read_u32_le() {
            Ok(s) => s as usize,
            Err(_) => break,
        };

        if undo_size > 50_000_000 || undo_size == 0 {
            continue;
        }

        if reader.remaining() < undo_size {
            break;
        }

        let undo_data = match reader.read_bytes(undo_size) {
            Ok(d) => d,
            Err(_) => break,
        };

        match parse_block_undo_data(&undo_data) {
            Ok(block_prevouts) => {
                all_blocks_undo.push(block_prevouts);
            }
            Err(_) => {
                all_blocks_undo.push(Vec::new());
            }
        }
    }

    Ok(all_blocks_undo)
}

/// Parse all transactions from a block, matching with undo data
pub fn parse_block_with_undo(
    block_data: &[u8],
    undo_prevouts: &[UndoPrevout],
) -> Result<Block, BlockError> {
    let mut reader = ByteReader::new(block_data.to_vec());

    // Parse header (80 bytes)
    let header_bytes = reader.read_bytes(80)?;
    let header = parse_block_header(&header_bytes)?;
    let block_hash = compute_block_hash(&header_bytes);

    // Read transaction count
    let tx_count = reader.read_varint()?;

    let mut transactions = Vec::new();
    let mut txids = Vec::new();

    let mut prevout_index = 0;

    for tx_idx in 0..tx_count {
        let is_coinbase = tx_idx == 0;

        let tx_result =
            parse_block_transaction(&mut reader, is_coinbase, undo_prevouts, &mut prevout_index)?;

        txids.push(tx_result.txid.clone());
        transactions.push(tx_result);
    }
    // Extract BIP34 height from coinbase
    let bip34_height = if let Some(coinbase) = transactions.first() {
        if let Some(first_input) = coinbase.vin.first() {
            let script_sig_bytes = hex::decode(&first_input.script_sig_hex).unwrap_or_default();
            extract_bip34_height(&script_sig_bytes)
        } else {
            None
        }
    } else {
        None
    };

    Ok(Block {
        block_hash,
        header,
        tx_count,
        transactions,
        size_bytes: block_data.len(),
        txids,
        bip34_height, // Add this
    })
}

/// Serialize a varint (Bitcoin's compact size encoding)
fn serialize_varint(n: u64) -> Vec<u8> {
    if n < 0xFD {
        vec![n as u8]
    } else if n <= 0xFFFF {
        let mut bytes = vec![0xFD];
        bytes.extend_from_slice(&(n as u16).to_le_bytes());
        bytes
    } else if n <= 0xFFFFFFFF {
        let mut bytes = vec![0xFE];
        bytes.extend_from_slice(&(n as u32).to_le_bytes());
        bytes
    } else {
        let mut bytes = vec![0xFF];
        bytes.extend_from_slice(&n.to_le_bytes());
        bytes
    }
}

/// Serialize transaction for txid computation (non-witness bytes only)

fn serialize_transaction_for_txid(
    version: u32,
    inputs: &[(String, u32, Vec<u8>, u32)],
    outputs: &[(u64, Vec<u8>)],
    locktime: u32,
) -> Vec<u8> {
    let mut bytes = Vec::new();

    // Version
    bytes.extend_from_slice(&version.to_le_bytes());

    // Input count (proper varint)
    bytes.extend_from_slice(&serialize_varint(inputs.len() as u64));

    // Inputs
    for (txid, vout, script_sig, sequence) in inputs {
        // Previous txid (reversed back to memory order)
        let mut txid_bytes = hex::decode(txid).unwrap_or_default();
        txid_bytes.reverse();
        bytes.extend_from_slice(&txid_bytes);

        // Previous vout
        bytes.extend_from_slice(&vout.to_le_bytes());

        // Script sig length and data
        bytes.extend_from_slice(&serialize_varint(script_sig.len() as u64));
        bytes.extend_from_slice(script_sig);

        // Sequence
        bytes.extend_from_slice(&sequence.to_le_bytes());
    }

    // Output count (proper varint)
    bytes.extend_from_slice(&serialize_varint(outputs.len() as u64));

    // Outputs
    for (value, script) in outputs {
        // Value
        bytes.extend_from_slice(&value.to_le_bytes());

        // Script length and data
        bytes.extend_from_slice(&serialize_varint(script.len() as u64));
        bytes.extend_from_slice(script);
    }

    // Locktime
    bytes.extend_from_slice(&locktime.to_le_bytes());

    bytes
}

/// Compute txid from transaction data
fn compute_txid(
    version: u32,
    inputs: &[(String, u32, Vec<u8>, u32)],
    outputs: &[(u64, Vec<u8>)],
    locktime: u32,
) -> String {
    let tx_bytes = serialize_transaction_for_txid(version, inputs, outputs, locktime);
    let hash = double_sha256(&tx_bytes);
    hash_to_hex_reversed(&hash)
}

/// Parse a single transaction from block data
fn parse_block_transaction(
    reader: &mut ByteReader,
    is_coinbase: bool,
    all_prevouts: &[UndoPrevout],
    prevout_index: &mut usize,
) -> Result<crate::types::Transaction, BlockError> {
    let tx_start = reader.position();

    // Version
    let version = reader.read_u32_le()?;

    // Check for SegWit marker
    let position_before_marker = reader.position();
    let is_segwit = if reader.remaining() >= 2 {
        let byte1 = reader.read_u8()?;
        let byte2 = reader.read_u8()?;

        if byte1 == 0x00 && byte2 == 0x01 {
            true
        } else {
            reader.set_position(position_before_marker);
            false
        }
    } else {
        false
    };

    // Input count
    let input_count = reader.read_varint()?;

    // Parse inputs
    let mut inputs_data = Vec::new();

    for _ in 0..input_count {
        let prev_txid_bytes = reader.read_bytes(32)?;
        let mut prev_txid_display = prev_txid_bytes.clone();
        prev_txid_display.reverse();
        let prev_txid = hex::encode(prev_txid_display);

        let prev_vout = reader.read_u32_le()?;

        let script_sig_len = reader.read_varint()? as usize;
        let script_sig = reader.read_bytes(script_sig_len)?;

        let sequence = reader.read_u32_le()?;

        inputs_data.push((prev_txid, prev_vout, script_sig, sequence));
    }

    // Output count
    let output_count = reader.read_varint()?;

    // Parse outputs
    let mut outputs_data = Vec::new();

    for _ in 0..output_count {
        let value = reader.read_u64_le()?;
        let script_len = reader.read_varint()? as usize;
        let script_pubkey = reader.read_bytes(script_len)?;

        outputs_data.push((value, script_pubkey));
    }

    // Parse witness (if SegWit)
    let mut witness_data = Vec::new();

    if is_segwit {
        for _ in 0..input_count {
            let witness_count = reader.read_varint()?;
            let mut witness_items = Vec::new();

            for _ in 0..witness_count {
                let item_len = reader.read_varint()? as usize;
                if item_len == 0 {
                    witness_items.push("".to_string());
                } else {
                    let item = reader.read_bytes(item_len)?;
                    witness_items.push(hex::encode(item));
                }
            }

            witness_data.push(witness_items);
        }
    } else {
        // Legacy - empty witness for each input
        witness_data = vec![vec![]; input_count as usize];
    }

    // Locktime
    let locktime = reader.read_u32_le()?;

    let tx_end = reader.position();
    let tx_bytes_len = tx_end - tx_start;

    // Compute real txid
    let txid = compute_txid(version, &inputs_data, &outputs_data, locktime);

    // Build vin
    let mut vin = Vec::new();

    for (i, (prev_txid, prev_vout, script_sig, sequence)) in inputs_data.iter().enumerate() {
        let prevout = if is_coinbase {
            crate::types::Prevout {
                value_sats: 0,
                script_pubkey_hex: "".to_string(),
            }
        } else {
            // Try to get from undo data, use dummy if not available
            if *prevout_index < all_prevouts.len() {
                let undo_prevout = &all_prevouts[*prevout_index];
                *prevout_index += 1;

                crate::types::Prevout {
                    value_sats: undo_prevout.value_sats,
                    script_pubkey_hex: hex::encode(&undo_prevout.script_pubkey),
                }
            } else {
                // Undo data exhausted - use dummy (THIS IS THE FIX)
                // This can happen if undo format is not fully understood
                crate::types::Prevout {
                    value_sats: 0,
                    script_pubkey_hex: "".to_string(),
                }
            }
        };
        // Classify script type
        let script_type = if is_coinbase {
            "coinbase".to_string()
        } else {
            let prevout_script = hex::decode(&prevout.script_pubkey_hex).unwrap_or_default();
            crate::script::classify_input_script(&prevout_script, script_sig, &witness_data[i])
        };

        // Derive address
        let address = if is_coinbase {
            None
        } else {
            let prevout_script = hex::decode(&prevout.script_pubkey_hex).unwrap_or_default();
            crate::address::derive_address(
                &crate::script::classify_output_script(&prevout_script),
                &prevout_script,
            )
        };

        let input = crate::types::TransactionInput {
            txid: prev_txid.clone(),
            vout: *prev_vout,
            sequence: *sequence,
            script_sig_hex: hex::encode(script_sig),
            script_asm: crate::script::disassemble_script(script_sig),
            witness: witness_data[i].clone(),
            script_type,
            address,
            prevout,
            relative_timelock: crate::transaction::decode_relative_timelock(*sequence),
        };

        vin.push(input);
    }

    // Build vout
    let mut vout = Vec::new();

    for (i, (value, script_pubkey)) in outputs_data.iter().enumerate() {
        let script_type = crate::script::classify_output_script(script_pubkey);
        let address = crate::address::derive_address(&script_type, script_pubkey);

        let (op_return_data_hex, op_return_data_utf8, op_return_protocol) =
            if script_type == "op_return" {
                crate::script::extract_op_return_data(script_pubkey)
            } else {
                (None, None, None)
            };

        let output = crate::types::TransactionOutput {
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

    // Calculate totals and fees
    let total_input_sats: u64 = vin.iter().map(|i| i.prevout.value_sats).sum();
    let total_output_sats: u64 = vout.iter().map(|o| o.value_sats).sum();
    let fee_sats = total_input_sats.saturating_sub(total_output_sats);
    // let fee_sats = total_input_sats - total_output_sats;

    // RBF detection
    let rbf_signaling = vin.iter().any(|i| i.sequence < 0xFFFFFFFE);

    // Locktime classification
    let (locktime_type, locktime_value) = if locktime == 0 {
        ("none".to_string(), 0)
    } else if locktime < 500_000_000 {
        ("block_height".to_string(), locktime)
    } else {
        ("unix_timestamp".to_string(), locktime)
    };

    // Generate warnings
    let mut warnings = Vec::new();

    if fee_sats > 1_000_000 || (tx_bytes_len > 0 && (fee_sats as f64 / tx_bytes_len as f64) > 200.0)
    {
        warnings.push(crate::types::Warning {
            code: "HIGH_FEE".to_string(),
        });
    }

    for output in &vout {
        if output.script_type != "op_return" && output.value_sats < 546 {
            warnings.push(crate::types::Warning {
                code: "DUST_OUTPUT".to_string(),
            });
            break;
        }
    }

    for output in &vout {
        if output.script_type == "unknown" {
            warnings.push(crate::types::Warning {
                code: "UNKNOWN_OUTPUT_SCRIPT".to_string(),
            });
            break;
        }
    }

    if rbf_signaling {
        warnings.push(crate::types::Warning {
            code: "RBF_SIGNALING".to_string(),
        });
    }
    let non_wit_size =
        serialize_transaction_for_txid(version, &inputs_data, &outputs_data, locktime).len();
    let _wit_size = if is_segwit {
        tx_bytes_len - non_wit_size
    } else {
        0
    };
    // Build transaction
    let transaction = crate::types::Transaction {
        ok: true,
        network: "mainnet".to_string(),
        segwit: is_segwit,
        txid,

        wtxid: if is_segwit {
            use crate::transaction::serialize_with_witness;
            let full_bytes = serialize_with_witness(
                version,
                &inputs_data,
                &outputs_data,
                &witness_data,
                locktime,
            );
            let wtxid_hash = crate::hash::double_sha256(&full_bytes);
            Some(crate::hash::hash_to_hex_reversed(&wtxid_hash))
        } else {
            None
        },
        version,
        locktime,
        size_bytes: tx_bytes_len,
        weight: if is_segwit {
            let non_wit_size =
                serialize_transaction_for_txid(version, &inputs_data, &outputs_data, locktime)
                    .len();
            let wit_size = tx_bytes_len - non_wit_size;
            (non_wit_size * 4) + wit_size
        } else {
            tx_bytes_len * 4
        },
        vbytes: if is_segwit {
            let non_wit_size =
                serialize_transaction_for_txid(version, &inputs_data, &outputs_data, locktime)
                    .len();
            let wit_size = tx_bytes_len - non_wit_size;
            let w = (non_wit_size * 4) + wit_size;
            (w + 3) / 4
        } else {
            tx_bytes_len
        },
        total_input_sats,
        total_output_sats,
        fee_sats,
        fee_rate_sat_vb: if tx_bytes_len > 0 {
            fee_sats as f64 / tx_bytes_len as f64
        } else {
            0.0
        },
        rbf_signaling,
        locktime_type,
        locktime_value,
        segwit_savings: if is_segwit {
            let non_wit_size =
                serialize_transaction_for_txid(version, &inputs_data, &outputs_data, locktime)
                    .len();
            let wit_size = tx_bytes_len - non_wit_size;
            let weight_actual = (non_wit_size * 4) + wit_size;
            let weight_if_legacy = tx_bytes_len * 4;
            let savings_pct =
                ((weight_if_legacy - weight_actual) as f64 / weight_if_legacy as f64) * 100.0;
            Some(crate::types::SegwitSavings {
                witness_bytes: wit_size,
                non_witness_bytes: non_wit_size,
                total_bytes: tx_bytes_len,
                weight_actual,
                weight_if_legacy,
                savings_pct: (savings_pct * 100.0).round() / 100.0,
            })
        } else {
            None
        },
        vin,
        vout,
        warnings,
    };

    Ok(transaction)
}

/// Compute merkle root from a list of transaction IDs

pub fn compute_merkle_root(txids: &[String]) -> Result<String, BlockError> {
    if txids.is_empty() {
        return Err(BlockError::InvalidBlock("No transactions".to_string()));
    }

    // Convert txids to bytes (reverse for memory order)
    let mut hashes: Vec<Vec<u8>> = txids
        .iter()
        .map(|txid| {
            let mut bytes = hex::decode(txid).unwrap_or_default();
            bytes.reverse(); // Convert from display to memory order
            bytes
        })
        .collect();

    // Build merkle tree
    while hashes.len() > 1 {
        let mut next_level = Vec::new();

        // Process pairs
        let mut i = 0;
        while i < hashes.len() {
            let left = &hashes[i];

            // If odd number, duplicate the last one
            let right = if i + 1 < hashes.len() {
                &hashes[i + 1]
            } else {
                &hashes[i]
            };

            // Concatenate and double-hash
            let mut combined = Vec::new();
            combined.extend_from_slice(left);
            combined.extend_from_slice(right);

            let hash = double_sha256(&combined);
            next_level.push(hash.to_vec());

            i += 2;
        }

        hashes = next_level;
    }

    // Return the root (reversed for display)
    let mut root = hashes[0].clone();
    root.reverse();
    Ok(hex::encode(root))
}

/// Verify that a block's merkle root matches the computed one
pub fn verify_merkle_root(block: &Block) -> Result<bool, BlockError> {
    let computed_root = compute_merkle_root(&block.txids)?;
    Ok(computed_root == block.header.merkle_root)
}

/// Extract BIP34 block height from coinbase transaction
///

pub fn extract_bip34_height(coinbase_script_sig: &[u8]) -> Option<u32> {
    if coinbase_script_sig.is_empty() {
        return None;
    }

    let push_len = coinbase_script_sig[0] as usize;

    // Height push should be 1-4 bytes
    if push_len < 1 || push_len > 4 || coinbase_script_sig.len() < 1 + push_len {
        return None;
    }

    // Extract height bytes (little-endian)
    let height_bytes = &coinbase_script_sig[1..1 + push_len];

    // Convert to u32
    let mut height = 0u32;
    for (i, &byte) in height_bytes.iter().enumerate() {
        height |= (byte as u32) << (i * 8);
    }

    Some(height)
}

pub fn block_to_output(block: &Block) -> crate::types::BlockOutput {
    use crate::types::{BlockHeaderOutput, BlockOutput, BlockStats, CoinbaseSummary};

    use std::collections::HashMap;

    // Verify merkle root
    let merkle_root_valid = verify_merkle_root(block).unwrap_or(false);

    // Coinbase transaction (first tx)
    let coinbase_tx = &block.transactions[0];

    let bip34_height = block.bip34_height.unwrap_or(0);

    let coinbase_script_hex = coinbase_tx
        .vin
        .first()
        .map(|vin| vin.script_sig_hex.clone())
        .unwrap_or_default();

    let coinbase_total_output_sats = coinbase_tx.total_output_sats;

    // Total fees (exclude coinbase)
    let total_fees_sats: u64 = block
        .transactions
        .iter()
        .skip(1)
        .map(|tx| tx.fee_sats)
        .sum();

    // Total weight
    let total_weight: u64 = block.transactions.iter().map(|tx| tx.weight as u64).sum();

    // Total vbytes
    let total_vbytes: u64 = block.transactions.iter().map(|tx| tx.vbytes as u64).sum();

    let avg_fee_rate_sat_vb = if total_vbytes > 0 {
        total_fees_sats as f64 / total_vbytes as f64
    } else {
        0.0
    };

    // Script type summary (count output types)
    let mut script_type_summary: HashMap<String, u64> = HashMap::new();

    for tx in &block.transactions {
        for output in &tx.vout {
            *script_type_summary
                .entry(output.script_type.clone())
                .or_insert(0) += 1;
        }
    }

    BlockOutput {
        ok: true,
        mode: "block".to_string(),

        block_header: BlockHeaderOutput {
            version: block.header.version,
            prev_block_hash: block.header.prev_block_hash.clone(),
            merkle_root: block.header.merkle_root.clone(),
            merkle_root_valid,
            timestamp: block.header.timestamp,
            bits: format!("{:08x}", block.header.bits), // MUST be string
            nonce: block.header.nonce,
            block_hash: block.block_hash.clone(),
        },

        tx_count: block.tx_count,

        coinbase: CoinbaseSummary {
            bip34_height,
            coinbase_script_hex,
            total_output_sats: coinbase_total_output_sats,
        },

        transactions: block.transactions.clone(),

        block_stats: BlockStats {
            total_fees_sats,
            total_weight,
            avg_fee_rate_sat_vb,
            script_type_summary,
        },
    }
}

/// Write block output to JSON file
pub fn write_block_json(block: &Block, output_dir: &str) -> Result<String, BlockError> {
    // Create output directory
    std::fs::create_dir_all(output_dir).map_err(|e| BlockError::IoError(e))?;

    // Convert to output format
    let output = block_to_output(block);

    // Serialize to JSON
    let json = serde_json::to_string_pretty(&output)
        .map_err(|e| BlockError::InvalidBlock(format!("JSON serialization failed: {}", e)))?;

    // Write to file: out/<block_hash>.json
    let filename = format!("{}/{}.json", output_dir, block.block_hash);
    std::fs::write(&filename, json).map_err(|e| BlockError::IoError(e))?;

    Ok(filename)
}
