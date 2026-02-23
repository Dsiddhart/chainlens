pub fn classify_output_script(script_bytes: &[u8]) -> String {
    let len = script_bytes.len();

    // Check each pattern in order

    // P2PKH: OP_DUP OP_HASH160 <20 bytes> OP_EQUALVERIFY OP_CHECKSIG
    // Hex: 76 a9 14 [20 bytes] 88 ac
    // Total length: 25 bytes
    if len == 25
        && script_bytes[0] == 0x76  // OP_DUP
        && script_bytes[1] == 0xa9  // OP_HASH160
        && script_bytes[2] == 0x14  // push 20 bytes
        && script_bytes[23] == 0x88 // OP_EQUALVERIFY
        && script_bytes[24] == 0xac
    // OP_CHECKSIG
    {
        return "p2pkh".to_string();
    }

    // P2SH: OP_HASH160 <20 bytes> OP_EQUAL
    // Hex: a9 14 [20 bytes] 87
    // Total length: 23 bytes
    if len == 23
        && script_bytes[0] == 0xa9  // OP_HASH160
        && script_bytes[1] == 0x14  // push 20 bytes
        && script_bytes[22] == 0x87
    // OP_EQUAL
    {
        return "p2sh".to_string();
    }

    // P2WPKH: OP_0 <20 bytes>
    // Hex: 00 14 [20 bytes]
    // Total length: 22 bytes
    if len == 22
        && script_bytes[0] == 0x00  // OP_0
        && script_bytes[1] == 0x14
    // push 20 bytes
    {
        return "p2wpkh".to_string();
    }

    // P2WSH: OP_0 <32 bytes>
    // Hex: 00 20 [32 bytes]
    // Total length: 34 bytes
    if len == 34
        && script_bytes[0] == 0x00  // OP_0
        && script_bytes[1] == 0x20
    // push 32 bytes
    {
        return "p2wsh".to_string();
    }

    // P2TR (Taproot): OP_1 <32 bytes>
    // Hex: 51 20 [32 bytes]
    // Total length: 34 bytes
    if len == 34
        && script_bytes[0] == 0x51  // OP_1
        && script_bytes[1] == 0x20
    // push 32 bytes
    {
        return "p2tr".to_string();
    }

    // OP_RETURN: starts with OP_RETURN (0x6a)
    // Can be any length
    if len > 0 && script_bytes[0] == 0x6a {
        return "op_return".to_string();
    }

    // If none of the above, it's unknown
    "unknown".to_string()
}

pub fn extract_op_return_data(
    script_bytes: &[u8],
) -> (Option<String>, Option<String>, Option<String>) {
    // OP_RETURN outputs start with 0x6a
    if script_bytes.is_empty() || script_bytes[0] != 0x6a {
        return (None, None, None);
    }

    // Skip the OP_RETURN opcode
    let mut pos = 1;
    let mut all_data = Vec::new();

    // Parse all push opcodes after OP_RETURN
    while pos < script_bytes.len() {
        let opcode = script_bytes[pos];
        pos += 1;

        
        let data_len = if opcode >= 0x01 && opcode <= 0x4b {
            // Direct push: opcode itself is the length
            opcode as usize
        } else if opcode == 0x4c {
            // OP_PUSHDATA1: next 1 byte is length
            if pos >= script_bytes.len() {
                break;
            }
            let len = script_bytes[pos] as usize;
            pos += 1;
            len
        } else if opcode == 0x4d {
            // OP_PUSHDATA2: next 2 bytes are length (little-endian)
            if pos + 1 >= script_bytes.len() {
                break;
            }
            let len = u16::from_le_bytes([script_bytes[pos], script_bytes[pos + 1]]) as usize;
            pos += 2;
            len
        } else if opcode == 0x4e {
            // OP_PUSHDATA4: next 4 bytes are length (little-endian)
            if pos + 3 >= script_bytes.len() {
                break;
            }
            let len = u32::from_le_bytes([
                script_bytes[pos],
                script_bytes[pos + 1],
                script_bytes[pos + 2],
                script_bytes[pos + 3],
            ]) as usize;
            pos += 4;
            len
        } else {
            // Unknown opcode or OP_0 
            break;
        };

        // Read the data bytes
        if pos + data_len > script_bytes.len() {
            break;
        }
        all_data.extend_from_slice(&script_bytes[pos..pos + data_len]);
        pos += data_len;
    }

    
    if all_data.is_empty() {
        return (
            Some("".to_string()),
            Some("".to_string()),
            Some("unknown".to_string()),
        );
    }

   
    let data_hex = hex::encode(&all_data);

    let data_utf8 = String::from_utf8(all_data.clone()).ok();


    let protocol = if all_data.len() >= 4 {
        let prefix = &all_data[0..4];
        if prefix == b"omni" {
            // 0x6f6d6e69
            "omni".to_string()
        } else if all_data.len() >= 5 && &all_data[0..5] == &[0x01, 0x09, 0xf9, 0x11, 0x02] {
            "opentimestamps".to_string()
        } else {
            "unknown".to_string()
        }
    } else {
        "unknown".to_string()
    };

    (Some(data_hex), data_utf8, Some(protocol))
}

pub fn classify_input_script(
    prevout_script_pubkey: &[u8],
    script_sig: &[u8],
    witness: &[String],
) -> String {
    // First, classify the prevout (what we're spending)
    let prevout_type = classify_output_script(prevout_script_pubkey);

    match prevout_type.as_str() {
        "p2pkh" => {
            // P2PKH input: scriptSig has sig + pubkey, no witness
            "p2pkh".to_string()
        }

        "p2sh" => {

            if script_sig.is_empty() {
                return "unknown".to_string();
            }


            if !witness.is_empty() {
                // Check witness count to determine type
                if witness.len() == 2 {
                    // P2WPKH witness: [sig, pubkey]
                    "p2sh-p2wpkh".to_string()
                } else {
                    // P2WSH witness: [items..., witnessScript]
                    "p2sh-p2wsh".to_string()
                }
            } else {

                if let Some(redeem_script) = extract_last_push(script_sig) {
                    let redeem_type = classify_output_script(&redeem_script);
                    match redeem_type.as_str() {
                        "p2wpkh" => "p2sh-p2wpkh".to_string(),
                        "p2wsh" => "p2sh-p2wsh".to_string(),
                        _ => "unknown".to_string(),
                    }
                } else {
                    "unknown".to_string()
                }
            }
        }

        "p2wpkh" => {
            "p2wpkh".to_string()
        }

        "p2wsh" => {
            "p2wsh".to_string()
        }

        "p2tr" => {
            if witness.len() == 1 {
                // Single witness item = keypath spend (just a signature)
                "p2tr_keypath".to_string()
            } else {
                // Multiple witness items = scriptpath spend
                "p2tr_scriptpath".to_string()
            }
        }

        _ => "unknown".to_string(),
    }
}


fn extract_last_push(script: &[u8]) -> Option<Vec<u8>> {
    let mut i = 0;
    let mut last_push: Option<Vec<u8>> = None;

    while i < script.len() {
        let opcode = script[i];
        i += 1;

        let data = if opcode == 0x00 {
            // OP_0: pushes empty bytes
            Some(vec![])
        } else if opcode >= 0x01 && opcode <= 0x4b {
            // Direct push: next `opcode` bytes
            let len = opcode as usize;
            if i + len > script.len() {
                return last_push;
            }
            let d = script[i..i + len].to_vec();
            i += len;
            Some(d)
        } else if opcode == 0x4c {
            // OP_PUSHDATA1
            if i >= script.len() {
                return last_push;
            }
            let len = script[i] as usize;
            i += 1;
            if i + len > script.len() {
                return last_push;
            }
            let d = script[i..i + len].to_vec();
            i += len;
            Some(d)
        } else if opcode == 0x4d {
            // OP_PUSHDATA2
            if i + 2 > script.len() {
                return last_push;
            }
            let len = u16::from_le_bytes([script[i], script[i + 1]]) as usize;
            i += 2;
            if i + len > script.len() {
                return last_push;
            }
            let d = script[i..i + len].to_vec();
            i += len;
            Some(d)
        } else if opcode == 0x4e {
            // OP_PUSHDATA4
            if i + 4 > script.len() {
                return last_push;
            }
            let len = u32::from_le_bytes([script[i], script[i + 1], script[i + 2], script[i + 3]])
                as usize;
            i += 4;
            if i + len > script.len() {
                return last_push;
            }
            let d = script[i..i + len].to_vec();
            i += len;
            Some(d)
        } else {
            // Non-push opcode, no data
            None
        };

        if let Some(push) = data {
            last_push = Some(push);
        }
    }

    last_push
}


pub fn disassemble_script(script_bytes: &[u8]) -> String {
    if script_bytes.is_empty() {
        return "".to_string();
    }

    let mut tokens = Vec::new();
    let mut pos = 0;

    while pos < script_bytes.len() {
        let opcode = script_bytes[pos];
        pos += 1;

        match opcode {
            // OP_0
            0x00 => tokens.push("OP_0".to_string()),

            // Direct push (0x01-0x4b): opcode itself is the length
            0x01..=0x4b => {
                let len = opcode as usize;
                if pos + len <= script_bytes.len() {
                    let data = hex::encode(&script_bytes[pos..pos + len]);
                    tokens.push(format!("OP_PUSHBYTES_{} {}", len, data));
                    pos += len;
                } else {
                    tokens.push(format!("OP_PUSHBYTES_{} <truncated>", len));
                    break;
                }
            }

            // OP_PUSHDATA1
            0x4c => {
                if pos < script_bytes.len() {
                    let len = script_bytes[pos] as usize;
                    pos += 1;
                    if pos + len <= script_bytes.len() {
                        let data = hex::encode(&script_bytes[pos..pos + len]);
                        tokens.push(format!("OP_PUSHDATA1 {}", data));
                        pos += len;
                    } else {
                        tokens.push("OP_PUSHDATA1 <truncated>".to_string());
                        break;
                    }
                } else {
                    tokens.push("OP_PUSHDATA1 <incomplete>".to_string());
                    break;
                }
            }

            // OP_PUSHDATA2
            0x4d => {
                if pos + 1 < script_bytes.len() {
                    let len =
                        u16::from_le_bytes([script_bytes[pos], script_bytes[pos + 1]]) as usize;
                    pos += 2;
                    if pos + len <= script_bytes.len() {
                        let data = hex::encode(&script_bytes[pos..pos + len]);
                        tokens.push(format!("OP_PUSHDATA2 {}", data));
                        pos += len;
                    } else {
                        tokens.push("OP_PUSHDATA2 <truncated>".to_string());
                        break;
                    }
                } else {
                    tokens.push("OP_PUSHDATA2 <incomplete>".to_string());
                    break;
                }
            }

            // OP_PUSHDATA4
            0x4e => {
                if pos + 3 < script_bytes.len() {
                    let len = u32::from_le_bytes([
                        script_bytes[pos],
                        script_bytes[pos + 1],
                        script_bytes[pos + 2],
                        script_bytes[pos + 3],
                    ]) as usize;
                    pos += 4;
                    if pos + len <= script_bytes.len() {
                        let data = hex::encode(&script_bytes[pos..pos + len]);
                        tokens.push(format!("OP_PUSHDATA4 {}", data));
                        pos += len;
                    } else {
                        tokens.push("OP_PUSHDATA4 <truncated>".to_string());
                        break;
                    }
                } else {
                    tokens.push("OP_PUSHDATA4 <incomplete>".to_string());
                    break;
                }
            }

            // OP_1NEGATE
            0x4f => tokens.push("OP_1NEGATE".to_string()),

            // OP_1 through OP_16
            0x51..=0x60 => tokens.push(format!("OP_{}", opcode - 0x50)),

            // Standard opcodes
            0x61 => tokens.push("OP_NOP".to_string()),
            0x63 => tokens.push("OP_IF".to_string()),
            0x64 => tokens.push("OP_NOTIF".to_string()),
            0x67 => tokens.push("OP_ELSE".to_string()),
            0x68 => tokens.push("OP_ENDIF".to_string()),
            0x69 => tokens.push("OP_VERIFY".to_string()),
            0x6a => tokens.push("OP_RETURN".to_string()),

            // Stack ops
            0x6b => tokens.push("OP_TOALTSTACK".to_string()),
            0x6c => tokens.push("OP_FROMALTSTACK".to_string()),
            0x6d => tokens.push("OP_2DROP".to_string()),
            0x6e => tokens.push("OP_2DUP".to_string()),
            0x6f => tokens.push("OP_3DUP".to_string()),
            0x70 => tokens.push("OP_2OVER".to_string()),
            0x71 => tokens.push("OP_2ROT".to_string()),
            0x72 => tokens.push("OP_2SWAP".to_string()),
            0x73 => tokens.push("OP_IFDUP".to_string()),
            0x74 => tokens.push("OP_DEPTH".to_string()),
            0x75 => tokens.push("OP_DROP".to_string()),
            0x76 => tokens.push("OP_DUP".to_string()),
            0x77 => tokens.push("OP_NIP".to_string()),
            0x78 => tokens.push("OP_OVER".to_string()),
            0x79 => tokens.push("OP_PICK".to_string()),
            0x7a => tokens.push("OP_ROLL".to_string()),
            0x7b => tokens.push("OP_ROT".to_string()),
            0x7c => tokens.push("OP_SWAP".to_string()),
            0x7d => tokens.push("OP_TUCK".to_string()),

            // Splice ops
            0x7e => tokens.push("OP_CAT".to_string()),
            0x7f => tokens.push("OP_SUBSTR".to_string()),
            0x80 => tokens.push("OP_LEFT".to_string()),
            0x81 => tokens.push("OP_RIGHT".to_string()),
            0x82 => tokens.push("OP_SIZE".to_string()),

            // Bitwise logic
            0x83 => tokens.push("OP_INVERT".to_string()),
            0x84 => tokens.push("OP_AND".to_string()),
            0x85 => tokens.push("OP_OR".to_string()),
            0x86 => tokens.push("OP_XOR".to_string()),
            0x87 => tokens.push("OP_EQUAL".to_string()),
            0x88 => tokens.push("OP_EQUALVERIFY".to_string()),

            // Numeric ops
            0x8b => tokens.push("OP_1ADD".to_string()),
            0x8c => tokens.push("OP_1SUB".to_string()),
            0x8f => tokens.push("OP_NEGATE".to_string()),
            0x90 => tokens.push("OP_ABS".to_string()),
            0x91 => tokens.push("OP_NOT".to_string()),
            0x92 => tokens.push("OP_0NOTEQUAL".to_string()),
            0x93 => tokens.push("OP_ADD".to_string()),
            0x94 => tokens.push("OP_SUB".to_string()),
            0x9a => tokens.push("OP_BOOLAND".to_string()),
            0x9b => tokens.push("OP_BOOLOR".to_string()),
            0x9c => tokens.push("OP_NUMEQUAL".to_string()),
            0x9d => tokens.push("OP_NUMEQUALVERIFY".to_string()),
            0x9e => tokens.push("OP_NUMNOTEQUAL".to_string()),
            0x9f => tokens.push("OP_LESSTHAN".to_string()),
            0xa0 => tokens.push("OP_GREATERTHAN".to_string()),
            0xa1 => tokens.push("OP_LESSTHANOREQUAL".to_string()),
            0xa2 => tokens.push("OP_GREATERTHANOREQUAL".to_string()),
            0xa3 => tokens.push("OP_MIN".to_string()),
            0xa4 => tokens.push("OP_MAX".to_string()),
            0xa5 => tokens.push("OP_WITHIN".to_string()),

            // Crypto ops
            0xa6 => tokens.push("OP_RIPEMD160".to_string()),
            0xa7 => tokens.push("OP_SHA1".to_string()),
            0xa8 => tokens.push("OP_SHA256".to_string()),
            0xa9 => tokens.push("OP_HASH160".to_string()),
            0xaa => tokens.push("OP_HASH256".to_string()),
            0xab => tokens.push("OP_CODESEPARATOR".to_string()),
            0xac => tokens.push("OP_CHECKSIG".to_string()),
            0xad => tokens.push("OP_CHECKSIGVERIFY".to_string()),
            0xae => tokens.push("OP_CHECKMULTISIG".to_string()),
            0xaf => tokens.push("OP_CHECKMULTISIGVERIFY".to_string()),

            // Locktime
            0xb1 => tokens.push("OP_CHECKLOCKTIMEVERIFY".to_string()),
            0xb2 => tokens.push("OP_CHECKSEQUENCEVERIFY".to_string()),

            // Unknown opcode
            _ => tokens.push(format!("OP_UNKNOWN_{:#04x}", opcode)),
        }
    }

    tokens.join(" ")
}

