# Chain Lens — Bitcoin Transaction Analyzer

A high-performance Bitcoin transaction and block analyzer built in Rust.
Parses raw Bitcoin transactions and block data, computes all fields from
scratch, and exposes results via a clean web UI and REST API.

## Features

- Parse raw Bitcoin transactions (legacy & SegWit)
- Compute txid, wtxid, weight, vbytes, fee, fee rate
- Classify script types — P2PKH, P2SH, P2WPKH, P2WSH, P2TR, OP_RETURN
- Derive addresses (Base58, Bech32, Bech32m)
- Decode BIP68 relative timelocks and absolute locktimes
- Detect RBF signaling, dust outputs, high fees, unknown scripts
- Parse raw block files (blk*.dat) with undo data (rev*.dat)
- Verify Merkle root integrity
- Extract BIP34 coinbase height
- SegWit savings visualization (actual weight vs hypothetical legacy weight)
- Structured JSON output via REST API

## Tech Stack

- **Rust** — core parsing engine
- **Axum** — async web framework
- **Tokio** — async runtime
- **Serde** — JSON serialization
- **Bech32 / BS58** — address encoding

## Getting Started

### Prerequisites
- Rust (latest stable)

### Run the web UI
```bash
bash setup.sh
bash web.sh
```
Then open `http://127.0.0.1:3000` in your browser.

### Run the CLI
```bash
# Single transaction
bash cli.sh fixtures/transactions/tx_segwit_p2wpkh_p2tr.json

# Block mode
bash cli.sh --block fixtures/blocks/blk04330.dat \
            fixtures/blocks/rev04330.dat \
            fixtures/blocks/xor.dat
```

## API

### `GET /api/health`
Returns `{ "ok": true }` if the server is running.

### `POST /api/analyze`
```json
{
  "raw_tx": "<hex>",
  "prevouts": [
    {
      "txid": "<hex>",
      "vout": 0,
      "value_sats": 100000,
      "script_pubkey_hex": "<hex>"
    }
  ]
}
```

## Project Structure
```
crates/
  core/        # Bitcoin parsing logic
    transaction.rs   # Transaction parser
    block.rs         # Block parser
    script.rs        # Script classification & disassembly
    address.rs       # Address derivation
    hash.rs          # SHA256, RIPEMD160, double SHA256
    reader.rs        # Byte cursor for binary parsing
    types.rs         # Shared data types
  web/         # Axum web server
  cli/         # Command-line interface
```

## Author

Built by [Siddharth](https://github.com/Dsiddhart)