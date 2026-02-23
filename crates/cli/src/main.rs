// main.rs - CLI entry point
//
// Reads a transaction fixture, parses it, and outputs JSON.
// Usage: btc-cli <fixture.json>

use std::env;
use std::fs;
use std::process;

fn main() {
    // Get command line arguments
    let args: Vec<String> = env::args().collect();
    
    // We expect: program_name <fixture_path>
    if args.len() != 2 {
        eprintln!("Usage: {} <fixture.json>", args[0]);
        eprintln!(r#"{{"ok":false,"error":{{"code":"INVALID_ARGS","message":"Expected fixture file path"}}}}"#);
        process::exit(1);
    }
    
    let fixture_path = &args[1];
    
    // Run the parser and handle result
    match run_parser(fixture_path) {
        Ok(()) => process::exit(0),
        Err(err) => {
            eprintln!("Error: {}", err);
            process::exit(1);
        }
    }
}

/// Main parsing logic
fn run_parser(fixture_path: &str) -> Result<(), String> {
    
    // Read the fixture file
    let fixture_content = fs::read_to_string(fixture_path)
        .map_err(|e| {
            let error_json = serde_json::json!({
                "ok": false,
                "error": {
                    "code": "FILE_NOT_FOUND",
                    "message": format!("Could not read fixture file: {}", e)
                }
            });
            eprintln!("{}", serde_json::to_string(&error_json).unwrap());
            format!("Could not read fixture file: {}", e)
        })?;
    
    // Parse the fixture JSON
    let fixture: serde_json::Value = serde_json::from_str(&fixture_content)
        .map_err(|e| {
            let error_json = serde_json::json!({
                "ok": false,
                "error": {
                    "code": "INVALID_JSON",
                    "message": format!("Invalid fixture JSON: {}", e)
                }
            });
            eprintln!("{}", serde_json::to_string(&error_json).unwrap());
            format!("Invalid fixture JSON: {}", e)
        })?;
    
    // Extract fields from fixture
    let raw_tx = fixture["raw_tx"]
        .as_str()
        .ok_or_else(|| {
            let error_json = serde_json::json!({
                "ok": false,
                "error": {
                    "code": "INVALID_FIXTURE",
                    "message": "Fixture missing 'raw_tx' field"
                }
            });
            eprintln!("{}", serde_json::to_string(&error_json).unwrap());
            "Fixture missing 'raw_tx' field".to_string()
        })?;
    
    let prevouts = fixture["prevouts"]
        .as_array()
        .ok_or_else(|| {
            let error_json = serde_json::json!({
                "ok": false,
                "error": {
                    "code": "INVALID_FIXTURE",
                    "message": "Fixture missing 'prevouts' array"
                }
            });
            eprintln!("{}", serde_json::to_string(&error_json).unwrap());
            "Fixture missing 'prevouts' array".to_string()
        })?;
    
    // Parse the transaction using our core library
    let transaction = btc_core::transaction::parse_raw_transaction(raw_tx, prevouts)
        .map_err(|e| {
            let error_json = serde_json::json!({
                "ok": false,
                "error": {
                    "code": "PARSE_ERROR",
                    "message": format!("Failed to parse transaction: {:?}", e)
                }
            });
            eprintln!("{}", serde_json::to_string(&error_json).unwrap());
            format!("Failed to parse transaction: {:?}", e)
        })?;
    
    // Serialize to JSON
    let output_json = serde_json::to_string_pretty(&transaction)
        .map_err(|e| format!("Failed to serialize JSON: {}", e))?;
    
    // Create output directory
    fs::create_dir_all("out")
        .map_err(|e| format!("Failed to create out/ directory: {}", e))?;
    
    // Write to out/<txid>.json
    let output_filename = format!("out/{}.json", transaction.txid);
    fs::write(&output_filename, &output_json)
        .map_err(|e| format!("Failed to write output file: {}", e))?;
    
    // Print to stdout (README Section 4 requirement for single-tx mode)
    println!("{}", output_json);
    
    Ok(())
}