use serde::{Serialize,Deserialize};


use std::collections::HashMap;

#[derive(Debug, Serialize)]
pub struct BlockOutput {
    pub ok: bool,
    pub mode: String,
    pub block_header: BlockHeaderOutput,
    pub tx_count: u64,
    pub coinbase: CoinbaseSummary,
    pub transactions: Vec<Transaction>,
    pub block_stats: BlockStats,
}

#[derive(Debug, Serialize)]
pub struct BlockHeaderOutput {
    pub version: u32,
    pub prev_block_hash: String,
    pub merkle_root: String,
    pub merkle_root_valid: bool,
    pub timestamp: u32,
    pub bits: String,    
    pub nonce: u32,
    pub block_hash: String,
}

#[derive(Debug, Serialize)]
pub struct CoinbaseSummary {
    pub bip34_height: u32,
    pub coinbase_script_hex: String,
    pub total_output_sats: u64,
}

#[derive(Debug, Serialize)]
pub struct BlockStats {
    pub total_fees_sats: u64,
    pub total_weight: u64,
    pub avg_fee_rate_sat_vb: f64,
    pub script_type_summary: HashMap<String, u64>,
}
#[derive(Debug,Serialize)]
#[derive(Clone)]
pub struct Transaction {
    pub ok: bool,
    pub network: String,
    pub segwit: bool,
    pub txid:String,
    pub wtxid: Option<String>,
    pub version:u32,
    pub locktime: u32,
    pub size_bytes: usize,
    pub weight: usize,
    pub vbytes: usize,
    pub total_input_sats: u64,
    pub total_output_sats: u64,
    pub fee_sats: u64,
    pub fee_rate_sat_vb: f64,
    pub rbf_signaling: bool,
    pub locktime_type: String,
    pub locktime_value: u32,  
    #[serde(skip_serializing_if = "Option::is_none")]
    pub segwit_savings: Option<SegwitSavings>,
    pub vin: Vec<TransactionInput>,
    pub vout: Vec<TransactionOutput>,
    pub warnings: Vec<Warning>,      
}
#[derive(Debug, Serialize)]
#[derive(Clone)]
pub struct TransactionInput {
    pub txid: String,
    pub vout: u32,
    pub sequence: u32,
    pub script_sig_hex: String,
    pub script_asm: String,
    pub witness: Vec<String>,
    pub script_type: String,
    pub address: Option<String>,
    pub prevout: Prevout,
    pub relative_timelock: RelativeTimelock,

}
#[derive(Debug,Serialize)]
#[derive(Clone)]
pub struct TransactionOutput {
    pub n: u32,
    pub value_sats: u64,
    pub script_pubkey_hex: String,
    pub script_asm: String,
    pub script_type: String,
    pub address:Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub op_return_data_hex: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub op_return_data_utf8: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub op_return_protocol: Option<String>,    
}
#[derive(Debug,Clone,Serialize,Deserialize)]
pub struct Prevout {
    pub value_sats: u64,
    pub script_pubkey_hex: String,
}
#[derive(Debug,Serialize)]
#[derive(Clone)]
pub struct SegwitSavings {
    pub witness_bytes: usize,
    pub non_witness_bytes: usize,
    pub total_bytes: usize,
    pub weight_actual: usize,
    pub weight_if_legacy:usize,
    pub savings_pct:f64,
}
#[derive(Debug,Serialize)]
#[derive(Clone)]
pub struct RelativeTimelock {
    pub enabled:bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "type")]
    pub lock_type: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub value: Option<u32>,    
}
#[derive(Debug, Serialize)]
#[derive(Clone)]
pub struct Warning {
    pub code: String,
}
pub struct ErrorResponse {
    pub ok: bool,
    pub error: ErrorDetail,
}
#[derive(Debug, Serialize)]
pub struct ErrorDetail {
    pub code: String,
    pub message: String,
}