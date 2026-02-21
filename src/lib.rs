pub mod api;

// Re-export the SDK crate for backward compatibility.
// `use kaspa_escrow_lab::sdk::{EscrowBuilder, ...}` still works.
pub use kaspa_escrow_sdk as sdk;
pub use kaspa_escrow_sdk::{build_p2pk_sig_script, p2pk_spk, schnorr_sign_input, spk_to_bytes};

use kaspa_addresses::{Address, Prefix, Version};
use kaspa_consensus_core::{
    hashing::{
        sighash::{SigHashReusedValuesUnsync, calc_schnorr_signature_hash},
        sighash_type::SIG_HASH_ALL,
    },
    tx::{
        MutableTransaction, PopulatedTransaction, ScriptPublicKey, Transaction, TransactionId,
        TransactionInput, TransactionOutpoint, TransactionOutput, UtxoEntry,
    },
};
use kaspa_txscript::{EngineCtx, TxScriptEngine, caches::Cache};
use rand::thread_rng;
use secp256k1::Keypair;

/// Generate a new Schnorr keypair. Returns the keypair and its 32-byte x-only public key.
pub fn generate_keypair() -> (Keypair, [u8; 32]) {
    let kp = Keypair::new(secp256k1::SECP256K1, &mut thread_rng());
    let pk = kp.x_only_public_key().0.serialize();
    (kp, pk)
}

/// Create a testnet P2PK address from a 32-byte x-only public key.
pub fn testnet_address(pubkey: &[u8; 32]) -> Address {
    Address::new(Prefix::Testnet, Version::PubKey, pubkey.as_slice())
}

/// Build a mock transaction for local script verification.
///
/// - `utxo_spk`: the script_public_key of the UTXO being spent (e.g. the P2SH wrapper)
/// - `input_value`: the sompi value of the input UTXO
/// - `sig_script`: the signature script for the input (redeem script + signatures)
/// - `outputs`: the transaction outputs
/// - `lock_time`: the transaction lock_time (for CLTV tests; 0 if unused)
pub fn build_mock_tx(
    utxo_spk: ScriptPublicKey,
    input_value: u64,
    sig_script: Vec<u8>,
    outputs: Vec<TransactionOutput>,
    lock_time: u64,
) -> (Transaction, UtxoEntry) {
    let input = TransactionInput {
        previous_outpoint: TransactionOutpoint {
            transaction_id: TransactionId::from_bytes([
                0xc9, 0x97, 0xa5, 0xe5, 0x6e, 0x10, 0x42, 0x02, 0xfa, 0x20, 0x9c, 0x6a, 0x85, 0x2d,
                0xd9, 0x06, 0x60, 0xa2, 0x0b, 0x2d, 0x9c, 0x35, 0x24, 0x23, 0xed, 0xce, 0x25, 0x85,
                0x7f, 0xcd, 0x37, 0x04,
            ]),
            index: 0,
        },
        signature_script: sig_script,
        sequence: 0,
        sig_op_count: 4,
    };
    let tx = Transaction::new(
        1,
        vec![input],
        outputs,
        lock_time,
        Default::default(),
        0,
        vec![],
    );
    let utxo_entry = UtxoEntry::new(input_value, utxo_spk, 0, false, None);
    (tx, utxo_entry)
}

/// Execute the script engine on input 0 and return Ok(()) or an error string.
pub fn verify_script(tx: &Transaction, utxo_entry: &UtxoEntry) -> Result<(), String> {
    let sig_cache = Cache::new(10_000);
    let reused_values = SigHashReusedValuesUnsync::new();
    let ctx = EngineCtx::new(&sig_cache).with_reused(&reused_values);
    let populated = PopulatedTransaction::new(tx, vec![utxo_entry.clone()]);
    let mut vm = TxScriptEngine::from_transaction_input(
        &populated,
        &populated.tx.inputs[0],
        0,
        utxo_entry,
        ctx,
        Default::default(),
    );
    vm.execute().map_err(|e| format!("{:?}", e))
}

/// Sign transaction input 0 with a Schnorr keypair.
/// Returns the 65-byte signature (64-byte sig + SIG_HASH_ALL byte).
pub fn schnorr_sign(tx: &Transaction, utxo_entry: &UtxoEntry, keypair: &Keypair) -> Vec<u8> {
    let reused_values = SigHashReusedValuesUnsync::new();
    let mtx = MutableTransaction::with_entries(tx.clone(), vec![utxo_entry.clone()]);
    let sig_hash =
        calc_schnorr_signature_hash(&mtx.as_verifiable(), 0, SIG_HASH_ALL, &reused_values);
    let msg = secp256k1::Message::from_digest_slice(sig_hash.as_bytes().as_slice())
        .expect("sig hash is always 32 bytes");
    let sig = keypair.sign_schnorr(msg);
    let mut signature = Vec::with_capacity(65);
    signature.extend_from_slice(sig.as_ref().as_slice());
    signature.push(SIG_HASH_ALL.to_u8());
    signature
}

/// Execute the script engine on a specific input index and return Ok(()) or an error string.
pub fn verify_script_input(
    tx: &Transaction,
    utxo_entries: &[UtxoEntry],
    input_index: usize,
) -> Result<(), String> {
    if input_index >= tx.inputs.len() {
        return Err(format!(
            "input_index {input_index} out of bounds for {} inputs",
            tx.inputs.len()
        ));
    }
    if input_index >= utxo_entries.len() {
        return Err(format!(
            "input_index {input_index} out of bounds for {} UTXO entries",
            utxo_entries.len()
        ));
    }
    let sig_cache = Cache::new(10_000);
    let reused_values = SigHashReusedValuesUnsync::new();
    let ctx = EngineCtx::new(&sig_cache).with_reused(&reused_values);
    let populated = PopulatedTransaction::new(tx, utxo_entries.to_vec());
    let mut vm = TxScriptEngine::from_transaction_input(
        &populated,
        &populated.tx.inputs[input_index],
        input_index,
        &utxo_entries[input_index],
        ctx,
        Default::default(),
    );
    vm.execute().map_err(|e| format!("{:?}", e))
}

/// Build a multisig signature script from multiple 65-byte signatures and a redeem script.
/// Format: `<OpData65><sig1> <OpData65><sig2> ... <serialized_redeem_script>`
pub fn build_multisig_sig_script(sigs: Vec<Vec<u8>>, redeem: &[u8]) -> Result<Vec<u8>, String> {
    use kaspa_txscript::opcodes::codes::OpData65;
    use kaspa_txscript::script_builder::ScriptBuilder;
    let mut script = Vec::new();
    for sig in &sigs {
        script.push(OpData65);
        script.extend_from_slice(sig);
    }
    let redeem_data = ScriptBuilder::new()
        .add_data(redeem)
        .map_err(|e| format!("failed to serialize redeem script: {e}"))?
        .drain();
    script.extend_from_slice(&redeem_data);
    Ok(script)
}

/// Disassemble a script into human-readable opcode notation.
///
/// Data pushes are shown as `<hex>`, opcodes as `OP_NAME`.
/// Useful for debugging and understanding script structure.
pub fn disassemble_script(script: &[u8]) -> String {
    let mut parts = Vec::new();
    let mut i = 0;

    while i < script.len() {
        let op = script[i];
        match op {
            // Data push: next `op` bytes (1-75)
            0x01..=0x4b => {
                let len = op as usize;
                if i + 1 + len <= script.len() {
                    let data = &script[i + 1..i + 1 + len];
                    if len <= 8 {
                        parts.push(format!("<{}>", hex::encode(data)));
                    } else {
                        parts.push(format!(
                            "<{}..{} ({} bytes)>",
                            hex::encode(&data[..4]),
                            hex::encode(&data[len - 2..]),
                            len
                        ));
                    }
                    i += 1 + len;
                } else {
                    parts.push(format!("[TRUNCATED data{}]", len));
                    break;
                }
            }
            // OpPushData1: 1-byte length prefix
            0x4c => {
                if i + 1 < script.len() {
                    let len = script[i + 1] as usize;
                    if i + 2 + len <= script.len() {
                        parts.push(format!("<pushdata1: {} bytes>", len));
                        i += 2 + len;
                    } else {
                        parts.push("[TRUNCATED pushdata1]".to_string());
                        break;
                    }
                } else {
                    parts.push("[TRUNCATED pushdata1]".to_string());
                    break;
                }
            }
            // OpPushData2: 2-byte LE length prefix
            0x4d => {
                if i + 2 < script.len() {
                    let len = u16::from_le_bytes([script[i + 1], script[i + 2]]) as usize;
                    if i + 3 + len <= script.len() {
                        parts.push(format!("<pushdata2: {} bytes>", len));
                        i += 3 + len;
                    } else {
                        parts.push("[TRUNCATED pushdata2]".to_string());
                        break;
                    }
                } else {
                    parts.push("[TRUNCATED pushdata2]".to_string());
                    break;
                }
            }
            // Constants
            0x00 => {
                parts.push("OP_FALSE".into());
                i += 1;
            }
            0x4f => {
                parts.push("OP_1NEGATE".into());
                i += 1;
            }
            0x51 => {
                parts.push("OP_1".into());
                i += 1;
            }
            0x52 => {
                parts.push("OP_2".into());
                i += 1;
            }
            0x53 => {
                parts.push("OP_3".into());
                i += 1;
            }
            0x54..=0x60 => {
                parts.push(format!("OP_{}", op - 0x50));
                i += 1;
            }
            // Control flow
            0x63 => {
                parts.push("OP_IF".into());
                i += 1;
            }
            0x64 => {
                parts.push("OP_NOTIF".into());
                i += 1;
            }
            0x67 => {
                parts.push("OP_ELSE".into());
                i += 1;
            }
            0x68 => {
                parts.push("OP_ENDIF".into());
                i += 1;
            }
            0x69 => {
                parts.push("OP_VERIFY".into());
                i += 1;
            }
            0x6a => {
                parts.push("OP_RETURN".into());
                i += 1;
            }
            // Stack
            0x75 => {
                parts.push("OP_DROP".into());
                i += 1;
            }
            0x76 => {
                parts.push("OP_DUP".into());
                i += 1;
            }
            // Comparison
            0x87 => {
                parts.push("OP_EQUAL".into());
                i += 1;
            }
            0x88 => {
                parts.push("OP_EQUALVERIFY".into());
                i += 1;
            }
            // Arithmetic
            0x93 => {
                parts.push("OP_ADD".into());
                i += 1;
            }
            0x94 => {
                parts.push("OP_SUB".into());
                i += 1;
            }
            0x9f => {
                parts.push("OP_LESSTHAN".into());
                i += 1;
            }
            0xa0 => {
                parts.push("OP_GREATERTHAN".into());
                i += 1;
            }
            0xa2 => {
                parts.push("OP_GREATERTHANOREQUAL".into());
                i += 1;
            }
            // Crypto
            0xaa => {
                parts.push("OP_BLAKE2B".into());
                i += 1;
            }
            0xac => {
                parts.push("OP_CHECKSIG".into());
                i += 1;
            }
            0xae => {
                parts.push("OP_CHECKMULTISIG".into());
                i += 1;
            }
            0xb0 => {
                parts.push("OP_CHECKLOCKTIMEVERIFY".into());
                i += 1;
            }
            // Introspection
            0xb2 => {
                parts.push("OP_TXVERSION".into());
                i += 1;
            }
            0xb3 => {
                parts.push("OP_TXINPUTCOUNT".into());
                i += 1;
            }
            0xb4 => {
                parts.push("OP_TXOUTPUTCOUNT".into());
                i += 1;
            }
            0xb5 => {
                parts.push("OP_TXLOCKTIME".into());
                i += 1;
            }
            0xbe => {
                parts.push("OP_TXINPUTAMOUNT".into());
                i += 1;
            }
            0xbf => {
                parts.push("OP_TXINPUTSPK".into());
                i += 1;
            }
            0xc2 => {
                parts.push("OP_TXOUTPUTAMOUNT".into());
                i += 1;
            }
            0xc3 => {
                parts.push("OP_TXOUTPUTSPK".into());
                i += 1;
            }
            // Unknown
            _ => {
                parts.push(format!("OP_UNKNOWN(0x{:02x})", op));
                i += 1;
            }
        }
    }

    parts.join(" ")
}

pub fn print_header(title: &str) {
    println!("\n=== {} ===\n", title);
}

pub fn print_step(num: usize, description: &str) {
    println!("Step {}: {}", num, description);
}

pub fn print_result(label: &str, result: &Result<(), String>) {
    match result {
        Ok(()) => println!("  [{}] PASS", label),
        Err(e) => println!("  [{}] FAIL as expected: {}", label, e),
    }
}
