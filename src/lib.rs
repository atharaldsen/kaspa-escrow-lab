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
use kaspa_txscript::{EngineCtx, TxScriptEngine, caches::Cache, pay_to_address_script};
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

/// Convert a ScriptPublicKey to the byte representation that
/// OpTxInputSpk/OpTxOutputSpk push onto the stack: 2-byte BE version + script bytes.
pub fn spk_to_bytes(spk: &ScriptPublicKey) -> Vec<u8> {
    let version = spk.version.to_be_bytes();
    let script = spk.script();
    let mut v = Vec::with_capacity(version.len() + script.len());
    v.extend_from_slice(&version);
    v.extend_from_slice(script);
    v
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
    let msg = secp256k1::Message::from_digest_slice(sig_hash.as_bytes().as_slice()).unwrap();
    let sig = keypair.sign_schnorr(msg);
    let mut signature = Vec::with_capacity(65);
    signature.extend_from_slice(sig.as_ref().as_slice());
    signature.push(SIG_HASH_ALL.to_u8());
    signature
}

/// Create a P2PK ScriptPublicKey for a testnet address from an x-only pubkey.
pub fn p2pk_spk(pubkey: &[u8; 32]) -> ScriptPublicKey {
    pay_to_address_script(&testnet_address(pubkey))
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
