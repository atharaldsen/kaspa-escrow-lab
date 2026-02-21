use kaspa_addresses::{Address, Prefix, Version};
use kaspa_consensus_core::{
    hashing::{
        sighash::{SigHashReusedValuesUnsync, calc_schnorr_signature_hash},
        sighash_type::SIG_HASH_ALL,
    },
    tx::{MutableTransaction, ScriptPublicKey, Transaction, UtxoEntry},
};
use kaspa_txscript::pay_to_address_script;
use secp256k1::Keypair;

use crate::error::EscrowError;

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

/// Create a P2PK ScriptPublicKey from a 32-byte x-only public key.
///
/// Note: The resulting ScriptPublicKey is network-prefix-independent
/// (P2PK script is `<pubkey> OP_CHECKSIG` regardless of prefix).
pub fn p2pk_spk(pubkey: &[u8; 32]) -> ScriptPublicKey {
    let addr = Address::new(Prefix::Testnet, Version::PubKey, pubkey.as_slice());
    pay_to_address_script(&addr)
}

/// Build a P2PK signature script from a 65-byte Schnorr signature.
/// Format: `<OpData65><signature>`
pub fn build_p2pk_sig_script(signature: &[u8]) -> Vec<u8> {
    use kaspa_txscript::opcodes::codes::OpData65;
    let mut script = Vec::with_capacity(1 + signature.len());
    script.push(OpData65);
    script.extend_from_slice(signature);
    script
}

/// Sign a specific transaction input with a Schnorr keypair.
/// For multi-input transactions (e.g. UTXO compounding).
/// Returns the 65-byte signature (64-byte sig + SIG_HASH_ALL byte).
pub fn schnorr_sign_input(
    tx: &Transaction,
    utxo_entries: &[UtxoEntry],
    keypair: &Keypair,
    input_index: usize,
) -> Result<Vec<u8>, EscrowError> {
    if input_index >= tx.inputs.len() {
        return Err(EscrowError::InvalidConfig(format!(
            "input_index {input_index} out of bounds for {} inputs",
            tx.inputs.len()
        )));
    }
    if input_index >= utxo_entries.len() {
        return Err(EscrowError::InvalidConfig(format!(
            "input_index {input_index} out of bounds for {} UTXO entries",
            utxo_entries.len()
        )));
    }
    let reused_values = SigHashReusedValuesUnsync::new();
    let mtx = MutableTransaction::with_entries(tx.clone(), utxo_entries.to_vec());
    let sig_hash = calc_schnorr_signature_hash(
        &mtx.as_verifiable(),
        input_index,
        SIG_HASH_ALL,
        &reused_values,
    );
    let msg = secp256k1::Message::from_digest_slice(sig_hash.as_bytes().as_slice())
        .expect("sig hash is always 32 bytes");
    let sig = keypair.sign_schnorr(msg);
    let mut signature = Vec::with_capacity(65);
    signature.extend_from_slice(sig.as_ref().as_slice());
    signature.push(SIG_HASH_ALL.to_u8());
    Ok(signature)
}
