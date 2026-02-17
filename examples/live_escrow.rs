//! Live 2-of-2 Escrow on Testnet 12
//!
//! End-to-end escrow flow against a running TN12 node:
//! 1. Generate buyer & seller keypairs
//! 2. Wait for the user to fund the buyer's address
//! 3. Create escrow P2SH UTXO (funding tx)
//! 4. Release escrow to seller (release tx, both sign)
//!
//! Usage:
//!   cargo run --example live_escrow
//!
//! Requires kaspad running with:
//!   --rpclisten-borsh=127.0.0.1:17110 --utxoindex --enable-unsynced-mining

use kaspa_consensus_core::{
    hashing::{
        sighash::{SigHashReusedValuesUnsync, calc_schnorr_signature_hash},
        sighash_type::SIG_HASH_ALL,
    },
    tx::{
        MutableTransaction, Transaction, TransactionInput, TransactionOutpoint,
        TransactionOutput,
    },
};
use kaspa_escrow_lab::*;
use kaspa_rpc_core::RpcTransaction;
use kaspa_txscript::{
    opcodes::codes::OpData65,
    pay_to_address_script, pay_to_script_hash_script,
    script_builder::ScriptBuilder,
    standard::multisig_redeem_script,
};
use kaspa_wrpc_client::prelude::*;
use std::time::Duration;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    print_header("Live 2-of-2 Escrow on Testnet 12");

    // Step 1: Connect to node
    print_step(1, "Connecting to local TN12 node...");
    let client = KaspaRpcClient::new(
        WrpcEncoding::Borsh,
        Some("ws://127.0.0.1:17110"),
        None,
        None,
        None,
    )?;
    client.connect(None).await?;

    let info = client.get_block_dag_info().await?;
    println!("  Connected! Network: {}, DAA: {}", info.network, info.virtual_daa_score);

    // Step 2: Generate keypairs
    print_step(2, "Generating keypairs...");
    let (buyer_kp, buyer_pk) = generate_keypair();
    let (seller_kp, seller_pk) = generate_keypair();

    let buyer_addr = testnet_address(&buyer_pk);
    let seller_addr = testnet_address(&seller_pk);
    println!("  Buyer address:  {}", buyer_addr);
    println!("  Seller address: {}", seller_addr);

    // Step 3: Build escrow script
    print_step(3, "Building 2-of-2 escrow script...");
    let redeem_script = multisig_redeem_script([buyer_pk, seller_pk].iter(), 2)?;
    let p2sh_spk = pay_to_script_hash_script(&redeem_script);
    println!("  Redeem script: {} bytes", redeem_script.len());

    // Step 4: Wait for funding
    print_step(4, "Waiting for funds...");
    println!("  Send test KAS to buyer address:");
    println!("  {}", buyer_addr);
    println!("  (In wallet: transfer {})", buyer_addr);
    println!();

    let (outpoint, utxo_amount) = loop {
        let utxos = client
            .get_utxos_by_addresses(vec![buyer_addr.clone()])
            .await?;
        if let Some(entry) = utxos.first() {
            let op = TransactionOutpoint::new(
                entry.outpoint.transaction_id,
                entry.outpoint.index,
            );
            println!("  Found UTXO: {} sompi (tx: {})", entry.utxo_entry.amount, entry.outpoint.transaction_id);
            break (op, entry.utxo_entry.amount);
        }
        tokio::time::sleep(Duration::from_secs(2)).await;
    };

    // Step 5: Build and submit funding transaction (buyer → escrow P2SH)
    print_step(5, "Building escrow funding transaction...");
    let fee: u64 = 5000;
    let escrow_amount = utxo_amount - fee;
    println!("  Input:  {} sompi", utxo_amount);
    println!("  Escrow: {} sompi", escrow_amount);
    println!("  Fee:    {} sompi", fee);

    let funding_input = TransactionInput {
        previous_outpoint: outpoint,
        signature_script: vec![],
        sequence: 0,
        sig_op_count: 1,
    };
    let funding_output = TransactionOutput {
        value: escrow_amount,
        script_public_key: p2sh_spk.clone(),
        covenant: None,
    };
    let funding_tx = Transaction::new(
        1,
        vec![funding_input],
        vec![funding_output],
        0,
        Default::default(),
        0,
        vec![],
    );

    // Sign the funding tx with buyer's key (spending from buyer's P2PK address)
    let buyer_spk = pay_to_address_script(&buyer_addr);
    let funding_utxo =
        kaspa_consensus_core::tx::UtxoEntry::new(utxo_amount, buyer_spk, 0, false, None);

    let reused_values = SigHashReusedValuesUnsync::new();
    let mtx = MutableTransaction::with_entries(funding_tx.clone(), vec![funding_utxo.clone()]);
    let sig_hash =
        calc_schnorr_signature_hash(&mtx.as_verifiable(), 0, SIG_HASH_ALL, &reused_values);
    let msg = secp256k1::Message::from_digest_slice(sig_hash.as_bytes().as_slice())?;
    let sig = buyer_kp.sign_schnorr(msg);
    let mut signature = Vec::with_capacity(65);
    signature.extend_from_slice(sig.as_ref().as_slice());
    signature.push(SIG_HASH_ALL.to_u8());

    // For P2PK, sig_script is just: <sig_data_65>
    let mut sig_script = Vec::new();
    sig_script.push(OpData65);
    sig_script.extend_from_slice(&signature);

    let mut signed_funding_tx = funding_tx;
    signed_funding_tx.inputs[0].signature_script = sig_script;

    // Verify locally before submitting
    let verify_result = verify_script(&signed_funding_tx, &funding_utxo);
    println!("  Local verify: {:?}", verify_result);
    assert!(verify_result.is_ok(), "Funding tx should verify locally");

    // Submit
    let rpc_tx: RpcTransaction = (&signed_funding_tx).into();
    let funding_tx_id = client.submit_transaction(rpc_tx, false).await?;
    println!("  Funding TX submitted: {}", funding_tx_id);

    // Step 6: Wait for escrow UTXO to appear
    print_step(6, "Waiting for escrow UTXO to confirm...");
    // The P2SH address isn't a standard address we can query by,
    // so we wait a few seconds and build the release tx from the known outpoint.
    tokio::time::sleep(Duration::from_secs(5)).await;
    println!("  Escrow UTXO should be at outpoint {}:0", funding_tx_id);

    // Step 7: Build and submit release transaction (escrow → seller)
    print_step(7, "Building release transaction...");
    let release_fee: u64 = 5000;
    let release_amount = escrow_amount - release_fee;
    println!("  Escrow input: {} sompi", escrow_amount);
    println!("  To seller:    {} sompi", release_amount);
    println!("  Fee:          {} sompi", release_fee);

    let escrow_outpoint = TransactionOutpoint::new(funding_tx_id, 0);
    let release_input = TransactionInput {
        previous_outpoint: escrow_outpoint,
        signature_script: vec![],
        sequence: 0,
        sig_op_count: 4, // multisig needs higher sig_op_count
    };
    let release_output = TransactionOutput {
        value: release_amount,
        script_public_key: pay_to_address_script(&seller_addr),
        covenant: None,
    };
    let release_tx = Transaction::new(
        1,
        vec![release_input],
        vec![release_output],
        0,
        Default::default(),
        0,
        vec![],
    );

    // Sign with both buyer and seller
    let escrow_utxo =
        kaspa_consensus_core::tx::UtxoEntry::new(escrow_amount, p2sh_spk.clone(), 0, false, None);

    let buyer_sig = schnorr_sign(&release_tx, &escrow_utxo, &buyer_kp);
    let seller_sig = schnorr_sign(&release_tx, &escrow_utxo, &seller_kp);

    // Build multisig sig_script: <buyer_sig> <seller_sig> <redeem_script>
    let mut sig_script = Vec::new();
    sig_script.push(OpData65);
    sig_script.extend_from_slice(&buyer_sig);
    sig_script.push(OpData65);
    sig_script.extend_from_slice(&seller_sig);
    sig_script.extend_from_slice(&ScriptBuilder::new().add_data(&redeem_script)?.drain());

    let mut signed_release_tx = release_tx;
    signed_release_tx.inputs[0].signature_script = sig_script;

    // Verify locally
    let verify_result = verify_script(&signed_release_tx, &escrow_utxo);
    println!("  Local verify: {:?}", verify_result);
    assert!(verify_result.is_ok(), "Release tx should verify locally");

    // Submit
    let rpc_release: RpcTransaction = (&signed_release_tx).into();
    let release_tx_id = client.submit_transaction(rpc_release, false).await?;
    println!("  Release TX submitted: {}", release_tx_id);

    // Step 8: Verify seller received funds
    print_step(8, "Verifying seller received funds...");
    tokio::time::sleep(Duration::from_secs(5)).await;
    let seller_utxos = client
        .get_utxos_by_addresses(vec![seller_addr.clone()])
        .await?;
    if let Some(entry) = seller_utxos.first() {
        println!("  Seller balance: {} sompi", entry.utxo_entry.amount);
        println!("  Escrow released successfully!");
    } else {
        println!("  Waiting for seller UTXO... (may need another block)");
    }

    client.disconnect().await?;
    println!("\n=== Live escrow complete ===\n");
    Ok(())
}
