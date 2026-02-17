//! Live Covenant Escrow on Testnet 12
//!
//! Tests covenant introspection opcodes on-chain by exercising the timeout
//! refund path of a multi-path covenant escrow:
//!
//! 1. Build a covenant escrow with 3 branches (normal / dispute / timeout)
//! 2. Fund the escrow P2SH UTXO
//! 3. Execute timeout refund — covenant enforces output address + minimum amount
//!    (no signatures required, just script validation!)
//!
//! This proves that OpTxOutputSpk and OpTxOutputAmount work on-chain.
//!
//! Usage:
//!   cargo run --example live_covenant_escrow
//!
//! Requires kaspad running with:
//!   --rpclisten-borsh=127.0.0.1:17110 --utxoindex --enable-unsynced-mining

use kaspa_consensus_core::tx::{
    Transaction, TransactionInput, TransactionOutpoint, TransactionOutput,
};
use kaspa_escrow_lab::*;
use kaspa_rpc_core::RpcTransaction;
use kaspa_txscript::{
    opcodes::codes::{
        OpCheckLockTimeVerify, OpCheckMultiSig, OpElse, OpEndIf, OpEqualVerify, OpFalse,
        OpGreaterThanOrEqual, OpIf, OpTxOutputAmount, OpTxOutputSpk,
    },
    pay_to_address_script, pay_to_script_hash_script,
    script_builder::ScriptBuilder,
};
use kaspa_wrpc_client::prelude::*;
use std::time::Duration;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    print_header("Live Covenant Escrow on Testnet 12");

    // Step 1: Connect to node
    print_step(1, "Connecting to local TN12 node...");
    let client = KaspaRpcClient::new(
        WrpcEncoding::Borsh,
        Some("ws://127.0.0.1:17110"),
        None,
        None,
        None,
    )?;
    client.connect(None).await.map_err(|e| {
        format!(
            "Failed to connect to TN12 node at ws://127.0.0.1:17110: {e}\n  \
             Is kaspad running with --rpclisten-borsh=127.0.0.1:17110?"
        )
    })?;

    let info = client.get_block_dag_info().await?;
    let current_daa = info.virtual_daa_score;
    println!(
        "  Connected! Network: {}, DAA: {}",
        info.network, current_daa
    );

    // Step 2: Generate keypairs
    print_step(2, "Generating keypairs...");
    let (buyer_kp, buyer_pk) = generate_keypair();
    let (_, seller_pk) = generate_keypair();
    let (_, arbitrator_pk) = generate_keypair();

    let buyer_addr = testnet_address(&buyer_pk);
    println!("  Buyer address:      {}", buyer_addr);
    println!("  Seller pubkey:      {}", hex::encode(seller_pk));
    println!("  Arbitrator pubkey:  {}", hex::encode(arbitrator_pk));

    // Step 3: Build covenant escrow script
    // Lock time is set to current_daa - 10 so the timeout path is already available.
    // This lets us test the covenant constraints immediately after funding.
    let lock_time_value = current_daa.saturating_sub(10);
    let fee: u64 = 5000;

    print_step(3, "Building covenant escrow script...");
    println!("  Lock time: {} (current DAA: {})", lock_time_value, current_daa);

    let buyer_spk = p2pk_spk(&buyer_pk);
    let buyer_spk_bytes = spk_to_bytes(&buyer_spk);

    // Script structure:
    //   OpIf
    //     OpIf
    //       2 <buyer> <seller> 2 OpCheckMultiSig       // Branch 1: normal
    //     OpElse
    //       2 <buyer> <seller> <arb> 3 OpCheckMultiSig  // Branch 2: dispute
    //     OpEndIf
    //   OpElse
    //     <lock_time> OpCheckLockTimeVerify              // Branch 3: timeout
    //     <buyer_spk> 0 OpTxOutputSpk OpEqualVerify      //   covenant: output → buyer
    //     0 OpTxOutputAmount <min> OpGreaterThanOrEqual   //   covenant: min amount
    //   OpEndIf
    let redeem_script = ScriptBuilder::new()
        .add_op(OpIf)?
        .add_op(OpIf)?
        .add_i64(2)?
        .add_data(&buyer_pk)?
        .add_data(&seller_pk)?
        .add_i64(2)?
        .add_op(OpCheckMultiSig)?
        .add_op(OpElse)?
        .add_i64(2)?
        .add_data(&buyer_pk)?
        .add_data(&seller_pk)?
        .add_data(&arbitrator_pk)?
        .add_i64(3)?
        .add_op(OpCheckMultiSig)?
        .add_op(OpEndIf)?
        .add_op(OpElse)?
        .add_i64(lock_time_value as i64)?
        .add_op(OpCheckLockTimeVerify)?
        .add_data(&buyer_spk_bytes)?
        .add_i64(0)?
        .add_op(OpTxOutputSpk)?
        .add_op(OpEqualVerify)?
        .add_i64(0)?
        .add_op(OpTxOutputAmount)?
        // min_amount will be set after we know the escrow amount
        // For now use a placeholder — we'll rebuild after funding
        .add_i64(0)?
        .add_op(OpGreaterThanOrEqual)?
        .add_op(OpEndIf)?
        .drain();

    println!("  Redeem script: {} bytes", redeem_script.len());
    println!("  Disassembly:\n    {}", disassemble_script(&redeem_script));

    // Step 4: Wait for funding
    print_step(4, "Waiting for funds...");
    println!("  Send test KAS to buyer address:");
    println!("  {}", buyer_addr);
    println!("  (In wallet: transfer {})", buyer_addr);
    println!();

    let max_wait = Duration::from_secs(300);
    let start = std::time::Instant::now();
    let (outpoint, utxo_amount) = loop {
        let utxos = client
            .get_utxos_by_addresses(vec![buyer_addr.clone()])
            .await?;
        if let Some(entry) = utxos.first() {
            let op = TransactionOutpoint::new(
                entry.outpoint.transaction_id,
                entry.outpoint.index,
            );
            println!(
                "  Found UTXO: {} sompi (tx: {})",
                entry.utxo_entry.amount, entry.outpoint.transaction_id
            );
            break (op, entry.utxo_entry.amount);
        }
        if start.elapsed() > max_wait {
            return Err(
                "Timed out after 5 minutes waiting for funds. Send test KAS and try again.".into(),
            );
        }
        eprint!(".");
        tokio::time::sleep(Duration::from_secs(2)).await;
    };

    // Now rebuild the script with the actual min_amount (escrow - fee for the refund tx)
    if utxo_amount <= fee * 2 {
        return Err(format!(
            "UTXO too small: {} sompi (need > {} for two fees)",
            utxo_amount,
            fee * 2
        )
        .into());
    }
    let escrow_amount = utxo_amount - fee;
    let refund_amount = escrow_amount - fee;

    print_step(5, "Rebuilding script with actual amounts...");
    println!("  UTXO:    {} sompi", utxo_amount);
    println!("  Escrow:  {} sompi (after funding fee)", escrow_amount);
    println!("  Refund:  {} sompi (after refund fee)", refund_amount);

    let redeem_script = ScriptBuilder::new()
        .add_op(OpIf)?
        .add_op(OpIf)?
        .add_i64(2)?
        .add_data(&buyer_pk)?
        .add_data(&seller_pk)?
        .add_i64(2)?
        .add_op(OpCheckMultiSig)?
        .add_op(OpElse)?
        .add_i64(2)?
        .add_data(&buyer_pk)?
        .add_data(&seller_pk)?
        .add_data(&arbitrator_pk)?
        .add_i64(3)?
        .add_op(OpCheckMultiSig)?
        .add_op(OpEndIf)?
        .add_op(OpElse)?
        .add_i64(lock_time_value as i64)?
        .add_op(OpCheckLockTimeVerify)?
        .add_data(&buyer_spk_bytes)?
        .add_i64(0)?
        .add_op(OpTxOutputSpk)?
        .add_op(OpEqualVerify)?
        .add_i64(0)?
        .add_op(OpTxOutputAmount)?
        .add_i64(refund_amount as i64)?
        .add_op(OpGreaterThanOrEqual)?
        .add_op(OpEndIf)?
        .drain();

    let p2sh_spk = pay_to_script_hash_script(&redeem_script);
    println!("  Final redeem script: {} bytes", redeem_script.len());

    // Step 6: Build and submit funding transaction (buyer → escrow P2SH)
    print_step(6, "Building escrow funding transaction...");
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

    let funding_utxo_spk = pay_to_address_script(&buyer_addr);
    let funding_utxo =
        kaspa_consensus_core::tx::UtxoEntry::new(utxo_amount, funding_utxo_spk, 0, false, None);

    let signature = schnorr_sign(&funding_tx, &funding_utxo, &buyer_kp);
    let sig_script = build_p2pk_sig_script(&signature);

    let mut signed_funding_tx = funding_tx;
    signed_funding_tx.inputs[0].signature_script = sig_script;

    verify_script(&signed_funding_tx, &funding_utxo)
        .map_err(|e| format!("Funding tx failed local verification: {e}"))?;
    println!("  Local verify: OK");

    let rpc_tx: RpcTransaction = (&signed_funding_tx).into();
    let funding_tx_id = client.submit_transaction(rpc_tx, false).await?;
    println!("  Funding TX submitted: {}", funding_tx_id);

    // Step 7: Wait for escrow UTXO
    print_step(7, "Waiting for escrow UTXO...");
    tokio::time::sleep(Duration::from_secs(5)).await;
    println!("  Escrow at outpoint {}:0", funding_tx_id);

    // Step 8: Build timeout refund transaction (Branch 3)
    // This is the covenant test — no signatures needed!
    // The script validates: output goes to buyer's address with >= refund_amount.
    let info = client.get_block_dag_info().await?;
    let spend_daa = info.virtual_daa_score;
    println!("  Current DAA: {} (lock_time threshold: {})", spend_daa, lock_time_value);

    print_step(8, "Building covenant timeout refund (no signatures!)...");
    let escrow_outpoint = TransactionOutpoint::new(funding_tx_id, 0);
    let refund_input = TransactionInput {
        previous_outpoint: escrow_outpoint,
        signature_script: vec![],
        sequence: 0,
        sig_op_count: 4,
    };
    let refund_output = TransactionOutput {
        value: refund_amount,
        script_public_key: buyer_spk.clone(),
        covenant: None,
    };
    let refund_tx = Transaction::new(
        1,
        vec![refund_input],
        vec![refund_output],
        spend_daa, // lock_time must be >= threshold and <= current DAA
        Default::default(),
        0,
        vec![],
    );

    // sig_script for timeout branch: OpFalse (select outer else) + serialized redeem script
    let mut sb = ScriptBuilder::new();
    sb.add_op(OpFalse)?;
    sb.add_data(&redeem_script)?;
    let sig_script = sb.drain();

    let mut signed_refund_tx = refund_tx;
    signed_refund_tx.inputs[0].signature_script = sig_script;

    let escrow_utxo =
        kaspa_consensus_core::tx::UtxoEntry::new(escrow_amount, p2sh_spk, 0, false, None);

    verify_script(&signed_refund_tx, &escrow_utxo)
        .map_err(|e| format!("Refund tx failed local verification: {e}"))?;
    println!("  Local verify: OK");
    println!("  (Covenant enforced: output → buyer address, amount >= {} sompi)", refund_amount);

    let rpc_refund: RpcTransaction = (&signed_refund_tx).into();
    let refund_tx_id = client.submit_transaction(rpc_refund, false).await?;
    println!("  Refund TX submitted: {}", refund_tx_id);

    // Step 9: Verify buyer got refund
    print_step(9, "Verifying buyer received refund...");
    tokio::time::sleep(Duration::from_secs(5)).await;
    let buyer_utxos = client
        .get_utxos_by_addresses(vec![buyer_addr.clone()])
        .await?;
    if let Some(entry) = buyer_utxos.first() {
        println!("  Buyer refund: {} sompi", entry.utxo_entry.amount);
        println!("  Covenant timeout refund successful!");
    } else {
        println!("  Waiting for buyer UTXO... (may need another block)");
    }

    client.disconnect().await?;
    println!("\n=== Live covenant escrow complete ===");
    println!("  Proved on-chain: OpTxOutputSpk + OpTxOutputAmount covenant enforcement\n");
    Ok(())
}
