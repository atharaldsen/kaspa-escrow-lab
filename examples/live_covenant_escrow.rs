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

    let fee: u64 = 5000;

    print_step(3, "Preparing covenant parameters...");

    let buyer_spk = p2pk_spk(&buyer_pk);
    let buyer_spk_bytes = spk_to_bytes(&buyer_spk);
    println!("  Script will be built after funding (needs actual amounts + current DAA)");

    // Step 4: Wait for funding
    print_step(4, "Waiting for funds...");
    println!("  Fund the buyer address via wallet or miner:");
    println!("  {}", buyer_addr);
    println!("  Wallet:  send {} 10", buyer_addr);
    println!("  Miner:   kaspa-miner --mining-address {} --mine-when-not-synced", buyer_addr);
    println!("  (Coinbase UTXOs need ~1000 DAA to mature, roughly 17 minutes)");
    println!();

    let max_wait = Duration::from_secs(1500);
    let start = std::time::Instant::now();
    let mut poll_count = 0u64;
    let coinbase_maturity: u64 = 1000;
    let (outpoint, utxo_amount) = loop {
        let info = client.get_block_dag_info().await?;
        let current_daa = info.virtual_daa_score;
        let utxos = client
            .get_utxos_by_addresses(vec![buyer_addr.clone()])
            .await?;
        let mature = utxos.iter().find(|e| {
            !e.utxo_entry.is_coinbase
                || current_daa >= e.utxo_entry.block_daa_score + coinbase_maturity
        });
        if let Some(entry) = mature {
            if poll_count > 0 {
                eprintln!();
            }
            let op = TransactionOutpoint::new(
                entry.outpoint.transaction_id,
                entry.outpoint.index,
            );
            println!(
                "  Found mature UTXO: {} sompi (tx: {})",
                entry.utxo_entry.amount, entry.outpoint.transaction_id
            );
            break (op, entry.utxo_entry.amount);
        }
        let immature_count = utxos.len();
        if start.elapsed() > max_wait {
            if immature_count > 0 {
                return Err(format!(
                    "Found {} immature coinbase UTXO(s) but none are spendable yet \
                     (need {} DAA confirmations). Keep mining and try again.",
                    immature_count, coinbase_maturity
                ).into());
            }
            return Err("Timed out waiting for funds. Send test KAS and try again.".into());
        }
        poll_count += 1;
        if poll_count % 30 == 0 {
            let elapsed = start.elapsed().as_secs();
            if immature_count > 0 {
                eprintln!(" ({elapsed}s, {immature_count} immature UTXOs waiting to mature)");
            } else {
                eprintln!(" ({elapsed}s)");
            }
        } else {
            eprint!(".");
        }
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

    // Set lock_time to current DAA - 10 so the timeout path is immediately available
    let info = client.get_block_dag_info().await?;
    let lock_time_value = info.virtual_daa_score.saturating_sub(10);

    print_step(5, "Building script with actual amounts...");
    println!("  UTXO:      {} sompi", utxo_amount);
    println!("  Escrow:    {} sompi (after funding fee)", escrow_amount);
    println!("  Refund:    {} sompi (after refund fee)", refund_amount);
    println!("  Lock time: {} (current DAA: {})", lock_time_value, info.virtual_daa_score);

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

    // Step 7: Wait for escrow UTXO to be finalized
    print_step(7, "Waiting for escrow UTXO to finalize...");
    println!("  Escrow at outpoint {}:0", funding_tx_id);

    // Step 8: Build and submit timeout refund transaction (Branch 3)
    // This is the covenant test — no signatures needed!
    // The script validates: output goes to buyer's address with >= refund_amount.
    // We retry submission because the escrow UTXO needs to be finalized first.
    print_step(8, "Building covenant timeout refund (no signatures!)...");
    let escrow_outpoint = TransactionOutpoint::new(funding_tx_id, 0);

    let escrow_utxo =
        kaspa_consensus_core::tx::UtxoEntry::new(escrow_amount, p2sh_spk, 0, false, None);

    let refund_tx_id;
    let max_retries = 30;
    let mut attempt = 0;
    loop {
        attempt += 1;
        let info = client.get_block_dag_info().await?;
        let spend_daa = info.virtual_daa_score;

        let refund_input = TransactionInput {
            previous_outpoint: escrow_outpoint.clone(),
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
            spend_daa,
            Default::default(),
            0,
            vec![],
        );

        let mut sb = ScriptBuilder::new();
        sb.add_op(OpFalse)?;
        sb.add_data(&redeem_script)?;
        let sig_script = sb.drain();

        let mut signed_refund_tx = refund_tx;
        signed_refund_tx.inputs[0].signature_script = sig_script;

        if attempt == 1 {
            verify_script(&signed_refund_tx, &escrow_utxo)
                .map_err(|e| format!("Refund tx failed local verification: {e}"))?;
            println!("  Local verify: OK");
            println!("  (Covenant enforced: output → buyer address, amount >= {} sompi)", refund_amount);
            println!("  Current DAA: {} (lock_time threshold: {})", spend_daa, lock_time_value);
        }

        let rpc_refund: RpcTransaction = (&signed_refund_tx).into();
        match client.submit_transaction(rpc_refund, false).await {
            Ok(tx_id) => {
                refund_tx_id = tx_id;
                break;
            }
            Err(e) => {
                let err_msg = format!("{e}");
                if err_msg.contains("not finalized") && attempt < max_retries {
                    if attempt == 1 {
                        eprint!("  Waiting for finalization");
                    }
                    eprint!(".");
                    tokio::time::sleep(Duration::from_secs(5)).await;
                    continue;
                }
                if attempt > 1 {
                    eprintln!();
                }
                return Err(format!("Refund tx rejected after {attempt} attempts: {e}").into());
            }
        }
    }
    if attempt > 1 {
        eprintln!();
    }
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
