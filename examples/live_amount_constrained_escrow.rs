//! Live Amount-Constrained Escrow (Payment Split Covenant) on Testnet 12
//!
//! Tests covenant-enforced payment splits on-chain:
//!
//! 1. Build a 2-path escrow:
//!    - Path A: Owner signs (escape hatch, can spend anywhere)
//!    - Path B: Covenant release — no signatures, but output 0 must go to seller
//!      with >= seller_amount, and output 1 must go to fee address with >= fee_amount
//! 2. Fund the escrow P2SH UTXO
//! 3. Execute covenant release — proves multi-output payment routing on-chain
//!
//! This proves OpTxOutputSpk + OpTxOutputAmount work across multiple outputs,
//! enforcing payment splits without any signatures.
//!
//! Usage:
//!   cargo run --example live_amount_constrained_escrow
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
        OpCheckSig, OpElse, OpEndIf, OpEqualVerify, OpFalse, OpGreaterThanOrEqual, OpIf,
        OpTxOutputAmount, OpTxOutputSpk, OpVerify,
    },
    pay_to_address_script, pay_to_script_hash_script,
    script_builder::ScriptBuilder,
};
use kaspa_wrpc_client::prelude::*;
use std::time::Duration;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    print_header("Live Amount-Constrained Escrow on Testnet 12");

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
    println!(
        "  Connected! Network: {}, DAA: {}",
        info.network, info.virtual_daa_score
    );

    // Step 2: Generate keypairs
    print_step(2, "Generating keypairs...");
    let (buyer_kp, buyer_pk) = generate_keypair();
    let (_, seller_pk) = generate_keypair();
    let (_, fee_pk) = generate_keypair();
    let (owner_kp, owner_pk) = generate_keypair();

    let buyer_addr = testnet_address(&buyer_pk);
    let seller_addr = testnet_address(&seller_pk);
    let fee_addr = testnet_address(&fee_pk);
    println!("  Buyer address:    {}", buyer_addr);
    println!("  Seller address:   {}", seller_addr);
    println!("  Fee address:      {}", fee_addr);
    println!("  Owner pubkey:     {}", hex::encode(owner_pk));

    let funding_fee: u64 = 5000;
    let release_fee: u64 = 10000; // release tx is larger (2 outputs + redeem script)

    print_step(3, "Preparing covenant parameters...");
    let seller_spk = p2pk_spk(&seller_pk);
    let seller_spk_bytes = spk_to_bytes(&seller_spk);
    let fee_spk = p2pk_spk(&fee_pk);
    let fee_spk_bytes = spk_to_bytes(&fee_spk);
    println!("  Script will be built after funding (needs actual amounts)");

    // Step 4: Wait for funding
    print_step(4, "Waiting for funds...");
    println!("  Fund the buyer address via wallet or miner:");
    println!("  {}", buyer_addr);
    println!("  Wallet:  send {} 10", buyer_addr);
    println!(
        "  Miner:   kaspa-miner --mining-address {} --mine-when-not-synced",
        buyer_addr
    );
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
            let op = TransactionOutpoint::new(entry.outpoint.transaction_id, entry.outpoint.index);
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
                )
                .into());
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

    // Calculate payment split amounts
    if utxo_amount <= funding_fee + release_fee {
        return Err(format!(
            "UTXO too small: {} sompi (need > {} for fees)",
            utxo_amount,
            funding_fee + release_fee
        )
        .into());
    }
    let escrow_amount = utxo_amount - funding_fee;
    let spendable = escrow_amount - release_fee;

    // 90% to seller, 10% platform fee
    let seller_amount = (spendable * 90) / 100;
    let fee_amount = spendable - seller_amount;

    print_step(5, "Building script with actual amounts...");
    println!("  UTXO:         {} sompi", utxo_amount);
    println!(
        "  Escrow:       {} sompi (after funding fee)",
        escrow_amount
    );
    println!("  Seller gets:  {} sompi (90%)", seller_amount);
    println!("  Platform fee: {} sompi (10%)", fee_amount);

    // Build the amount-constrained escrow script
    //   OpIf
    //     <owner_pk> OpCheckSig                              // Escape: owner overrides
    //   OpElse
    //     <seller_spk> 0 OpTxOutputSpk OpEqualVerify         // Output 0 -> seller
    //     0 OpTxOutputAmount <seller_amount> OpGreaterThanOrEqual OpVerify
    //     <fee_spk> 1 OpTxOutputSpk OpEqualVerify            // Output 1 -> fee
    //     1 OpTxOutputAmount <fee_amount> OpGreaterThanOrEqual  // Final check on stack
    //   OpEndIf
    let redeem_script = ScriptBuilder::new()
        .add_op(OpIf)?
        .add_data(&owner_pk)?
        .add_op(OpCheckSig)?
        .add_op(OpElse)?
        // Output 0: seller destination
        .add_data(&seller_spk_bytes)?
        .add_i64(0)?
        .add_op(OpTxOutputSpk)?
        .add_op(OpEqualVerify)?
        // Output 0: seller amount
        .add_i64(0)?
        .add_op(OpTxOutputAmount)?
        .add_i64(seller_amount as i64)?
        .add_op(OpGreaterThanOrEqual)?
        .add_op(OpVerify)?
        // Output 1: fee destination
        .add_data(&fee_spk_bytes)?
        .add_i64(1)?
        .add_op(OpTxOutputSpk)?
        .add_op(OpEqualVerify)?
        // Output 1: fee amount (final — leaves bool on stack)
        .add_i64(1)?
        .add_op(OpTxOutputAmount)?
        .add_i64(fee_amount as i64)?
        .add_op(OpGreaterThanOrEqual)?
        .add_op(OpEndIf)?
        .drain();

    let p2sh_spk = pay_to_script_hash_script(&redeem_script);
    println!("  Redeem script: {} bytes", redeem_script.len());

    // Step 6: Build and submit funding transaction (buyer -> escrow P2SH)
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

    // Step 7: Wait for escrow UTXO to finalize
    print_step(7, "Waiting for escrow UTXO to finalize...");
    println!("  Escrow at outpoint {}:0", funding_tx_id);

    // Step 8: Build and submit covenant release transaction
    // This is the key test — no signatures needed!
    // The script validates: output 0 goes to seller, output 1 goes to fee address,
    // both with minimum amounts enforced by the covenant.
    print_step(
        8,
        "Building covenant payment split release (no signatures!)...",
    );
    let escrow_outpoint = TransactionOutpoint::new(funding_tx_id, 0);

    let escrow_utxo =
        kaspa_consensus_core::tx::UtxoEntry::new(escrow_amount, p2sh_spk, 0, false, None);

    let release_tx_id;
    let max_retries = 30;
    let mut attempt = 0;
    loop {
        attempt += 1;

        let release_input = TransactionInput {
            previous_outpoint: escrow_outpoint.clone(),
            signature_script: vec![],
            sequence: 0,
            sig_op_count: 4,
        };
        // Two outputs: seller payment + platform fee
        let release_outputs = vec![
            TransactionOutput {
                value: seller_amount,
                script_public_key: seller_spk.clone(),
                covenant: None,
            },
            TransactionOutput {
                value: fee_amount,
                script_public_key: fee_spk.clone(),
                covenant: None,
            },
        ];
        let release_tx = Transaction::new(
            1,
            vec![release_input],
            release_outputs,
            0,
            Default::default(),
            0,
            vec![],
        );

        // sig_script for release branch: OpFalse (select covenant branch) + redeem script
        let mut sb = ScriptBuilder::new();
        sb.add_op(OpFalse)?;
        sb.add_data(&redeem_script)?;
        let sig_script = sb.drain();

        let mut signed_release_tx = release_tx;
        signed_release_tx.inputs[0].signature_script = sig_script;

        if attempt == 1 {
            verify_script(&signed_release_tx, &escrow_utxo)
                .map_err(|e| format!("Release tx failed local verification: {e}"))?;
            println!("  Local verify: OK");
            println!(
                "  (Covenant enforced: output 0 -> seller >= {} sompi, output 1 -> fee >= {} sompi)",
                seller_amount, fee_amount
            );
        }

        let rpc_release: RpcTransaction = (&signed_release_tx).into();
        match client.submit_transaction(rpc_release, false).await {
            Ok(tx_id) => {
                release_tx_id = tx_id;
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
                return Err(format!("Release tx rejected after {attempt} attempts: {e}").into());
            }
        }
    }
    if attempt > 1 {
        eprintln!();
    }
    println!("  Release TX submitted: {}", release_tx_id);

    // Step 9: Verify seller and fee address received funds
    print_step(9, "Verifying payment split...");
    tokio::time::sleep(Duration::from_secs(5)).await;

    let seller_utxos = client
        .get_utxos_by_addresses(vec![seller_addr.clone()])
        .await?;
    if let Some(entry) = seller_utxos.first() {
        println!("  Seller received:  {} sompi", entry.utxo_entry.amount);
    } else {
        println!("  Seller UTXO pending... (may need another block)");
    }

    let fee_utxos = client
        .get_utxos_by_addresses(vec![fee_addr.clone()])
        .await?;
    if let Some(entry) = fee_utxos.first() {
        println!("  Fee addr received: {} sompi", entry.utxo_entry.amount);
    } else {
        println!("  Fee UTXO pending... (may need another block)");
    }

    if seller_utxos.first().is_some() && fee_utxos.first().is_some() {
        println!("  Covenant payment split successful!");
    }

    // Step 10: Bonus — test that owner escape also works on-chain
    // We need a second UTXO for this. Check if one is available.
    print_step(10, "Testing owner escape path...");
    let buyer_utxos = client
        .get_utxos_by_addresses(vec![buyer_addr.clone()])
        .await?;

    let info = client.get_block_dag_info().await?;
    let current_daa = info.virtual_daa_score;
    let escape_utxo = buyer_utxos.iter().find(|e| {
        !e.utxo_entry.is_coinbase || current_daa >= e.utxo_entry.block_daa_score + coinbase_maturity
    });

    if let Some(entry) = escape_utxo {
        let escape_utxo_amount = entry.utxo_entry.amount;
        let escape_outpoint =
            TransactionOutpoint::new(entry.outpoint.transaction_id, entry.outpoint.index);
        println!("  Found second mature UTXO: {} sompi", escape_utxo_amount);

        if escape_utxo_amount <= funding_fee + release_fee {
            println!("  UTXO too small for escape test, skipping");
        } else {
            let escape_escrow_amount = escape_utxo_amount - funding_fee;

            // Build a new escrow with same script, fund it, then owner-escape it
            let escape_p2sh_spk = pay_to_script_hash_script(&redeem_script);

            // Fund the second escrow
            let fund_input = TransactionInput {
                previous_outpoint: escape_outpoint,
                signature_script: vec![],
                sequence: 0,
                sig_op_count: 1,
            };
            let fund_output = TransactionOutput {
                value: escape_escrow_amount,
                script_public_key: escape_p2sh_spk.clone(),
                covenant: None,
            };
            let fund_tx = Transaction::new(
                1,
                vec![fund_input],
                vec![fund_output],
                0,
                Default::default(),
                0,
                vec![],
            );

            let buyer_utxo_spk = pay_to_address_script(&buyer_addr);
            let buyer_utxo_entry = kaspa_consensus_core::tx::UtxoEntry::new(
                escape_utxo_amount,
                buyer_utxo_spk,
                0,
                false,
                None,
            );

            let fund_sig = schnorr_sign(&fund_tx, &buyer_utxo_entry, &buyer_kp);
            let fund_sig_script = build_p2pk_sig_script(&fund_sig);

            let mut signed_fund_tx = fund_tx;
            signed_fund_tx.inputs[0].signature_script = fund_sig_script;

            verify_script(&signed_fund_tx, &buyer_utxo_entry)
                .map_err(|e| format!("Escape funding tx failed local verification: {e}"))?;

            let rpc_fund: RpcTransaction = (&signed_fund_tx).into();
            let fund_tx_id = client.submit_transaction(rpc_fund, false).await?;
            println!("  Escape escrow funded: {}", fund_tx_id);

            // Build owner escape tx — owner signs, sends to buyer (arbitrary destination)
            let escape_outpoint2 = TransactionOutpoint::new(fund_tx_id, 0);
            let escape_amount = escape_escrow_amount - release_fee;

            let escape_escrow_utxo = kaspa_consensus_core::tx::UtxoEntry::new(
                escape_escrow_amount,
                escape_p2sh_spk,
                0,
                false,
                None,
            );

            let mut escape_attempt = 0;
            let escape_tx_id;
            loop {
                escape_attempt += 1;

                let escape_input = TransactionInput {
                    previous_outpoint: escape_outpoint2.clone(),
                    signature_script: vec![],
                    sequence: 0,
                    sig_op_count: 4,
                };
                let escape_output = TransactionOutput {
                    value: escape_amount,
                    script_public_key: pay_to_address_script(&buyer_addr),
                    covenant: None,
                };
                let escape_tx = Transaction::new(
                    1,
                    vec![escape_input],
                    vec![escape_output],
                    0,
                    Default::default(),
                    0,
                    vec![],
                );

                // Owner signs + OpTrue (select escape branch) + redeem script
                let owner_sig = schnorr_sign(&escape_tx, &escape_escrow_utxo, &owner_kp);
                let mut sb = ScriptBuilder::new();
                sb.add_data(&owner_sig)?;
                sb.add_op(kaspa_txscript::opcodes::codes::OpTrue)?;
                sb.add_data(&redeem_script)?;
                let sig_script = sb.drain();

                let mut signed_escape_tx = escape_tx;
                signed_escape_tx.inputs[0].signature_script = sig_script;

                if escape_attempt == 1 {
                    verify_script(&signed_escape_tx, &escape_escrow_utxo)
                        .map_err(|e| format!("Escape tx failed local verification: {e}"))?;
                    println!("  Escape local verify: OK");
                }

                let rpc_escape: RpcTransaction = (&signed_escape_tx).into();
                match client.submit_transaction(rpc_escape, false).await {
                    Ok(tx_id) => {
                        escape_tx_id = tx_id;
                        break;
                    }
                    Err(e) => {
                        let err_msg = format!("{e}");
                        if err_msg.contains("not finalized") && escape_attempt < max_retries {
                            if escape_attempt == 1 {
                                eprint!("  Waiting for finalization");
                            }
                            eprint!(".");
                            tokio::time::sleep(Duration::from_secs(5)).await;
                            continue;
                        }
                        if escape_attempt > 1 {
                            eprintln!();
                        }
                        return Err(format!(
                            "Escape tx rejected after {escape_attempt} attempts: {e}"
                        )
                        .into());
                    }
                }
            }
            if escape_attempt > 1 {
                eprintln!();
            }
            println!("  Owner escape TX submitted: {}", escape_tx_id);
            println!(
                "  Owner escaped {} sompi back to buyer (no covenant constraints!)",
                escape_amount
            );
        }
    } else {
        println!("  No second mature UTXO available — skipping owner escape test");
        println!("  (Mine more blocks to get another mature UTXO)");
    }

    client.disconnect().await?;
    println!("\n=== Live amount-constrained escrow complete ===");
    println!("  Proved on-chain: multi-output covenant payment routing");
    println!("  OpTxOutputSpk + OpTxOutputAmount enforced across 2 outputs\n");
    Ok(())
}
