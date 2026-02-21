//! Live SDK Integration Test (Full) on Testnet 12
//!
//! End-to-end test of the remaining EscrowBuilder SDK patterns:
//! 1. Self-funds from wallet mnemonic in `.tn12rc`
//! 2. Arbitrated 2-of-3 multisig (dispute resolution: arbitrator + seller)
//! 3. TimeLocked escrow (buyer-only timeout refund with CLTV)
//! 4. CovenantMultiPath (covenant-enforced timeout refund, no signatures)
//!
//! Usage:
//!   cargo run --example live_sdk_escrow_full
//!
//! Requires:
//!   - kaspad running with --rpclisten-borsh=127.0.0.1:17110 --utxoindex
//!   - `.tn12rc` file with wallet mnemonic (12 words, one line)

use kaspa_addresses::{Address, Prefix, Version};
use kaspa_bip32::{DerivationPath, ExtendedPrivateKey, Language, Mnemonic, SecretKey};
use kaspa_consensus_core::tx::{
    Transaction, TransactionId, TransactionInput, TransactionOutpoint, TransactionOutput, UtxoEntry,
};
use kaspa_escrow_lab::sdk::{
    Branch, EscrowBuilder, EscrowConfig, EscrowPattern,
    tx::{build_funding_tx, build_refund_tx, build_release_tx, build_sig_script},
};
use kaspa_escrow_lab::*;
use kaspa_rpc_core::RpcTransaction;
use kaspa_txscript::pay_to_address_script;
use kaspa_wrpc_client::KaspaRpcClient;
use kaspa_wrpc_client::prelude::*;
use std::time::Duration;

/// Poll until a mature UTXO appears at the given address.
async fn poll_for_utxo(
    client: &KaspaRpcClient,
    address: &Address,
) -> Result<(TransactionOutpoint, u64), Box<dyn std::error::Error>> {
    let max_wait = Duration::from_secs(600);
    let start = std::time::Instant::now();
    let mut poll_count = 0u64;
    let coinbase_maturity: u64 = 1000;

    loop {
        let info = client.get_block_dag_info().await?;
        let current_daa = info.virtual_daa_score;
        let utxos = client.get_utxos_by_addresses(vec![address.clone()]).await?;
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
                "  Found UTXO: {} sompi (tx: {})",
                entry.utxo_entry.amount, entry.outpoint.transaction_id
            );
            return Ok((op, entry.utxo_entry.amount));
        }
        if start.elapsed() > max_wait {
            return Err("Timed out waiting for funds. Check the faucet and try again.".into());
        }
        poll_count += 1;
        if poll_count.is_multiple_of(15) {
            eprintln!(" ({}s)", start.elapsed().as_secs());
        } else {
            eprint!(".");
        }
        tokio::time::sleep(Duration::from_secs(2)).await;
    }
}

/// Submit a transaction with retry for finalization.
async fn submit_with_retry(
    client: &KaspaRpcClient,
    rpc_tx: RpcTransaction,
) -> Result<TransactionId, Box<dyn std::error::Error>> {
    let max_retries = 30;
    for attempt in 1..=max_retries {
        match client.submit_transaction(rpc_tx.clone(), false).await {
            Ok(id) => {
                if attempt > 1 {
                    eprintln!();
                }
                return Ok(id);
            }
            Err(e) => {
                let msg = format!("{e}");
                if msg.contains("not finalized") && attempt < max_retries {
                    if attempt == 1 {
                        eprint!("  Waiting for finalization");
                    }
                    eprint!(".");
                    tokio::time::sleep(Duration::from_secs(3)).await;
                    continue;
                }
                if attempt > 1 {
                    eprintln!();
                }
                return Err(format!("TX rejected after {attempt} attempts: {e}").into());
            }
        }
    }
    unreachable!()
}

/// Check and print the balance at an address.
async fn check_balance(client: &KaspaRpcClient, address: &Address, label: &str) -> Option<u64> {
    let utxos = client
        .get_utxos_by_addresses(vec![address.clone()])
        .await
        .ok()?;
    if let Some(entry) = utxos.first() {
        println!("  {} received: {} sompi", label, entry.utxo_entry.amount);
        Some(entry.utxo_entry.amount)
    } else {
        println!("  {} UTXO pending...", label);
        None
    }
}

/// Submit a refund transaction with retry, rebuilding the tx each attempt
/// to get a fresh DAA score for the lock_time field.
///
/// For TimeLocked pattern, pass `sign_keypair = Some(&buyer_kp)` to re-sign each attempt
/// (changing lock_time changes the sighash). For CovenantMultiPath, pass `None`.
async fn submit_refund_with_retry(
    client: &KaspaRpcClient,
    escrow_outpoint: TransactionOutpoint,
    escrow: &EscrowConfig,
    escrow_utxo: &UtxoEntry,
    fee: u64,
    branch: &Branch,
    sign_keypair: Option<&secp256k1::Keypair>,
) -> Result<TransactionId, Box<dyn std::error::Error>> {
    let max_retries = 30;
    for attempt in 1..=max_retries {
        // Get fresh DAA for lock_time
        let info = client.get_block_dag_info().await?;
        let current_daa = info.virtual_daa_score;

        // Build refund tx with current DAA as lock_time
        let refund_tx = build_refund_tx(escrow_outpoint, escrow, current_daa, fee)?;

        // Build sig script (with or without signature)
        let sigs: Vec<Vec<u8>> = if let Some(kp) = sign_keypair {
            let sig = schnorr_sign(&refund_tx, escrow_utxo, kp);
            vec![sig]
        } else {
            vec![]
        };

        let sig_script = build_sig_script(branch, &sigs, &escrow.redeem_script, &escrow.pattern)?;

        let mut signed_refund = refund_tx;
        signed_refund.inputs[0].signature_script = sig_script;

        // Local verify on first attempt
        if attempt == 1 {
            verify_script(&signed_refund, escrow_utxo)
                .map_err(|e| format!("Refund tx failed local verification: {e}"))?;
            println!("  Refund local verify: OK");
            println!("  Current DAA: {current_daa} (lock_time in script: past)");
        }

        let rpc_refund: RpcTransaction = (&signed_refund).into();
        match client.submit_transaction(rpc_refund, false).await {
            Ok(id) => {
                if attempt > 1 {
                    eprintln!();
                }
                return Ok(id);
            }
            Err(e) => {
                let msg = format!("{e}");
                if msg.contains("not finalized") && attempt < max_retries {
                    if attempt == 1 {
                        eprint!("  Waiting for finalization");
                    }
                    eprint!(".");
                    tokio::time::sleep(Duration::from_secs(3)).await;
                    continue;
                }
                if attempt > 1 {
                    eprintln!();
                }
                return Err(format!("Refund TX rejected after {attempt} attempts: {e}").into());
            }
        }
    }
    unreachable!()
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    print_header("Live SDK Full Integration Test on Testnet 12");

    // ── Step 1: Connect ─────────────────────────────────────────
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
            "Failed to connect: {e}\n  \
             Is kaspad running with --rpclisten-borsh=127.0.0.1:17110?"
        )
    })?;

    let info = client.get_block_dag_info().await?;
    println!(
        "  Connected! Network: {}, DAA: {}",
        info.network, info.virtual_daa_score
    );

    // ── Step 2: Load or generate keypairs ───────────────────────
    print_step(2, "Loading keypairs...");
    let keys_path = std::path::Path::new("/tmp/sdk_escrow_full_keys.json");
    let (buyer_kp, buyer_pk, seller_kp, seller_pk, arb_kp, arb_pk) = if keys_path.exists() {
        let data = std::fs::read_to_string(keys_path)?;
        let v: serde_json::Value = serde_json::from_str(&data)?;
        let load_kp =
            |field: &str| -> Result<(secp256k1::Keypair, [u8; 32]), Box<dyn std::error::Error>> {
                let secret = hex::decode(v[field].as_str().ok_or(format!("missing {field}"))?)?;
                let kp = secp256k1::Keypair::from_seckey_slice(secp256k1::SECP256K1, &secret)?;
                let pk = kp.x_only_public_key().0.serialize();
                Ok((kp, pk))
            };
        let (buyer_kp, buyer_pk) = load_kp("buyer_secret")?;
        let (seller_kp, seller_pk) = load_kp("seller_secret")?;
        let (arb_kp, arb_pk) = load_kp("arbitrator_secret")?;
        println!("  Reloaded from {}", keys_path.display());
        (buyer_kp, buyer_pk, seller_kp, seller_pk, arb_kp, arb_pk)
    } else {
        let (buyer_kp, buyer_pk) = generate_keypair();
        let (seller_kp, seller_pk) = generate_keypair();
        let (arb_kp, arb_pk) = generate_keypair();
        let data = serde_json::json!({
            "buyer_secret": hex::encode(buyer_kp.secret_bytes()),
            "seller_secret": hex::encode(seller_kp.secret_bytes()),
            "arbitrator_secret": hex::encode(arb_kp.secret_bytes()),
        });
        std::fs::write(keys_path, serde_json::to_string_pretty(&data)?)?;
        println!("  Generated new keypairs, saved to {}", keys_path.display());
        (buyer_kp, buyer_pk, seller_kp, seller_pk, arb_kp, arb_pk)
    };

    let buyer_addr = testnet_address(&buyer_pk);
    let seller_addr = testnet_address(&seller_pk);
    println!("  Buyer:      {}", buyer_addr);
    println!("  Seller:     {}", seller_addr);
    println!("  Arbitrator: {}", hex::encode(arb_pk));

    // ── Step 3: Check if buyer already funded, else fund from wallet ─
    print_step(3, "Checking buyer balance...");
    let buyer_utxos = client
        .get_utxos_by_addresses(vec![buyer_addr.clone()])
        .await?;
    let current_daa = info.virtual_daa_score;
    let already_funded = buyer_utxos.iter().any(|e| {
        let mature =
            !e.utxo_entry.is_coinbase || current_daa >= e.utxo_entry.block_daa_score + 1000;
        mature && e.utxo_entry.amount >= 100_000_000
    });

    if already_funded {
        println!("  Buyer already has funds!");
    } else {
        println!("  No funds yet. Funding from wallet mnemonic...");
        let rc_path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join(".tn12rc");
        let phrase = std::fs::read_to_string(&rc_path)
            .map_err(|_| "No .tn12rc found. Create it with: echo \"word1 ... word12\" > .tn12rc")?;
        let mnemonic = Mnemonic::new(phrase.trim(), Language::English)?;
        let seed = mnemonic.to_seed("");
        let master = ExtendedPrivateKey::<SecretKey>::new(seed)?;

        let mut wallet_funded = false;

        'fund: for acct in 0u32..3 {
            for idx in 0u32..20 {
                let path_str = format!("m/44'/111111'/{acct}'/0/{idx}");
                let path: DerivationPath = path_str.parse()?;
                let key = master.clone().derive_path(&path)?;
                let sk = key.private_key();
                let pk = secp256k1::PublicKey::from_secret_key(secp256k1::SECP256K1, sk);
                let xonly = pk.x_only_public_key().0.serialize();
                let wallet_addr = Address::new(Prefix::Testnet, Version::PubKey, &xonly);

                let utxos = client
                    .get_utxos_by_addresses(vec![wallet_addr.clone()])
                    .await?;
                let mature = utxos.iter().find(|e| {
                    let ok = !e.utxo_entry.is_coinbase
                        || current_daa >= e.utxo_entry.block_daa_score + 1000;
                    ok && e.utxo_entry.amount >= 100_000_000
                });
                if let Some(entry) = mature {
                    let wallet_kp = secp256k1::Keypair::from_secret_key(secp256k1::SECP256K1, sk);
                    let utxo_amount = entry.utxo_entry.amount;
                    let op = TransactionOutpoint::new(
                        entry.outpoint.transaction_id,
                        entry.outpoint.index,
                    );
                    let fee = 5_000u64;
                    let send = utxo_amount - fee;
                    println!("  Found wallet UTXO at {path_str}: {utxo_amount} sompi");
                    println!("  Sending {send} sompi to buyer...");

                    let input = TransactionInput {
                        previous_outpoint: op,
                        signature_script: vec![],
                        sequence: 0,
                        sig_op_count: 1,
                    };
                    let output = TransactionOutput {
                        value: send,
                        script_public_key: pay_to_address_script(&buyer_addr),
                        covenant: None,
                    };
                    let tx = Transaction::new(
                        1,
                        vec![input],
                        vec![output],
                        0,
                        Default::default(),
                        0,
                        vec![],
                    );
                    let wallet_spk = pay_to_address_script(&wallet_addr);
                    let utxo_entry = UtxoEntry::new(utxo_amount, wallet_spk, 0, false, None);
                    let sig = schnorr_sign(&tx, &utxo_entry, &wallet_kp);
                    let mut signed = tx;
                    signed.inputs[0].signature_script = build_p2pk_sig_script(&sig);
                    verify_script(&signed, &utxo_entry)
                        .map_err(|e| format!("Wallet funding verify failed: {e}"))?;
                    let rpc_tx: RpcTransaction = (&signed).into();
                    let tx_id = client.submit_transaction(rpc_tx, false).await?;
                    println!("  Funded! TX: {}", tx_id);
                    wallet_funded = true;
                    break 'fund;
                }
            }
        }
        if !wallet_funded {
            return Err("No funded wallet address found in .tn12rc mnemonic".into());
        }
    }

    // Wait for buyer UTXO to appear
    if !already_funded {
        println!("  Waiting for confirmation...");
        tokio::time::sleep(Duration::from_secs(15)).await;
    }
    println!("  Polling for buyer UTXO...");
    let (outpoint, utxo_amount) = poll_for_utxo(&client, &buyer_addr).await?;

    // ═════════════════════════════════════════════════════════════
    // TEST 1: Arbitrated 2-of-3 — dispute resolution
    // ═════════════════════════════════════════════════════════════
    print_step(4, "TEST 1: Arbitrated 2-of-3 dispute release via SDK");
    println!("  (Arbitrator + seller sign to resolve dispute in seller's favor)");

    let arb_funding_fee = 5_000u64;
    let arb_release_fee = 5_000u64;

    let arb_escrow_amount = utxo_amount
        .checked_sub(arb_funding_fee)
        .ok_or("UTXO too small for fees")?;

    let arb_escrow = EscrowBuilder::new(EscrowPattern::Arbitrated)
        .buyer(buyer_pk)
        .seller(seller_pk)
        .arbitrator(arb_pk)
        .amount(arb_escrow_amount)
        .build()?;

    println!("  UTXO:    {} sompi", utxo_amount);
    println!("  Escrow:  {} sompi", arb_escrow_amount);
    println!("  Script:  {} bytes", arb_escrow.redeem_script.len());

    // Fund the escrow from buyer's UTXO
    let arb_funding = build_funding_tx(outpoint, utxo_amount, &arb_escrow, arb_funding_fee)?;
    let buyer_spk = pay_to_address_script(&buyer_addr);
    let buyer_utxo = UtxoEntry::new(utxo_amount, buyer_spk, 0, false, None);

    let sig = schnorr_sign(&arb_funding, &buyer_utxo, &buyer_kp);
    let mut signed_arb_funding = arb_funding;
    signed_arb_funding.inputs[0].signature_script = build_p2pk_sig_script(&sig);

    verify_script(&signed_arb_funding, &buyer_utxo)
        .map_err(|e| format!("Arb funding verify failed: {e}"))?;
    println!("  Funding local verify: OK");

    let rpc_arb_fund: RpcTransaction = (&signed_arb_funding).into();
    let arb_funding_id = client.submit_transaction(rpc_arb_fund, false).await?;
    println!("  Funding TX: {}", arb_funding_id);

    // Release with arbitrator + seller (dispute resolution)
    let arb_escrow_outpoint = TransactionOutpoint::new(arb_funding_id, 0);
    let arb_on_chain = utxo_amount - arb_funding_fee;
    let arb_escrow_utxo = UtxoEntry::new(arb_on_chain, arb_escrow.p2sh_spk.clone(), 0, false, None);

    let arb_release = build_release_tx(arb_escrow_outpoint, &arb_escrow, arb_release_fee)?;

    // Signatures must match pubkey order in script:
    // Script is: 2 <buyer> <seller> <arbitrator> 3 OpCheckMultiSig
    // We provide sigs for positions 1 (seller) and 2 (arbitrator).
    let seller_sig = schnorr_sign(&arb_release, &arb_escrow_utxo, &seller_kp);
    let arb_sig = schnorr_sign(&arb_release, &arb_escrow_utxo, &arb_kp);

    let arb_sig_script = build_sig_script(
        &Branch::Normal,
        &[seller_sig, arb_sig],
        &arb_escrow.redeem_script,
        &arb_escrow.pattern,
    )?;

    let mut signed_arb_release = arb_release;
    signed_arb_release.inputs[0].signature_script = arb_sig_script;

    verify_script(&signed_arb_release, &arb_escrow_utxo)
        .map_err(|e| format!("Arb release verify failed: {e}"))?;
    println!("  Dispute release local verify: OK (arbitrator + seller)");

    let rpc_arb_release: RpcTransaction = (&signed_arb_release).into();
    let arb_release_id = submit_with_retry(&client, rpc_arb_release).await?;
    println!("  Release TX: {}", arb_release_id);

    // Verify seller received funds
    tokio::time::sleep(Duration::from_secs(3)).await;
    check_balance(&client, &seller_addr, "Seller").await;
    println!("  TEST 1 PASSED: Arbitrated 2-of-3 dispute release on-chain!");

    // ═════════════════════════════════════════════════════════════
    // TEST 2: TimeLocked — buyer-only timeout refund with CLTV
    // ═════════════════════════════════════════════════════════════
    print_step(5, "TEST 2: TimeLocked CLTV timeout refund via SDK");
    println!("  (Using seller's proceeds from test 1)");
    println!("  (Buyer-only refund after CLTV timeout)");

    // Wait for seller's UTXO from the release
    println!("  Polling for seller's UTXO...");
    let (seller_outpoint, seller_utxo_amount) = poll_for_utxo(&client, &seller_addr).await?;

    let tl_funding_fee = 5_000u64;
    let tl_refund_fee = 5_000u64;

    // Get current DAA to set lock_time in the past (immediately available)
    let info = client.get_block_dag_info().await?;
    let tl_lock_time = info.virtual_daa_score.saturating_sub(10);

    let tl_escrow_amount = seller_utxo_amount
        .checked_sub(tl_funding_fee)
        .ok_or("Seller UTXO too small")?;

    // Seller funds escrow, buyer gets the refund
    let tl_escrow = EscrowBuilder::new(EscrowPattern::TimeLocked {
        lock_time: tl_lock_time,
    })
    .buyer(buyer_pk)
    .seller(seller_pk)
    .amount(tl_escrow_amount)
    .build()?;

    println!("  Seller UTXO: {} sompi", seller_utxo_amount);
    println!("  Escrow:      {} sompi", tl_escrow_amount);
    println!("  Lock time:   {} (DAA score, already past)", tl_lock_time);
    println!("  Script:      {} bytes", tl_escrow.redeem_script.len());

    // Fund from seller's UTXO
    let tl_funding = build_funding_tx(
        seller_outpoint,
        seller_utxo_amount,
        &tl_escrow,
        tl_funding_fee,
    )?;
    let seller_spk = pay_to_address_script(&seller_addr);
    let seller_utxo = UtxoEntry::new(seller_utxo_amount, seller_spk, 0, false, None);

    let seller_fund_sig = schnorr_sign(&tl_funding, &seller_utxo, &seller_kp);
    let mut signed_tl_funding = tl_funding;
    signed_tl_funding.inputs[0].signature_script = build_p2pk_sig_script(&seller_fund_sig);

    verify_script(&signed_tl_funding, &seller_utxo)
        .map_err(|e| format!("TimeLocked funding verify failed: {e}"))?;
    println!("  Funding local verify: OK");

    let rpc_tl_fund: RpcTransaction = (&signed_tl_funding).into();
    let tl_funding_id = client.submit_transaction(rpc_tl_fund, false).await?;
    println!("  Funding TX: {}", tl_funding_id);

    // Refund with buyer-only signature after timeout
    let tl_escrow_outpoint = TransactionOutpoint::new(tl_funding_id, 0);
    let tl_on_chain = seller_utxo_amount - tl_funding_fee;
    let tl_escrow_utxo = UtxoEntry::new(tl_on_chain, tl_escrow.p2sh_spk.clone(), 0, false, None);

    println!("  Submitting timeout refund (buyer-only CLTV)...");
    let tl_refund_id = submit_refund_with_retry(
        &client,
        tl_escrow_outpoint,
        &tl_escrow,
        &tl_escrow_utxo,
        tl_refund_fee,
        &Branch::Timeout,
        Some(&buyer_kp), // TimeLocked requires buyer signature
    )
    .await?;
    println!("  Refund TX: {}", tl_refund_id);

    // Verify buyer received refund
    tokio::time::sleep(Duration::from_secs(3)).await;
    check_balance(&client, &buyer_addr, "Buyer (refund)").await;
    println!("  TEST 2 PASSED: TimeLocked CLTV timeout refund on-chain!");

    // ═════════════════════════════════════════════════════════════
    // TEST 3: CovenantMultiPath — covenant-enforced timeout refund
    // ═════════════════════════════════════════════════════════════
    print_step(
        6,
        "TEST 3: CovenantMultiPath covenant timeout refund via SDK",
    );
    println!("  (Using buyer's refund proceeds from test 2)");
    println!("  (No signatures — covenant enforces output address + amount)");

    // Wait for buyer's UTXO from the refund
    println!("  Polling for buyer's UTXO...");
    let (buyer_outpoint2, buyer_utxo_amount2) = poll_for_utxo(&client, &buyer_addr).await?;

    let cm_funding_fee = 5_000u64;
    let cm_refund_fee = 10_000u64; // Must be <= COVENANT_FEE_BUFFER (10_000)

    // Get current DAA for lock_time
    let info = client.get_block_dag_info().await?;
    let cm_lock_time = info.virtual_daa_score.saturating_sub(10);

    let cm_escrow_amount = buyer_utxo_amount2
        .checked_sub(cm_funding_fee)
        .ok_or("Buyer UTXO too small")?;

    let cm_escrow = EscrowBuilder::new(EscrowPattern::CovenantMultiPath {
        lock_time: cm_lock_time,
    })
    .buyer(buyer_pk)
    .seller(seller_pk)
    .arbitrator(arb_pk)
    .amount(cm_escrow_amount)
    .build()?;

    println!("  Buyer UTXO: {} sompi", buyer_utxo_amount2);
    println!("  Escrow:     {} sompi", cm_escrow_amount);
    println!("  Lock time:  {} (DAA score, already past)", cm_lock_time);
    println!("  Script:     {} bytes", cm_escrow.redeem_script.len());

    // Fund from buyer's UTXO
    let cm_funding = build_funding_tx(
        buyer_outpoint2,
        buyer_utxo_amount2,
        &cm_escrow,
        cm_funding_fee,
    )?;
    let buyer_spk2 = pay_to_address_script(&buyer_addr);
    let buyer_utxo2 = UtxoEntry::new(buyer_utxo_amount2, buyer_spk2, 0, false, None);

    let buyer_fund_sig = schnorr_sign(&cm_funding, &buyer_utxo2, &buyer_kp);
    let mut signed_cm_funding = cm_funding;
    signed_cm_funding.inputs[0].signature_script = build_p2pk_sig_script(&buyer_fund_sig);

    verify_script(&signed_cm_funding, &buyer_utxo2)
        .map_err(|e| format!("CovenantMultiPath funding verify failed: {e}"))?;
    println!("  Funding local verify: OK");

    let rpc_cm_fund: RpcTransaction = (&signed_cm_funding).into();
    let cm_funding_id = client.submit_transaction(rpc_cm_fund, false).await?;
    println!("  Funding TX: {}", cm_funding_id);

    // Covenant timeout refund — NO signatures!
    let cm_escrow_outpoint = TransactionOutpoint::new(cm_funding_id, 0);
    let cm_on_chain = buyer_utxo_amount2 - cm_funding_fee;
    let cm_escrow_utxo = UtxoEntry::new(cm_on_chain, cm_escrow.p2sh_spk.clone(), 0, false, None);

    println!("  Submitting covenant timeout refund (zero signatures)...");
    let cm_refund_id = submit_refund_with_retry(
        &client,
        cm_escrow_outpoint,
        &cm_escrow,
        &cm_escrow_utxo,
        cm_refund_fee,
        &Branch::Timeout,
        None, // CovenantMultiPath timeout needs NO signatures
    )
    .await?;
    println!("  Refund TX: {}", cm_refund_id);

    // Verify buyer received refund
    tokio::time::sleep(Duration::from_secs(3)).await;
    check_balance(&client, &buyer_addr, "Buyer (covenant refund)").await;
    println!("  TEST 3 PASSED: CovenantMultiPath covenant timeout on-chain!");

    // ── Summary ─────────────────────────────────────────────────
    client.disconnect().await?;
    println!();
    println!("=== Live SDK Full Integration Test Complete ===");
    println!();
    println!("  Test 1: Arbitrated 2-of-3 (dispute: arbitrator + seller)");
    println!("    Funding:  {}", arb_funding_id);
    println!("    Release:  {}", arb_release_id);
    println!();
    println!("  Test 2: TimeLocked CLTV timeout refund (buyer-only sig)");
    println!("    Funding:  {}", tl_funding_id);
    println!("    Refund:   {}", tl_refund_id);
    println!();
    println!("  Test 3: CovenantMultiPath timeout (no sigs, covenant-enforced)");
    println!("    Funding:  {}", cm_funding_id);
    println!("    Refund:   {}", cm_refund_id);
    println!();
    println!("  All transactions submitted via EscrowBuilder SDK.");
    println!("  View on explorer: https://tn12.kaspa.stream");
    println!();

    Ok(())
}
