//! Live SDK Integration Test on Testnet 12
//!
//! End-to-end test of the EscrowBuilder SDK against a running TN12 node:
//! 1. Self-funds from wallet mnemonic in `.tn12rc`
//! 2. PaymentSplit covenant release (no signatures — covenant-enforced output routing)
//! 3. Basic 2-of-2 multisig release (chained from covenant proceeds)
//!
//! Usage:
//!   cargo run --example live_sdk_escrow
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
    Branch, EscrowBuilder, EscrowPattern,
    tx::{build_funding_tx, build_payment_split_tx, build_release_tx, build_sig_script},
};
use kaspa_escrow_lab::*;
use kaspa_rpc_core::RpcTransaction;
use kaspa_txscript::pay_to_address_script;
use kaspa_wrpc_client::KaspaRpcClient;
use kaspa_wrpc_client::prelude::*;
use serde_json;
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

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    print_header("Live SDK Integration Test on Testnet 12");

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
    let keys_path = std::path::Path::new("/tmp/sdk_escrow_keys.json");
    let (buyer_kp, buyer_pk, seller_kp, seller_pk, owner_pk, fee_pk) = if keys_path.exists() {
        let data = std::fs::read_to_string(keys_path)?;
        let v: serde_json::Value = serde_json::from_str(&data)?;
        let load_kp = |field: &str| -> Result<(secp256k1::Keypair, [u8; 32]), Box<dyn std::error::Error>> {
            let secret = hex::decode(v[field].as_str().ok_or(format!("missing {field}"))?)?;
            let kp = secp256k1::Keypair::from_seckey_slice(secp256k1::SECP256K1, &secret)?;
            let pk = kp.x_only_public_key().0.serialize();
            Ok((kp, pk))
        };
        let load_pk = |field: &str| -> Result<[u8; 32], Box<dyn std::error::Error>> {
            let bytes = hex::decode(v[field].as_str().ok_or(format!("missing {field}"))?)?;
            Ok(bytes.try_into().map_err(|_| "bad pk length")?)
        };
        let (buyer_kp, buyer_pk) = load_kp("buyer_secret")?;
        let (seller_kp, seller_pk) = load_kp("seller_secret")?;
        let owner_pk = load_pk("owner_pk")?;
        let fee_pk = load_pk("fee_pk")?;
        println!("  Reloaded from {}", keys_path.display());
        (buyer_kp, buyer_pk, seller_kp, seller_pk, owner_pk, fee_pk)
    } else {
        let (buyer_kp, buyer_pk) = generate_keypair();
        let (seller_kp, seller_pk) = generate_keypair();
        let (_, owner_pk) = generate_keypair();
        let (_, fee_pk) = generate_keypair();
        let data = serde_json::json!({
            "buyer_secret": hex::encode(buyer_kp.secret_bytes()),
            "seller_secret": hex::encode(seller_kp.secret_bytes()),
            "owner_pk": hex::encode(owner_pk),
            "fee_pk": hex::encode(fee_pk),
        });
        std::fs::write(keys_path, serde_json::to_string_pretty(&data)?)?;
        println!("  Generated new keypairs, saved to {}", keys_path.display());
        (buyer_kp, buyer_pk, seller_kp, seller_pk, owner_pk, fee_pk)
    };

    let buyer_addr = testnet_address(&buyer_pk);
    let seller_addr = testnet_address(&seller_pk);
    let fee_addr = testnet_address(&fee_pk);
    println!("  Buyer:  {}", buyer_addr);
    println!("  Seller: {}", seller_addr);
    println!("  Fee:    {}", fee_addr);

    // ── Step 3: Check if buyer already funded, else fund from wallet ─
    print_step(3, "Checking buyer balance...");
    let buyer_utxos = client
        .get_utxos_by_addresses(vec![buyer_addr.clone()])
        .await?;
    let current_daa = info.virtual_daa_score;
    let already_funded = buyer_utxos.iter().any(|e| {
        let mature = !e.utxo_entry.is_coinbase
            || current_daa >= e.utxo_entry.block_daa_score + 1000;
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
                    let wallet_kp =
                        secp256k1::Keypair::from_secret_key(secp256k1::SECP256K1, sk);
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
    // TEST 1: PaymentSplit — covenant-enforced payment routing
    // ═════════════════════════════════════════════════════════════
    print_step(4, "TEST 1: PaymentSplit covenant release via SDK");
    println!("  (No signatures needed — covenant enforces output routing)");

    let funding_fee = 5_000u64;
    let release_fee = 10_000u64;

    // Escrow amount must leave room for both fees so the release tx
    // has a non-zero mining fee (outputs sum to escrow_amount, input
    // is escrow_amount + release_fee, difference = release_fee).
    let ps_escrow_amount = utxo_amount
        .checked_sub(funding_fee + release_fee)
        .ok_or("UTXO too small for fees")?;

    let ps_escrow = EscrowBuilder::new(EscrowPattern::PaymentSplit { fee_percent: 10 })
        .buyer(buyer_pk)
        .seller(seller_pk)
        .owner(owner_pk)
        .fee_address(fee_pk)
        .amount(ps_escrow_amount)
        .build()?;

    println!("  UTXO:        {} sompi", utxo_amount);
    println!("  Escrow:      {} sompi", ps_escrow_amount);
    println!("  Seller gets: {} sompi (90%)", ps_escrow.seller_amount);
    println!("  Fee gets:    {} sompi (10%)", ps_escrow.fee_amount);
    println!("  Script:      {} bytes", ps_escrow.redeem_script.len());

    // Fund the escrow
    let funding_tx = build_funding_tx(outpoint, utxo_amount, &ps_escrow, funding_fee)?;
    let buyer_spk = pay_to_address_script(&buyer_addr);
    let funding_utxo = UtxoEntry::new(utxo_amount, buyer_spk, 0, false, None);

    let sig = schnorr_sign(&funding_tx, &funding_utxo, &buyer_kp);
    let mut signed_funding = funding_tx;
    signed_funding.inputs[0].signature_script = build_p2pk_sig_script(&sig);

    verify_script(&signed_funding, &funding_utxo)
        .map_err(|e| format!("Funding verify failed: {e}"))?;
    println!("  Funding local verify: OK");

    let rpc_funding: RpcTransaction = (&signed_funding).into();
    let funding_id = client.submit_transaction(rpc_funding, false).await?;
    println!("  Funding TX: {}", funding_id);

    // Covenant release — NO SIGNATURES!
    let escrow_outpoint = TransactionOutpoint::new(funding_id, 0);
    let on_chain_escrow_value = utxo_amount - funding_fee;
    let escrow_utxo = UtxoEntry::new(
        on_chain_escrow_value,
        ps_escrow.p2sh_spk.clone(),
        0,
        false,
        None,
    );

    let release_tx = build_payment_split_tx(escrow_outpoint, &ps_escrow)?;
    let release_sig_script = build_sig_script(
        &Branch::CovenantRelease,
        &[],
        &ps_escrow.redeem_script,
        &ps_escrow.pattern,
    )?;

    let mut signed_release = release_tx;
    signed_release.inputs[0].signature_script = release_sig_script;

    verify_script(&signed_release, &escrow_utxo)
        .map_err(|e| format!("Covenant release verify failed: {e}"))?;
    println!("  Covenant release local verify: OK (zero signatures!)");

    let rpc_release: RpcTransaction = (&signed_release).into();
    let release_id = submit_with_retry(&client, rpc_release).await?;
    println!("  Covenant Release TX: {}", release_id);

    // Verify outputs arrived
    tokio::time::sleep(Duration::from_secs(3)).await;
    check_balance(&client, &seller_addr, "Seller").await;
    check_balance(&client, &fee_addr, "Fee addr").await;
    println!("  TEST 1 PASSED: Covenant payment split on-chain!");

    // ═════════════════════════════════════════════════════════════
    // TEST 2: Basic 2-of-2 multisig release
    // ═════════════════════════════════════════════════════════════
    print_step(5, "TEST 2: Basic 2-of-2 release via SDK");
    println!("  (Using seller's proceeds from test 1)");

    // Wait for seller's UTXO from the covenant release
    println!("  Polling for seller's UTXO...");
    let (seller_outpoint, seller_utxo_amount) = poll_for_utxo(&client, &seller_addr).await?;

    let basic_funding_fee = 5_000u64;
    let basic_release_fee = 5_000u64;

    // For Basic pattern, escrow_amount = on-chain UTXO value.
    // build_release_tx subtracts the release fee from escrow_amount.
    let basic_escrow_amount = seller_utxo_amount
        .checked_sub(basic_funding_fee)
        .ok_or("Seller UTXO too small")?;

    // Seller from test 1 acts as "buyer" (funder), buyer acts as "seller" (payee)
    let basic_escrow = EscrowBuilder::new(EscrowPattern::Basic)
        .buyer(seller_pk)
        .seller(buyer_pk)
        .amount(basic_escrow_amount)
        .build()?;

    println!("  Escrow amount: {} sompi", basic_escrow_amount);
    println!(
        "  Script:        {} bytes",
        basic_escrow.redeem_script.len()
    );

    // Fund the basic escrow from seller's UTXO
    let basic_funding = build_funding_tx(
        seller_outpoint,
        seller_utxo_amount,
        &basic_escrow,
        basic_funding_fee,
    )?;
    let seller_spk = pay_to_address_script(&seller_addr);
    let seller_utxo = UtxoEntry::new(seller_utxo_amount, seller_spk, 0, false, None);

    let seller_fund_sig = schnorr_sign(&basic_funding, &seller_utxo, &seller_kp);
    let mut signed_basic_funding = basic_funding;
    signed_basic_funding.inputs[0].signature_script = build_p2pk_sig_script(&seller_fund_sig);

    verify_script(&signed_basic_funding, &seller_utxo)
        .map_err(|e| format!("Basic funding verify failed: {e}"))?;
    println!("  Basic funding local verify: OK");

    let rpc_basic_fund: RpcTransaction = (&signed_basic_funding).into();
    let basic_funding_id = client.submit_transaction(rpc_basic_fund, false).await?;
    println!("  Basic Funding TX: {}", basic_funding_id);

    // Release: both parties sign
    let basic_escrow_outpoint = TransactionOutpoint::new(basic_funding_id, 0);
    let basic_on_chain_value = seller_utxo_amount - basic_funding_fee;
    let basic_escrow_utxo = UtxoEntry::new(
        basic_on_chain_value,
        basic_escrow.p2sh_spk.clone(),
        0,
        false,
        None,
    );

    let basic_release = build_release_tx(basic_escrow_outpoint, &basic_escrow, basic_release_fee)?;

    // Signatures must match pubkey order in script: seller_pk first, buyer_pk second
    let sig1 = schnorr_sign(&basic_release, &basic_escrow_utxo, &seller_kp);
    let sig2 = schnorr_sign(&basic_release, &basic_escrow_utxo, &buyer_kp);

    let basic_sig_script = build_sig_script(
        &Branch::Normal,
        &[sig1, sig2],
        &basic_escrow.redeem_script,
        &basic_escrow.pattern,
    )?;

    let mut signed_basic_release = basic_release;
    signed_basic_release.inputs[0].signature_script = basic_sig_script;

    verify_script(&signed_basic_release, &basic_escrow_utxo)
        .map_err(|e| format!("Basic release verify failed: {e}"))?;
    println!("  Basic release local verify: OK");

    let rpc_basic_release: RpcTransaction = (&signed_basic_release).into();
    let basic_release_id = submit_with_retry(&client, rpc_basic_release).await?;
    println!("  Basic Release TX: {}", basic_release_id);

    // Verify buyer received funds
    tokio::time::sleep(Duration::from_secs(3)).await;
    check_balance(&client, &buyer_addr, "Buyer (recipient)").await;
    println!("  TEST 2 PASSED: 2-of-2 multisig release on-chain!");

    // ── Summary ─────────────────────────────────────────────────
    client.disconnect().await?;
    println!();
    println!("=== Live SDK Integration Test Complete ===");
    println!();
    println!("  Test 1: PaymentSplit covenant (no sigs, enforced split)");
    println!("    Funding:  {}", funding_id);
    println!("    Release:  {}", release_id);
    println!();
    println!("  Test 2: Basic 2-of-2 multisig");
    println!("    Funding:  {}", basic_funding_id);
    println!("    Release:  {}", basic_release_id);
    println!();
    println!("  All transactions submitted via EscrowBuilder SDK.");
    println!("  View on explorer: https://tn12.kaspa.stream");
    println!();

    Ok(())
}
