//! Fund the escrow buyer address by scanning mnemonic-derived wallet addresses.
//!
//! Strategy: derive addresses from the wallet mnemonic, query the node for
//! UTXOs at each batch, and use the first funded address to send to the buyer.
//!
//! The mnemonic is read from `.tn12rc` in the project root (one line, 12 words).
//! This file is in .gitignore and never committed.
//!
//! Setup:
//!   echo "word1 word2 ... word12" > .tn12rc
//!
//! Usage:
//!   cargo run --example fund_escrow

use kaspa_addresses::{Address, Prefix, Version};
use kaspa_bip32::{DerivationPath, ExtendedPrivateKey, Language, Mnemonic, SecretKey};
use kaspa_consensus_core::tx::{
    Transaction, TransactionInput, TransactionOutpoint, TransactionOutput,
};
use kaspa_escrow_lab::*;
use kaspa_rpc_core::RpcTransaction;
use kaspa_txscript::pay_to_address_script;
use kaspa_wrpc_client::prelude::*;

fn load_mnemonic() -> Result<String, Box<dyn std::error::Error>> {
    let rc_path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join(".tn12rc");
    if !rc_path.exists() {
        return Err(format!(
            "No .tn12rc found at {}\n  Create it with: echo \"word1 word2 ... word12\" > .tn12rc",
            rc_path.display()
        )
        .into());
    }
    let contents = std::fs::read_to_string(&rc_path)?;
    let phrase = contents.trim().to_string();
    if phrase.split_whitespace().count() < 12 {
        return Err("Expected 12+ words in .tn12rc".into());
    }
    Ok(phrase)
}

struct DerivedKey {
    keypair: secp256k1::Keypair,
    address: Address,
    path: String,
}

fn derive_address(
    master: &ExtendedPrivateKey<SecretKey>,
    account: u32,
    addr_type: u32,
    index: u32,
) -> Result<DerivedKey, Box<dyn std::error::Error>> {
    let path_str = format!("m/44'/111111'/{}'/{}/{}", account, addr_type, index);
    let path: DerivationPath = path_str.parse()?;
    let key = master.clone().derive_path(&path)?;
    let sk = key.private_key();
    let pk = secp256k1::PublicKey::from_secret_key(secp256k1::SECP256K1, sk);
    let xonly = pk.x_only_public_key().0.serialize();
    let addr = Address::new(Prefix::Testnet, Version::PubKey, &xonly);
    let kp = secp256k1::Keypair::from_secret_key(secp256k1::SECP256K1, sk);
    Ok(DerivedKey {
        keypair: kp,
        address: addr,
        path: path_str,
    })
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    print_header("Fund Escrow via Mnemonic UTXO Scan");

    // ── Step 1: Connect to node ────────────────────────────────────
    print_step(1, "Connecting to TN12 node...");
    let client = KaspaRpcClient::new(
        WrpcEncoding::Borsh,
        Some("ws://127.0.0.1:17110"),
        None,
        None,
        None,
    )?;
    client.connect(None).await?;
    let info = client.get_block_dag_info().await?;
    let current_daa = info.virtual_daa_score;
    println!("  Connected! DAA: {}", current_daa);

    // ── Step 2: Load buyer address ─────────────────────────────────
    print_step(2, "Loading buyer address...");
    let keys_path = std::path::Path::new("/tmp/escrow_keys.json");
    if !keys_path.exists() {
        return Err(
            "No /tmp/escrow_keys.json found. Run live_escrow first to generate keys.".into(),
        );
    }
    let data = std::fs::read_to_string(keys_path)?;
    let parsed: serde_json::Value = serde_json::from_str(&data)?;
    let buyer_secret = hex::decode(
        parsed["buyer_secret"]
            .as_str()
            .ok_or("missing buyer_secret in keys JSON")?,
    )?;
    let buyer_kp = secp256k1::Keypair::from_seckey_slice(secp256k1::SECP256K1, &buyer_secret)?;
    let buyer_pk = buyer_kp.x_only_public_key().0.serialize();
    let buyer_addr = testnet_address(&buyer_pk);
    println!("  Buyer address: {}", buyer_addr);

    // ── Step 3: Derive wallet keys and scan for UTXOs ──────────────
    print_step(3, "Deriving wallet keys and scanning for UTXOs...");
    let phrase = load_mnemonic()?;
    let mnemonic = Mnemonic::new(&phrase, Language::English)?;
    let seed = mnemonic.to_seed("");
    let master = ExtendedPrivateKey::<SecretKey>::new(seed)?;

    let batch_size = 20;
    let max_index = 200;
    let mut funded_key: Option<DerivedKey> = None;
    let mut funded_utxo: Option<(TransactionOutpoint, u64)> = None;

    // Scan accounts 0-2, both receive (0) and change (1) types
    'outer: for account in 0u32..3 {
        for addr_type in 0u32..2 {
            let type_name = if addr_type == 0 { "receive" } else { "change" };
            for batch_start in (0u32..max_index).step_by(batch_size) {
                let batch_end = (batch_start + batch_size as u32).min(max_index);

                // Derive a batch of addresses
                let mut keys: Vec<DerivedKey> = Vec::new();
                let mut addrs: Vec<Address> = Vec::new();
                for idx in batch_start..batch_end {
                    let dk = derive_address(&master, account, addr_type, idx)?;
                    addrs.push(dk.address.clone());
                    keys.push(dk);
                }

                // Query node for UTXOs at all addresses in this batch
                let utxos = client.get_utxos_by_addresses(addrs).await?;

                // Check for mature UTXOs with sufficient funds
                for entry in &utxos {
                    let mature = !entry.utxo_entry.is_coinbase
                        || current_daa >= entry.utxo_entry.block_daa_score + 1000;
                    if mature && entry.utxo_entry.amount >= 100_000_000 {
                        // >= 1 KAS
                        // Find which key matches this UTXO
                        let utxo_addr_str = entry
                            .address
                            .as_ref()
                            .map(|a| a.to_string())
                            .unwrap_or_default();
                        if let Some(key_idx) = keys
                            .iter()
                            .position(|k| k.address.to_string() == utxo_addr_str)
                        {
                            let dk = keys.remove(key_idx);
                            println!(
                                "  FOUND! Account {}, {} index {}: {} sompi ({:.2} KAS)",
                                account,
                                type_name,
                                batch_start + key_idx as u32,
                                entry.utxo_entry.amount,
                                entry.utxo_entry.amount as f64 / 100_000_000.0
                            );
                            println!("  Path: {}", dk.path);
                            println!("  Address: {}", dk.address);
                            let op = TransactionOutpoint::new(
                                entry.outpoint.transaction_id,
                                entry.outpoint.index,
                            );
                            funded_utxo = Some((op, entry.utxo_entry.amount));
                            funded_key = Some(dk);
                            break 'outer;
                        }
                    }
                }

                // Progress indicator
                if batch_start == 0 {
                    eprint!("  Scanning account {} {}", account, type_name);
                }
                eprint!(".");
            }
            eprintln!(" (no funds found)");
        }
    }

    if funded_key.is_none() || funded_utxo.is_none() {
        println!();
        println!("  No funded addresses found in accounts 0-2, indices 0-199.");
        println!("  The wallet address may be at a very high index or use a payment secret.");
        println!();
        println!("  Fund the buyer address directly:");
        println!("  Wallet: send {} 1337", buyer_addr);
        println!(
            "  Miner:  kaspa-miner --mining-address {} --mine-when-not-synced",
            buyer_addr
        );
        return Err("No funded wallet address found".into());
    }

    let dk = funded_key.expect("checked above");
    let (outpoint, utxo_amount) = funded_utxo.expect("checked above");

    // ── Step 4: Build and submit funding tx ────────────────────────
    print_step(4, "Building funding transaction...");
    let fee: u64 = 5000;
    let send_amount = utxo_amount - fee;
    println!("  Sending: {} sompi to buyer", send_amount);
    println!("  Fee:     {} sompi", fee);

    let input = TransactionInput {
        previous_outpoint: outpoint,
        signature_script: vec![],
        sequence: 0,
        sig_op_count: 1,
    };
    let output = TransactionOutput {
        value: send_amount,
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

    let wallet_spk = pay_to_address_script(&dk.address);
    let utxo_entry =
        kaspa_consensus_core::tx::UtxoEntry::new(utxo_amount, wallet_spk, 0, false, None);

    let signature = schnorr_sign(&tx, &utxo_entry, &dk.keypair);
    let sig_script = build_p2pk_sig_script(&signature);

    let mut signed_tx = tx;
    signed_tx.inputs[0].signature_script = sig_script;

    verify_script(&signed_tx, &utxo_entry)
        .map_err(|e| format!("Funding tx failed local verification: {e}"))?;
    println!("  Local verify: OK");

    let rpc_tx: RpcTransaction = (&signed_tx).into();
    let tx_id = client.submit_transaction(rpc_tx, false).await?;
    println!("  TX submitted: {}", tx_id);

    // ── Step 5: Verify ─────────────────────────────────────────────
    print_step(5, "Verifying buyer received funds...");
    tokio::time::sleep(std::time::Duration::from_secs(3)).await;
    let buyer_utxos = client
        .get_utxos_by_addresses(vec![buyer_addr.clone()])
        .await?;
    if let Some(e) = buyer_utxos.first() {
        println!(
            "  Buyer funded: {} sompi ({:.2} KAS)",
            e.utxo_entry.amount,
            e.utxo_entry.amount as f64 / 100_000_000.0
        );
    } else {
        println!("  UTXO not yet visible (may need a block)");
    }

    client.disconnect().await?;
    println!("\n=== Funding complete ===\n");
    Ok(())
}
