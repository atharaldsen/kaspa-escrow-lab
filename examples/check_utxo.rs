//! Quick diagnostic: check UTXOs at given addresses.
//!
//! Usage:
//!   cargo run --example check_utxo -- kaspatest:qr... kaspatest:qp...

use kaspa_wrpc_client::prelude::*;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.is_empty() {
        return Err("Usage: cargo run --example check_utxo -- <address1> [address2] ...".into());
    }

    let client = KaspaRpcClient::new(
        WrpcEncoding::Borsh,
        Some("ws://127.0.0.1:17110"),
        None,
        None,
        None,
    )?;
    client.connect(None).await?;
    println!("Connected.");

    for addr_str in &args {
        let addr: kaspa_addresses::Address = addr_str.as_str().try_into()?;
        println!("\nQuerying UTXOs for: {}", addr);
        match client.get_utxos_by_addresses(vec![addr]).await {
            Ok(utxos) => {
                println!("  {} UTXOs found", utxos.len());
                for (i, e) in utxos.iter().take(5).enumerate() {
                    println!(
                        "  [{}] tx:{} idx:{} amount:{} coinbase:{}",
                        i, e.outpoint.transaction_id, e.outpoint.index,
                        e.utxo_entry.amount, e.utxo_entry.is_coinbase,
                    );
                }
                if utxos.len() > 5 {
                    println!("  ... and {} more", utxos.len() - 5);
                }
            }
            Err(e) => println!("  RPC error: {}", e),
        }
    }

    let info = client.get_block_dag_info().await?;
    println!("\nDAA score: {}", info.virtual_daa_score);

    client.disconnect().await?;
    Ok(())
}
