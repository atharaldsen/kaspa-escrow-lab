//! Connection test for Kaspa Testnet 12
//!
//! Connects to a local TN12 node via wRPC Borsh and prints network info.
//! Requires kaspad running with --rpclisten-borsh=127.0.0.1:17110

use kaspa_wrpc_client::prelude::*;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("Connecting to Testnet 12...");

    let client = KaspaRpcClient::new(
        WrpcEncoding::Borsh,
        Some("ws://127.0.0.1:17110"),
        None,
        None,
        None,
    )?;

    client.connect(None).await?;
    println!("Connected!");

    let info = client.get_block_dag_info().await?;
    println!("Network: {}", info.network);
    println!("DAA Score: {}", info.virtual_daa_score);
    println!("Tip hashes: {} tips", info.tip_hashes.len());
    println!("Difficulty: {}", info.difficulty);

    client.disconnect().await?;
    Ok(())
}
