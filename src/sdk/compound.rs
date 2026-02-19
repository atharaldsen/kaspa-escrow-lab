use kaspa_addresses::Address;
use kaspa_consensus_core::tx::{
    Transaction, TransactionId, TransactionInput, TransactionOutpoint, TransactionOutput, UtxoEntry,
};
use kaspa_rpc_core::RpcTransaction;
use kaspa_txscript::pay_to_address_script;
use kaspa_wrpc_client::KaspaRpcClient;
use kaspa_wrpc_client::prelude::RpcApi;
use secp256k1::Keypair;
use std::time::Duration;

use super::error::EscrowError;
use crate::schnorr_sign_input;

/// Compound many UTXOs into fewer, larger ones.
///
/// Queries all mature UTXOs at `address`, batches them into transactions
/// of up to `max_inputs_per_tx` inputs each, signs, and submits.
/// Returns the list of submitted compound transaction IDs.
///
/// `max_inputs_per_tx` defaults to 50 if set to 0 (safe under 100k mass limit).
pub async fn compound_utxos(
    client: &KaspaRpcClient,
    address: &Address,
    keypair: &Keypair,
    max_inputs_per_tx: usize,
) -> Result<Vec<TransactionId>, EscrowError> {
    let max_inputs = if max_inputs_per_tx == 0 {
        50
    } else {
        max_inputs_per_tx
    };

    // Get current DAA for coinbase maturity check
    let info = client
        .get_block_dag_info()
        .await
        .map_err(|e| EscrowError::Rpc(format!("{e}")))?;
    let current_daa = info.virtual_daa_score;
    let coinbase_maturity: u64 = 1000;

    // Fetch all UTXOs
    let utxos = client
        .get_utxos_by_addresses(vec![address.clone()])
        .await
        .map_err(|e| EscrowError::Rpc(format!("{e}")))?;

    // Filter to mature UTXOs only
    let mature_utxos: Vec<_> = utxos
        .into_iter()
        .filter(|e| {
            !e.utxo_entry.is_coinbase
                || current_daa >= e.utxo_entry.block_daa_score + coinbase_maturity
        })
        .collect();

    if mature_utxos.len() <= 1 {
        return Ok(vec![]);
    }

    let address_spk = pay_to_address_script(address);
    let mut tx_ids = Vec::new();

    // Process in batches
    for batch in mature_utxos.chunks(max_inputs) {
        if batch.len() <= 1 {
            continue;
        }

        // Build inputs and calculate total
        let mut inputs = Vec::with_capacity(batch.len());
        let mut utxo_entries = Vec::with_capacity(batch.len());
        let mut total_amount: u64 = 0;

        for entry in batch {
            let outpoint =
                TransactionOutpoint::new(entry.outpoint.transaction_id, entry.outpoint.index);
            inputs.push(TransactionInput {
                previous_outpoint: outpoint,
                signature_script: vec![],
                sequence: 0,
                sig_op_count: 1,
            });
            utxo_entries.push(UtxoEntry::new(
                entry.utxo_entry.amount,
                address_spk.clone(),
                entry.utxo_entry.block_daa_score,
                entry.utxo_entry.is_coinbase,
                None,
            ));
            total_amount = total_amount
                .checked_add(entry.utxo_entry.amount)
                .ok_or_else(|| EscrowError::InvalidConfig("UTXO total overflows u64".into()))?;
        }

        // Estimate fee: ~150 bytes per input + ~50 bytes output + ~50 bytes overhead
        // mass_per_tx_byte = 1, so mass ~= byte count
        // fee = mass (at minimum relay rate of 1000/1000 = 1 sompi/gram)
        let estimated_mass = (batch.len() as u64) * 150 + 100;
        let fee = estimated_mass.max(5000); // minimum 5000 sompi

        if total_amount <= fee {
            continue;
        }

        let output = TransactionOutput {
            value: total_amount - fee,
            script_public_key: address_spk.clone(),
            covenant: None,
        };

        let tx = Transaction::new(1, inputs, vec![output], 0, Default::default(), 0, vec![]);

        // Sign each input
        let mut signed_tx = tx;
        for i in 0..batch.len() {
            let sig = schnorr_sign_input(&signed_tx, &utxo_entries, keypair, i);
            let mut sig_script = Vec::with_capacity(1 + sig.len());
            sig_script.push(kaspa_txscript::opcodes::codes::OpData65);
            sig_script.extend_from_slice(&sig);
            signed_tx.inputs[i].signature_script = sig_script;
        }

        // Submit with retry for finalization
        let rpc_tx: RpcTransaction = (&signed_tx).into();
        let mut attempt = 0;
        let tx_id = loop {
            attempt += 1;
            match client.submit_transaction(rpc_tx.clone(), false).await {
                Ok(id) => break id,
                Err(e) => {
                    let msg = format!("{e}");
                    if msg.contains("not finalized") && attempt < 20 {
                        tokio::time::sleep(Duration::from_secs(3)).await;
                        continue;
                    }
                    return Err(EscrowError::Rpc(format!(
                        "compound tx rejected after {attempt} attempts: {e}"
                    )));
                }
            }
        };

        tx_ids.push(tx_id);

        // Brief pause between batches to allow network propagation
        if batch.len() == max_inputs {
            tokio::time::sleep(Duration::from_secs(2)).await;
        }
    }

    Ok(tx_ids)
}
