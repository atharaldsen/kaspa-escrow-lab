//! 2-of-3 Multi-Signature Escrow with Arbitrator
//!
//! Demonstrates a dispute resolution escrow where any 2 of 3 parties can release:
//! - Normal flow: Buyer + Seller sign
//! - Dispute (buyer wins): Arbitrator + Buyer sign
//! - Dispute (seller wins): Arbitrator + Seller sign

use kaspa_consensus_core::tx::TransactionOutput;
use kaspa_escrow_lab::*;
use kaspa_txscript::{
    opcodes::codes::OpData65, pay_to_script_hash_script, script_builder::ScriptBuilder,
    standard::multisig_redeem_script,
};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    print_header("2-of-3 Escrow with Arbitrator");

    // Step 1: Generate keypairs for all three parties
    print_step(1, "Generating keypairs...");
    let (buyer_kp, buyer_pk) = generate_keypair();
    let (seller_kp, seller_pk) = generate_keypair();
    let (arbitrator_kp, arbitrator_pk) = generate_keypair();
    println!("  Buyer:      {}", hex::encode(buyer_pk));
    println!("  Seller:     {}", hex::encode(seller_pk));
    println!("  Arbitrator: {}", hex::encode(arbitrator_pk));

    // Step 2: Build 2-of-3 multisig script
    print_step(2, "Building 2-of-3 multisig escrow script...");
    let redeem_script = multisig_redeem_script([buyer_pk, seller_pk, arbitrator_pk].iter(), 2)?;
    let p2sh_spk = pay_to_script_hash_script(&redeem_script);
    println!("  Redeem script: {} bytes", redeem_script.len());

    let input_value: u64 = 1_000_000_000;
    let output_value: u64 = 999_900_000;

    // Helper to build multisig signature script
    let build_sig_script =
        |sigs: Vec<Vec<u8>>, redeem: &[u8]| -> Result<Vec<u8>, Box<dyn std::error::Error>> {
            let mut sig_bytes: Vec<u8> = Vec::new();
            for sig in &sigs {
                sig_bytes.push(OpData65);
                sig_bytes.extend_from_slice(sig);
            }
            sig_bytes.extend_from_slice(&ScriptBuilder::new().add_data(redeem)?.drain());
            Ok(sig_bytes)
        };

    let make_output = || TransactionOutput {
        value: output_value,
        script_public_key: p2pk_spk(&seller_pk),
        covenant: None,
    };

    // Step 3: Normal release — Buyer + Seller
    print_step(3, "Testing normal release (buyer + seller sign)...");
    {
        let (mut tx, utxo) = build_mock_tx(
            p2sh_spk.clone(),
            input_value,
            vec![],
            vec![make_output()],
            0,
        );
        let buyer_sig = schnorr_sign(&tx, &utxo, &buyer_kp);
        let seller_sig = schnorr_sign(&tx, &utxo, &seller_kp);
        // Signatures must be in pubkey order: buyer(0), seller(1)
        let sig_script = build_sig_script(vec![buyer_sig, seller_sig], &redeem_script)?;
        tx.inputs[0].signature_script = sig_script;

        let result = verify_script(&tx, &utxo);
        print_result("Buyer + Seller", &result);
        assert!(result.is_ok());
    }

    // Step 4: Dispute — Arbitrator + Buyer
    print_step(4, "Testing dispute resolution (arbitrator + buyer)...");
    {
        let (mut tx, utxo) = build_mock_tx(
            p2sh_spk.clone(),
            input_value,
            vec![],
            vec![make_output()],
            0,
        );
        let buyer_sig = schnorr_sign(&tx, &utxo, &buyer_kp);
        let arbitrator_sig = schnorr_sign(&tx, &utxo, &arbitrator_kp);
        // Pubkey order: buyer(0), arbitrator(2) — signatures in ascending pubkey index
        let sig_script = build_sig_script(vec![buyer_sig, arbitrator_sig], &redeem_script)?;
        tx.inputs[0].signature_script = sig_script;

        let result = verify_script(&tx, &utxo);
        print_result("Arbitrator + Buyer", &result);
        assert!(result.is_ok());
    }

    // Step 5: Dispute — Arbitrator + Seller
    print_step(5, "Testing dispute resolution (arbitrator + seller)...");
    {
        let (mut tx, utxo) = build_mock_tx(
            p2sh_spk.clone(),
            input_value,
            vec![],
            vec![make_output()],
            0,
        );
        let seller_sig = schnorr_sign(&tx, &utxo, &seller_kp);
        let arbitrator_sig = schnorr_sign(&tx, &utxo, &arbitrator_kp);
        // Pubkey order: seller(1), arbitrator(2)
        let sig_script = build_sig_script(vec![seller_sig, arbitrator_sig], &redeem_script)?;
        tx.inputs[0].signature_script = sig_script;

        let result = verify_script(&tx, &utxo);
        print_result("Arbitrator + Seller", &result);
        assert!(result.is_ok());
    }

    // Step 6: Single signer should fail
    print_step(6, "Testing single signer (should fail)...");
    {
        let (mut tx, utxo) = build_mock_tx(
            p2sh_spk.clone(),
            input_value,
            vec![],
            vec![make_output()],
            0,
        );
        let buyer_sig = schnorr_sign(&tx, &utxo, &buyer_kp);
        // Only one signature
        let mut sig_bytes: Vec<u8> = Vec::new();
        sig_bytes.push(OpData65);
        sig_bytes.extend_from_slice(&buyer_sig);
        sig_bytes.extend_from_slice(&ScriptBuilder::new().add_data(&redeem_script)?.drain());
        tx.inputs[0].signature_script = sig_bytes;

        let result = verify_script(&tx, &utxo);
        print_result("Single signer", &result);
        assert!(result.is_err());
    }

    println!("\n=== All multisig escrow tests passed ===\n");
    Ok(())
}
