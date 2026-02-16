//! Basic 2-of-2 Escrow
//!
//! Demonstrates the simplest escrow pattern: buyer and seller must both sign
//! to release funds. Uses standard Schnorr multisig (OpCheckMultiSig).

use kaspa_consensus_core::tx::TransactionOutput;
use kaspa_escrow_lab::*;
use kaspa_txscript::{
    opcodes::codes::{OpData65, OpFalse},
    pay_to_script_hash_script,
    script_builder::ScriptBuilder,
    standard::multisig_redeem_script,
};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    print_header("Basic 2-of-2 Escrow");

    // Step 1: Generate keypairs
    print_step(1, "Generating keypairs...");
    let (buyer_kp, buyer_pk) = generate_keypair();
    let (seller_kp, seller_pk) = generate_keypair();
    println!("  Buyer:  {}", hex::encode(buyer_pk));
    println!("  Seller: {}", hex::encode(seller_pk));

    // Step 2: Build 2-of-2 multisig escrow script
    print_step(2, "Building 2-of-2 multisig escrow script...");
    let redeem_script = multisig_redeem_script([buyer_pk, seller_pk].iter(), 2)?;
    let p2sh_spk = pay_to_script_hash_script(&redeem_script);
    println!("  Redeem script: {} bytes", redeem_script.len());
    println!("  P2SH script:   {} bytes", p2sh_spk.script().len());

    let input_value: u64 = 1_000_000_000; // 10 KAS in sompi
    let output_value: u64 = 999_900_000; // minus fee

    // Helper: build signature script with given signatures + redeem script
    // Multisig sig format: <sig1_bytes> <sig2_bytes> <redeem_script>
    // Using OpData65 prefix (65 = 64-byte sig + 1-byte sighash type)
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

    // Step 3: Test normal release (both buyer and seller sign)
    print_step(3, "Testing normal release (buyer + seller sign)...");
    {
        let seller_output = TransactionOutput {
            value: output_value,
            script_public_key: p2pk_spk(&seller_pk),
            covenant: None,
        };
        // Build tx with empty sig_script first (needed to compute sig hash)
        let (tx, utxo) = build_mock_tx(
            p2sh_spk.clone(),
            input_value,
            ScriptBuilder::new().add_data(&redeem_script)?.drain(),
            vec![seller_output],
            0,
        );

        let buyer_sig = schnorr_sign(&tx, &utxo, &buyer_kp);
        let seller_sig = schnorr_sign(&tx, &utxo, &seller_kp);
        let sig_script = build_sig_script(vec![buyer_sig, seller_sig], &redeem_script)?;

        let (mut tx, utxo) = build_mock_tx(
            p2sh_spk.clone(),
            input_value,
            sig_script,
            vec![TransactionOutput {
                value: output_value,
                script_public_key: p2pk_spk(&seller_pk),
                covenant: None,
            }],
            0,
        );
        // Re-sign with the actual sig_script set (sig hash depends on sig_script contents for P2SH)
        // Actually, sig hash doesn't include sig_script, so we can sign against the initial tx
        // But we need the outputs to match. Let me rebuild properly.

        // The signature covers the UTXO's SPK, not the sig_script itself.
        // So we can sign against any tx with the same structure.
        let buyer_sig = schnorr_sign(&tx, &utxo, &buyer_kp);
        let seller_sig = schnorr_sign(&tx, &utxo, &seller_kp);
        let sig_script = build_sig_script(vec![buyer_sig, seller_sig], &redeem_script)?;
        tx.inputs[0].signature_script = sig_script;

        let result = verify_script(&tx, &utxo);
        print_result("Both sign", &result);
        assert!(result.is_ok(), "Both signatures should pass");
    }

    // Step 4: Test with only buyer signing (seller signature is empty placeholder)
    print_step(4, "Testing with only buyer signature...");
    {
        let (mut tx, utxo) = build_mock_tx(
            p2sh_spk.clone(),
            input_value,
            vec![],
            vec![TransactionOutput {
                value: output_value,
                script_public_key: p2pk_spk(&seller_pk),
                covenant: None,
            }],
            0,
        );

        let buyer_sig = schnorr_sign(&tx, &utxo, &buyer_kp);
        // Only one signature where two are required
        let mut sig_bytes: Vec<u8> = Vec::new();
        sig_bytes.push(OpData65);
        sig_bytes.extend_from_slice(&buyer_sig);
        // Push empty byte for missing second sig
        sig_bytes.push(OpFalse);
        sig_bytes.extend_from_slice(&ScriptBuilder::new().add_data(&redeem_script)?.drain());
        tx.inputs[0].signature_script = sig_bytes;

        let result = verify_script(&tx, &utxo);
        print_result("Buyer only", &result);
        assert!(result.is_err(), "Single signature should fail");
    }

    // Step 5: Test with a completely wrong key
    print_step(5, "Testing with wrong key...");
    {
        let (wrong_kp, _) = generate_keypair();
        let (mut tx, utxo) = build_mock_tx(
            p2sh_spk.clone(),
            input_value,
            vec![],
            vec![TransactionOutput {
                value: output_value,
                script_public_key: p2pk_spk(&seller_pk),
                covenant: None,
            }],
            0,
        );

        let wrong_sig = schnorr_sign(&tx, &utxo, &wrong_kp);
        let seller_sig = schnorr_sign(&tx, &utxo, &seller_kp);
        let sig_script = build_sig_script(vec![wrong_sig, seller_sig], &redeem_script)?;
        tx.inputs[0].signature_script = sig_script;

        let result = verify_script(&tx, &utxo);
        print_result("Wrong key", &result);
        assert!(result.is_err(), "Wrong key should fail");
    }

    println!("\n=== All basic escrow tests passed ===\n");
    Ok(())
}
