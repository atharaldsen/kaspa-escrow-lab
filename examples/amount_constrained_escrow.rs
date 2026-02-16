//! Amount-Constrained Escrow (Payment Split Covenant)
//!
//! Demonstrates a covenant that enforces payment splits when funds are released:
//! - Output 0 must go to seller's address with at least seller_amount
//! - Output 1 must go to fee address with at least fee_amount
//!
//! Two paths:
//! - Owner escape: Owner signs to override and spend freely
//! - Release: No signature needed — covenant enforces correct output structure
//!
//! This is the KIP-10-inspired pattern adapted for escrow fee splitting.

use kaspa_consensus_core::tx::TransactionOutput;
use kaspa_escrow_lab::*;
use kaspa_txscript::{
    opcodes::codes::{
        OpCheckSig, OpElse, OpEndIf, OpEqualVerify, OpFalse, OpGreaterThanOrEqual, OpIf, OpTrue,
        OpTxOutputAmount, OpTxOutputSpk, OpVerify,
    },
    pay_to_script_hash_script,
    script_builder::ScriptBuilder,
};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    print_header("Amount-Constrained Escrow (Payment Splits)");

    // Step 1: Generate keypairs
    print_step(1, "Generating keypairs...");
    let (owner_kp, owner_pk) = generate_keypair();
    let (_, seller_pk) = generate_keypair();
    let (_, fee_pk) = generate_keypair();
    println!("  Owner:   {}", hex::encode(owner_pk));
    println!("  Seller:  {}", hex::encode(seller_pk));
    println!("  Fee addr: {}", hex::encode(fee_pk));

    let input_value: u64 = 1_000_000_000; // 10 KAS
    let seller_amount: i64 = 900_000_000; // 9 KAS to seller
    let fee_amount: i64 = 100_000_000; // 1 KAS platform fee
    println!(
        "  Split: {} sompi seller + {} sompi fee",
        seller_amount, fee_amount
    );

    // SPK bytes for covenant comparison
    let seller_spk = p2pk_spk(&seller_pk);
    let seller_spk_bytes = spk_to_bytes(&seller_spk);
    let fee_spk = p2pk_spk(&fee_pk);
    let fee_spk_bytes = spk_to_bytes(&fee_spk);

    // Step 2: Build amount-constrained escrow script
    //   OpIf
    //     <owner_pk> OpCheckSig                              // Escape: owner overrides
    //   OpElse
    //     <seller_spk> 0 OpTxOutputSpk OpEqualVerify         // Output 0 -> seller
    //     0 OpTxOutputAmount <seller_amount> OpGreaterThanOrEqual OpVerify
    //     <fee_spk> 1 OpTxOutputSpk OpEqualVerify            // Output 1 -> fee
    //     1 OpTxOutputAmount <fee_amount> OpGreaterThanOrEqual  // Final check on stack
    //   OpEndIf
    print_step(2, "Building amount-constrained escrow script...");
    let mut builder = ScriptBuilder::new();
    let redeem_script = builder
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
        .add_i64(seller_amount)?
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
        .add_i64(fee_amount)?
        .add_op(OpGreaterThanOrEqual)?
        .add_op(OpEndIf)?
        .drain();

    let p2sh_spk = pay_to_script_hash_script(&redeem_script);
    println!("  Redeem script: {} bytes", redeem_script.len());

    let correct_outputs = vec![
        TransactionOutput {
            value: seller_amount as u64,
            script_public_key: seller_spk.clone(),
            covenant: None,
        },
        TransactionOutput {
            value: fee_amount as u64,
            script_public_key: fee_spk.clone(),
            covenant: None,
        },
    ];

    // Step 3: Owner escape — owner signs and spends freely
    print_step(3, "Owner escape (owner signs, spends anywhere)...");
    {
        let (_, random_pk) = generate_keypair();
        let (mut tx, utxo) = build_mock_tx(
            p2sh_spk.clone(),
            input_value,
            vec![],
            vec![TransactionOutput {
                value: input_value - 1000,
                script_public_key: p2pk_spk(&random_pk),
                covenant: None,
            }],
            0,
        );

        let owner_sig = schnorr_sign(&tx, &utxo, &owner_kp);
        let mut sb = ScriptBuilder::new();
        sb.add_data(&owner_sig)?;
        sb.add_op(OpTrue)?;
        sb.add_data(&redeem_script)?;
        tx.inputs[0].signature_script = sb.drain();

        let result = verify_script(&tx, &utxo);
        print_result("Owner escape", &result);
        assert!(result.is_ok());
    }

    // Step 4: Release with correct splits
    print_step(4, "Release with correct payment splits...");
    {
        let (mut tx, utxo) = build_mock_tx(
            p2sh_spk.clone(),
            input_value,
            vec![],
            correct_outputs.clone(),
            0,
        );

        let mut sb = ScriptBuilder::new();
        sb.add_op(OpFalse)?; // select release branch
        sb.add_data(&redeem_script)?;
        tx.inputs[0].signature_script = sb.drain();

        let result = verify_script(&tx, &utxo);
        print_result("Correct splits", &result);
        assert!(result.is_ok());
    }

    // Step 5: Wrong seller address
    print_step(5, "Release with wrong seller address...");
    {
        let (_, wrong_pk) = generate_keypair();
        let (mut tx, utxo) = build_mock_tx(
            p2sh_spk.clone(),
            input_value,
            vec![],
            vec![
                TransactionOutput {
                    value: seller_amount as u64,
                    script_public_key: p2pk_spk(&wrong_pk), // wrong!
                    covenant: None,
                },
                TransactionOutput {
                    value: fee_amount as u64,
                    script_public_key: fee_spk.clone(),
                    covenant: None,
                },
            ],
            0,
        );

        let mut sb = ScriptBuilder::new();
        sb.add_op(OpFalse)?;
        sb.add_data(&redeem_script)?;
        tx.inputs[0].signature_script = sb.drain();

        let result = verify_script(&tx, &utxo);
        print_result("Wrong seller address", &result);
        assert!(result.is_err());
    }

    // Step 6: Seller amount too low
    print_step(6, "Release with seller amount too low...");
    {
        let (mut tx, utxo) = build_mock_tx(
            p2sh_spk.clone(),
            input_value,
            vec![],
            vec![
                TransactionOutput {
                    value: seller_amount as u64 - 1,
                    script_public_key: seller_spk.clone(),
                    covenant: None,
                },
                TransactionOutput {
                    value: fee_amount as u64,
                    script_public_key: fee_spk.clone(),
                    covenant: None,
                },
            ],
            0,
        );

        let mut sb = ScriptBuilder::new();
        sb.add_op(OpFalse)?;
        sb.add_data(&redeem_script)?;
        tx.inputs[0].signature_script = sb.drain();

        let result = verify_script(&tx, &utxo);
        print_result("Seller amount low", &result);
        assert!(result.is_err());
    }

    // Step 7: Wrong fee address
    print_step(7, "Release with wrong fee address...");
    {
        let (_, wrong_pk) = generate_keypair();
        let (mut tx, utxo) = build_mock_tx(
            p2sh_spk.clone(),
            input_value,
            vec![],
            vec![
                TransactionOutput {
                    value: seller_amount as u64,
                    script_public_key: seller_spk.clone(),
                    covenant: None,
                },
                TransactionOutput {
                    value: fee_amount as u64,
                    script_public_key: p2pk_spk(&wrong_pk), // wrong!
                    covenant: None,
                },
            ],
            0,
        );

        let mut sb = ScriptBuilder::new();
        sb.add_op(OpFalse)?;
        sb.add_data(&redeem_script)?;
        tx.inputs[0].signature_script = sb.drain();

        let result = verify_script(&tx, &utxo);
        print_result("Wrong fee address", &result);
        assert!(result.is_err());
    }

    // Step 8: Fee amount too low
    print_step(8, "Release with fee amount too low...");
    {
        let (mut tx, utxo) = build_mock_tx(
            p2sh_spk.clone(),
            input_value,
            vec![],
            vec![
                TransactionOutput {
                    value: seller_amount as u64,
                    script_public_key: seller_spk.clone(),
                    covenant: None,
                },
                TransactionOutput {
                    value: fee_amount as u64 - 1,
                    script_public_key: fee_spk.clone(),
                    covenant: None,
                },
            ],
            0,
        );

        let mut sb = ScriptBuilder::new();
        sb.add_op(OpFalse)?;
        sb.add_data(&redeem_script)?;
        tx.inputs[0].signature_script = sb.drain();

        let result = verify_script(&tx, &utxo);
        print_result("Fee amount low", &result);
        assert!(result.is_err());
    }

    println!("\n=== All amount-constrained escrow tests passed ===\n");
    Ok(())
}
