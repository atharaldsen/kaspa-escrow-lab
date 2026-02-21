//! Integration tests for all escrow patterns.
//!
//! Each test mirrors the corresponding example but runs as a proper #[test].

use kaspa_consensus_core::tx::TransactionOutput;
use kaspa_escrow_lab::*;
use kaspa_txscript::{
    opcodes::codes::{
        OpCheckLockTimeVerify, OpCheckMultiSig, OpCheckSig, OpData65, OpElse, OpEndIf,
        OpEqualVerify, OpFalse, OpGreaterThanOrEqual, OpIf, OpTrue, OpTxOutputAmount,
        OpTxOutputSpk, OpVerify,
    },
    pay_to_script_hash_script,
    script_builder::ScriptBuilder,
    standard::multisig_redeem_script,
};

// build_multisig_sig_script is now in kaspa_escrow_lab::* (lib.rs)

// ---------------------------------------------------------------------------
// Basic 2-of-2 Escrow
// ---------------------------------------------------------------------------

mod basic_escrow {
    use super::*;

    struct BasicSetup {
        buyer_kp: secp256k1::Keypair,
        seller_kp: secp256k1::Keypair,
        seller_pk: [u8; 32],
        redeem: Vec<u8>,
        p2sh: kaspa_consensus_core::tx::ScriptPublicKey,
    }

    fn setup() -> BasicSetup {
        let (buyer_kp, buyer_pk) = generate_keypair();
        let (seller_kp, seller_pk) = generate_keypair();
        let redeem = multisig_redeem_script([buyer_pk, seller_pk].iter(), 2).unwrap();
        let p2sh = pay_to_script_hash_script(&redeem);
        BasicSetup {
            buyer_kp,
            seller_kp,
            seller_pk,
            redeem,
            p2sh,
        }
    }

    #[test]
    fn both_sign_releases_funds() {
        let s = setup();

        let (mut tx, utxo) = build_mock_tx(
            s.p2sh,
            1_000_000_000,
            vec![],
            vec![TransactionOutput {
                value: 999_900_000,
                script_public_key: p2pk_spk(&s.seller_pk),
                covenant: None,
            }],
            0,
        );

        let buyer_sig = schnorr_sign(&tx, &utxo, &s.buyer_kp);
        let seller_sig = schnorr_sign(&tx, &utxo, &s.seller_kp);
        tx.inputs[0].signature_script =
            build_multisig_sig_script(vec![buyer_sig, seller_sig], &s.redeem).unwrap();

        assert!(verify_script(&tx, &utxo).is_ok());
    }

    #[test]
    fn single_signer_fails() {
        let s = setup();

        let (mut tx, utxo) = build_mock_tx(
            s.p2sh,
            1_000_000_000,
            vec![],
            vec![TransactionOutput {
                value: 999_900_000,
                script_public_key: p2pk_spk(&s.seller_pk),
                covenant: None,
            }],
            0,
        );

        let buyer_sig = schnorr_sign(&tx, &utxo, &s.buyer_kp);
        let mut sig_bytes: Vec<u8> = Vec::new();
        sig_bytes.push(OpData65);
        sig_bytes.extend_from_slice(&buyer_sig);
        sig_bytes.push(OpFalse);
        sig_bytes.extend_from_slice(&ScriptBuilder::new().add_data(&s.redeem).unwrap().drain());
        tx.inputs[0].signature_script = sig_bytes;

        assert!(verify_script(&tx, &utxo).is_err());
    }

    #[test]
    fn wrong_key_fails() {
        let s = setup();
        let (wrong_kp, _) = generate_keypair();

        let (mut tx, utxo) = build_mock_tx(
            s.p2sh,
            1_000_000_000,
            vec![],
            vec![TransactionOutput {
                value: 999_900_000,
                script_public_key: p2pk_spk(&s.seller_pk),
                covenant: None,
            }],
            0,
        );

        let wrong_sig = schnorr_sign(&tx, &utxo, &wrong_kp);
        let seller_sig = schnorr_sign(&tx, &utxo, &s.seller_kp);
        tx.inputs[0].signature_script =
            build_multisig_sig_script(vec![wrong_sig, seller_sig], &s.redeem).unwrap();

        assert!(verify_script(&tx, &utxo).is_err());
    }
}

// ---------------------------------------------------------------------------
// 2-of-3 Multisig Escrow with Arbitrator
// ---------------------------------------------------------------------------

mod multisig_escrow {
    use super::*;

    struct MultisigSetup {
        buyer_kp: secp256k1::Keypair,
        seller_kp: secp256k1::Keypair,
        seller_pk: [u8; 32],
        arb_kp: secp256k1::Keypair,
        redeem: Vec<u8>,
        p2sh: kaspa_consensus_core::tx::ScriptPublicKey,
    }

    fn setup() -> MultisigSetup {
        let (buyer_kp, buyer_pk) = generate_keypair();
        let (seller_kp, seller_pk) = generate_keypair();
        let (arb_kp, arb_pk) = generate_keypair();
        let redeem = multisig_redeem_script([buyer_pk, seller_pk, arb_pk].iter(), 2).unwrap();
        let p2sh = pay_to_script_hash_script(&redeem);
        MultisigSetup {
            buyer_kp,
            seller_kp,
            seller_pk,
            arb_kp,
            redeem,
            p2sh,
        }
    }

    fn make_output(seller_pk: &[u8; 32]) -> TransactionOutput {
        TransactionOutput {
            value: 999_900_000,
            script_public_key: p2pk_spk(seller_pk),
            covenant: None,
        }
    }

    #[test]
    fn buyer_and_seller_sign() {
        let s = setup();

        let (mut tx, utxo) = build_mock_tx(
            s.p2sh,
            1_000_000_000,
            vec![],
            vec![make_output(&s.seller_pk)],
            0,
        );
        let b_sig = schnorr_sign(&tx, &utxo, &s.buyer_kp);
        let s_sig = schnorr_sign(&tx, &utxo, &s.seller_kp);
        tx.inputs[0].signature_script =
            build_multisig_sig_script(vec![b_sig, s_sig], &s.redeem).unwrap();

        assert!(verify_script(&tx, &utxo).is_ok());
    }

    #[test]
    fn arbitrator_and_buyer_sign() {
        let s = setup();

        let (mut tx, utxo) = build_mock_tx(
            s.p2sh,
            1_000_000_000,
            vec![],
            vec![make_output(&s.seller_pk)],
            0,
        );
        let b_sig = schnorr_sign(&tx, &utxo, &s.buyer_kp);
        let a_sig = schnorr_sign(&tx, &utxo, &s.arb_kp);
        tx.inputs[0].signature_script =
            build_multisig_sig_script(vec![b_sig, a_sig], &s.redeem).unwrap();

        assert!(verify_script(&tx, &utxo).is_ok());
    }

    #[test]
    fn arbitrator_and_seller_sign() {
        let s = setup();

        let (mut tx, utxo) = build_mock_tx(
            s.p2sh,
            1_000_000_000,
            vec![],
            vec![make_output(&s.seller_pk)],
            0,
        );
        let s_sig = schnorr_sign(&tx, &utxo, &s.seller_kp);
        let a_sig = schnorr_sign(&tx, &utxo, &s.arb_kp);
        tx.inputs[0].signature_script =
            build_multisig_sig_script(vec![s_sig, a_sig], &s.redeem).unwrap();

        assert!(verify_script(&tx, &utxo).is_ok());
    }

    #[test]
    fn single_signer_fails() {
        let s = setup();

        let (mut tx, utxo) = build_mock_tx(
            s.p2sh,
            1_000_000_000,
            vec![],
            vec![make_output(&s.seller_pk)],
            0,
        );
        let b_sig = schnorr_sign(&tx, &utxo, &s.buyer_kp);
        let mut sig_bytes: Vec<u8> = Vec::new();
        sig_bytes.push(OpData65);
        sig_bytes.extend_from_slice(&b_sig);
        sig_bytes.extend_from_slice(&ScriptBuilder::new().add_data(&s.redeem).unwrap().drain());
        tx.inputs[0].signature_script = sig_bytes;

        assert!(verify_script(&tx, &utxo).is_err());
    }
}

// ---------------------------------------------------------------------------
// Time-Locked Escrow
// ---------------------------------------------------------------------------

mod timelock_escrow {
    use super::*;

    const LOCK_TIME: u64 = 1000;
    const INPUT_VALUE: u64 = 1_000_000_000;
    const OUTPUT_VALUE: u64 = 999_900_000;

    fn build_script(
        buyer_pk: &[u8; 32],
        seller_pk: &[u8; 32],
    ) -> (Vec<u8>, kaspa_consensus_core::tx::ScriptPublicKey) {
        let mut builder = ScriptBuilder::new();
        let redeem = builder
            .add_op(OpIf)
            .unwrap()
            .add_i64(2)
            .unwrap()
            .add_data(buyer_pk)
            .unwrap()
            .add_data(seller_pk)
            .unwrap()
            .add_i64(2)
            .unwrap()
            .add_op(OpCheckMultiSig)
            .unwrap()
            .add_op(OpElse)
            .unwrap()
            .add_i64(LOCK_TIME as i64)
            .unwrap()
            .add_op(OpCheckLockTimeVerify)
            .unwrap()
            .add_data(buyer_pk)
            .unwrap()
            .add_op(OpCheckSig)
            .unwrap()
            .add_op(OpEndIf)
            .unwrap()
            .drain();
        let p2sh = pay_to_script_hash_script(&redeem);
        (redeem, p2sh)
    }

    #[test]
    fn normal_release_both_sign() {
        let (buyer_kp, buyer_pk) = generate_keypair();
        let (seller_kp, seller_pk) = generate_keypair();
        let (redeem, p2sh) = build_script(&buyer_pk, &seller_pk);

        let (mut tx, utxo) = build_mock_tx(
            p2sh,
            INPUT_VALUE,
            vec![],
            vec![TransactionOutput {
                value: OUTPUT_VALUE,
                script_public_key: p2pk_spk(&seller_pk),
                covenant: None,
            }],
            0,
        );

        let b_sig = schnorr_sign(&tx, &utxo, &buyer_kp);
        let s_sig = schnorr_sign(&tx, &utxo, &seller_kp);

        let mut sig_script: Vec<u8> = Vec::new();
        sig_script.push(OpData65);
        sig_script.extend_from_slice(&b_sig);
        sig_script.push(OpData65);
        sig_script.extend_from_slice(&s_sig);
        let mut sb = ScriptBuilder::new();
        sb.add_op(OpTrue).unwrap();
        sb.add_data(&redeem).unwrap();
        sig_script.extend_from_slice(&sb.drain());
        tx.inputs[0].signature_script = sig_script;

        assert!(verify_script(&tx, &utxo).is_ok());
    }

    #[test]
    fn timeout_refund_succeeds() {
        let (buyer_kp, buyer_pk) = generate_keypair();
        let (_, seller_pk) = generate_keypair();
        let (redeem, p2sh) = build_script(&buyer_pk, &seller_pk);

        let (mut tx, utxo) = build_mock_tx(
            p2sh,
            INPUT_VALUE,
            vec![],
            vec![TransactionOutput {
                value: OUTPUT_VALUE,
                script_public_key: p2pk_spk(&buyer_pk),
                covenant: None,
            }],
            LOCK_TIME + 100,
        );

        let b_sig = schnorr_sign(&tx, &utxo, &buyer_kp);
        let mut sb = ScriptBuilder::new();
        sb.add_data(&b_sig).unwrap();
        sb.add_op(OpFalse).unwrap();
        sb.add_data(&redeem).unwrap();
        tx.inputs[0].signature_script = sb.drain();

        assert!(verify_script(&tx, &utxo).is_ok());
    }

    #[test]
    fn timeout_too_early_fails() {
        let (buyer_kp, buyer_pk) = generate_keypair();
        let (_, seller_pk) = generate_keypair();
        let (redeem, p2sh) = build_script(&buyer_pk, &seller_pk);

        let (mut tx, utxo) = build_mock_tx(
            p2sh,
            INPUT_VALUE,
            vec![],
            vec![TransactionOutput {
                value: OUTPUT_VALUE,
                script_public_key: p2pk_spk(&buyer_pk),
                covenant: None,
            }],
            LOCK_TIME - 100,
        );

        let b_sig = schnorr_sign(&tx, &utxo, &buyer_kp);
        let mut sb = ScriptBuilder::new();
        sb.add_data(&b_sig).unwrap();
        sb.add_op(OpFalse).unwrap();
        sb.add_data(&redeem).unwrap();
        tx.inputs[0].signature_script = sb.drain();

        assert!(verify_script(&tx, &utxo).is_err());
    }

    #[test]
    fn timeout_wrong_key_fails() {
        let (_, buyer_pk) = generate_keypair();
        let (_, seller_pk) = generate_keypair();
        let (wrong_kp, _) = generate_keypair();
        let (redeem, p2sh) = build_script(&buyer_pk, &seller_pk);

        let (mut tx, utxo) = build_mock_tx(
            p2sh,
            INPUT_VALUE,
            vec![],
            vec![TransactionOutput {
                value: OUTPUT_VALUE,
                script_public_key: p2pk_spk(&buyer_pk),
                covenant: None,
            }],
            LOCK_TIME + 100,
        );

        let wrong_sig = schnorr_sign(&tx, &utxo, &wrong_kp);
        let mut sb = ScriptBuilder::new();
        sb.add_data(&wrong_sig).unwrap();
        sb.add_op(OpFalse).unwrap();
        sb.add_data(&redeem).unwrap();
        tx.inputs[0].signature_script = sb.drain();

        assert!(verify_script(&tx, &utxo).is_err());
    }
}

// ---------------------------------------------------------------------------
// Multi-Path Covenant Escrow
// ---------------------------------------------------------------------------

mod covenant_escrow {
    use super::*;

    const LOCK_TIME: u64 = 1000;
    const INPUT_VALUE: u64 = 1_000_000_000;
    const OUTPUT_VALUE: u64 = 999_900_000;

    struct CovenantSetup {
        buyer_kp: secp256k1::Keypair,
        buyer_pk: [u8; 32],
        seller_kp: secp256k1::Keypair,
        seller_pk: [u8; 32],
        arb_kp: secp256k1::Keypair,
        redeem: Vec<u8>,
        p2sh: kaspa_consensus_core::tx::ScriptPublicKey,
        buyer_spk: kaspa_consensus_core::tx::ScriptPublicKey,
    }

    fn setup() -> CovenantSetup {
        let (buyer_kp, buyer_pk) = generate_keypair();
        let (seller_kp, seller_pk) = generate_keypair();
        let (arb_kp, arb_pk) = generate_keypair();

        let buyer_spk = p2pk_spk(&buyer_pk);
        let buyer_spk_bytes = spk_to_bytes(&buyer_spk);

        let mut builder = ScriptBuilder::new();
        let redeem = builder
            .add_op(OpIf)
            .unwrap()
            .add_op(OpIf)
            .unwrap()
            .add_i64(2)
            .unwrap()
            .add_data(&buyer_pk)
            .unwrap()
            .add_data(&seller_pk)
            .unwrap()
            .add_i64(2)
            .unwrap()
            .add_op(OpCheckMultiSig)
            .unwrap()
            .add_op(OpElse)
            .unwrap()
            .add_i64(2)
            .unwrap()
            .add_data(&buyer_pk)
            .unwrap()
            .add_data(&seller_pk)
            .unwrap()
            .add_data(&arb_pk)
            .unwrap()
            .add_i64(3)
            .unwrap()
            .add_op(OpCheckMultiSig)
            .unwrap()
            .add_op(OpEndIf)
            .unwrap()
            .add_op(OpElse)
            .unwrap()
            .add_i64(LOCK_TIME as i64)
            .unwrap()
            .add_op(OpCheckLockTimeVerify)
            .unwrap()
            .add_data(&buyer_spk_bytes)
            .unwrap()
            .add_i64(0)
            .unwrap()
            .add_op(OpTxOutputSpk)
            .unwrap()
            .add_op(OpEqualVerify)
            .unwrap()
            .add_i64(0)
            .unwrap()
            .add_op(OpTxOutputAmount)
            .unwrap()
            .add_i64(OUTPUT_VALUE as i64)
            .unwrap()
            .add_op(OpGreaterThanOrEqual)
            .unwrap()
            .add_op(OpEndIf)
            .unwrap()
            .drain();

        let p2sh = pay_to_script_hash_script(&redeem);
        CovenantSetup {
            buyer_kp,
            buyer_pk,
            seller_kp,
            seller_pk,
            arb_kp,
            redeem,
            p2sh,
            buyer_spk,
        }
    }

    #[test]
    fn branch1_normal_release() {
        let s = setup();
        let (mut tx, utxo) = build_mock_tx(
            s.p2sh,
            INPUT_VALUE,
            vec![],
            vec![TransactionOutput {
                value: OUTPUT_VALUE,
                script_public_key: p2pk_spk(&s.seller_pk),
                covenant: None,
            }],
            0,
        );

        let b_sig = schnorr_sign(&tx, &utxo, &s.buyer_kp);
        let s_sig = schnorr_sign(&tx, &utxo, &s.seller_kp);

        let mut sig_script: Vec<u8> = Vec::new();
        sig_script.push(OpData65);
        sig_script.extend_from_slice(&b_sig);
        sig_script.push(OpData65);
        sig_script.extend_from_slice(&s_sig);
        let mut sb = ScriptBuilder::new();
        sb.add_op(OpTrue).unwrap();
        sb.add_op(OpTrue).unwrap();
        sb.add_data(&s.redeem).unwrap();
        sig_script.extend_from_slice(&sb.drain());
        tx.inputs[0].signature_script = sig_script;

        assert!(verify_script(&tx, &utxo).is_ok());
    }

    #[test]
    fn branch2_dispute_resolution() {
        let s = setup();
        let (mut tx, utxo) = build_mock_tx(
            s.p2sh,
            INPUT_VALUE,
            vec![],
            vec![TransactionOutput {
                value: OUTPUT_VALUE,
                script_public_key: p2pk_spk(&s.buyer_pk),
                covenant: None,
            }],
            0,
        );

        let b_sig = schnorr_sign(&tx, &utxo, &s.buyer_kp);
        let a_sig = schnorr_sign(&tx, &utxo, &s.arb_kp);

        let mut sig_script: Vec<u8> = Vec::new();
        sig_script.push(OpData65);
        sig_script.extend_from_slice(&b_sig);
        sig_script.push(OpData65);
        sig_script.extend_from_slice(&a_sig);
        let mut sb = ScriptBuilder::new();
        sb.add_op(OpFalse).unwrap();
        sb.add_op(OpTrue).unwrap();
        sb.add_data(&s.redeem).unwrap();
        sig_script.extend_from_slice(&sb.drain());
        tx.inputs[0].signature_script = sig_script;

        assert!(verify_script(&tx, &utxo).is_ok());
    }

    #[test]
    fn branch3_timeout_correct_output() {
        let s = setup();
        let (mut tx, utxo) = build_mock_tx(
            s.p2sh,
            INPUT_VALUE,
            vec![],
            vec![TransactionOutput {
                value: OUTPUT_VALUE,
                script_public_key: s.buyer_spk.clone(),
                covenant: None,
            }],
            LOCK_TIME + 100,
        );

        let mut sb = ScriptBuilder::new();
        sb.add_op(OpFalse).unwrap();
        sb.add_data(&s.redeem).unwrap();
        tx.inputs[0].signature_script = sb.drain();

        assert!(verify_script(&tx, &utxo).is_ok());
    }

    #[test]
    fn branch3_wrong_address_fails() {
        let s = setup();
        let (_, wrong_pk) = generate_keypair();
        let (mut tx, utxo) = build_mock_tx(
            s.p2sh,
            INPUT_VALUE,
            vec![],
            vec![TransactionOutput {
                value: OUTPUT_VALUE,
                script_public_key: p2pk_spk(&wrong_pk),
                covenant: None,
            }],
            LOCK_TIME + 100,
        );

        let mut sb = ScriptBuilder::new();
        sb.add_op(OpFalse).unwrap();
        sb.add_data(&s.redeem).unwrap();
        tx.inputs[0].signature_script = sb.drain();

        assert!(verify_script(&tx, &utxo).is_err());
    }

    #[test]
    fn branch3_amount_too_low_fails() {
        let s = setup();
        let (mut tx, utxo) = build_mock_tx(
            s.p2sh,
            INPUT_VALUE,
            vec![],
            vec![TransactionOutput {
                value: OUTPUT_VALUE - 1,
                script_public_key: s.buyer_spk.clone(),
                covenant: None,
            }],
            LOCK_TIME + 100,
        );

        let mut sb = ScriptBuilder::new();
        sb.add_op(OpFalse).unwrap();
        sb.add_data(&s.redeem).unwrap();
        tx.inputs[0].signature_script = sb.drain();

        assert!(verify_script(&tx, &utxo).is_err());
    }

    #[test]
    fn branch3_before_timeout_fails() {
        let s = setup();
        let (mut tx, utxo) = build_mock_tx(
            s.p2sh,
            INPUT_VALUE,
            vec![],
            vec![TransactionOutput {
                value: OUTPUT_VALUE,
                script_public_key: s.buyer_spk.clone(),
                covenant: None,
            }],
            LOCK_TIME - 100,
        );

        let mut sb = ScriptBuilder::new();
        sb.add_op(OpFalse).unwrap();
        sb.add_data(&s.redeem).unwrap();
        tx.inputs[0].signature_script = sb.drain();

        assert!(verify_script(&tx, &utxo).is_err());
    }
}

// ---------------------------------------------------------------------------
// Amount-Constrained Escrow (Payment Splits)
// ---------------------------------------------------------------------------

mod amount_constrained_escrow {
    use super::*;

    const INPUT_VALUE: u64 = 1_000_000_000;
    const SELLER_AMOUNT: i64 = 900_000_000;
    const FEE_AMOUNT: i64 = 100_000_000;

    struct SplitSetup {
        owner_kp: secp256k1::Keypair,
        seller_spk: kaspa_consensus_core::tx::ScriptPublicKey,
        fee_spk: kaspa_consensus_core::tx::ScriptPublicKey,
        redeem: Vec<u8>,
        p2sh: kaspa_consensus_core::tx::ScriptPublicKey,
    }

    fn setup() -> SplitSetup {
        let (owner_kp, owner_pk) = generate_keypair();
        let (_, seller_pk) = generate_keypair();
        let (_, fee_pk) = generate_keypair();

        let seller_spk = p2pk_spk(&seller_pk);
        let seller_spk_bytes = spk_to_bytes(&seller_spk);
        let fee_spk = p2pk_spk(&fee_pk);
        let fee_spk_bytes = spk_to_bytes(&fee_spk);

        let mut builder = ScriptBuilder::new();
        let redeem = builder
            .add_op(OpIf)
            .unwrap()
            .add_data(&owner_pk)
            .unwrap()
            .add_op(OpCheckSig)
            .unwrap()
            .add_op(OpElse)
            .unwrap()
            .add_data(&seller_spk_bytes)
            .unwrap()
            .add_i64(0)
            .unwrap()
            .add_op(OpTxOutputSpk)
            .unwrap()
            .add_op(OpEqualVerify)
            .unwrap()
            .add_i64(0)
            .unwrap()
            .add_op(OpTxOutputAmount)
            .unwrap()
            .add_i64(SELLER_AMOUNT)
            .unwrap()
            .add_op(OpGreaterThanOrEqual)
            .unwrap()
            .add_op(OpVerify)
            .unwrap()
            .add_data(&fee_spk_bytes)
            .unwrap()
            .add_i64(1)
            .unwrap()
            .add_op(OpTxOutputSpk)
            .unwrap()
            .add_op(OpEqualVerify)
            .unwrap()
            .add_i64(1)
            .unwrap()
            .add_op(OpTxOutputAmount)
            .unwrap()
            .add_i64(FEE_AMOUNT)
            .unwrap()
            .add_op(OpGreaterThanOrEqual)
            .unwrap()
            .add_op(OpEndIf)
            .unwrap()
            .drain();

        let p2sh = pay_to_script_hash_script(&redeem);
        SplitSetup {
            owner_kp,
            seller_spk,
            fee_spk,
            redeem,
            p2sh,
        }
    }

    fn correct_outputs(s: &SplitSetup) -> Vec<TransactionOutput> {
        vec![
            TransactionOutput {
                value: SELLER_AMOUNT as u64,
                script_public_key: s.seller_spk.clone(),
                covenant: None,
            },
            TransactionOutput {
                value: FEE_AMOUNT as u64,
                script_public_key: s.fee_spk.clone(),
                covenant: None,
            },
        ]
    }

    #[test]
    fn owner_escape_spends_anywhere() {
        let s = setup();
        let (_, random_pk) = generate_keypair();

        let (mut tx, utxo) = build_mock_tx(
            s.p2sh,
            INPUT_VALUE,
            vec![],
            vec![TransactionOutput {
                value: INPUT_VALUE - 1000,
                script_public_key: p2pk_spk(&random_pk),
                covenant: None,
            }],
            0,
        );

        let sig = schnorr_sign(&tx, &utxo, &s.owner_kp);
        let mut sb = ScriptBuilder::new();
        sb.add_data(&sig).unwrap();
        sb.add_op(OpTrue).unwrap();
        sb.add_data(&s.redeem).unwrap();
        tx.inputs[0].signature_script = sb.drain();

        assert!(verify_script(&tx, &utxo).is_ok());
    }

    #[test]
    fn release_with_correct_splits() {
        let s = setup();
        let (mut tx, utxo) =
            build_mock_tx(s.p2sh.clone(), INPUT_VALUE, vec![], correct_outputs(&s), 0);

        let mut sb = ScriptBuilder::new();
        sb.add_op(OpFalse).unwrap();
        sb.add_data(&s.redeem).unwrap();
        tx.inputs[0].signature_script = sb.drain();

        assert!(verify_script(&tx, &utxo).is_ok());
    }

    #[test]
    fn wrong_seller_address_fails() {
        let s = setup();
        let (_, wrong_pk) = generate_keypair();

        let (mut tx, utxo) = build_mock_tx(
            s.p2sh,
            INPUT_VALUE,
            vec![],
            vec![
                TransactionOutput {
                    value: SELLER_AMOUNT as u64,
                    script_public_key: p2pk_spk(&wrong_pk),
                    covenant: None,
                },
                TransactionOutput {
                    value: FEE_AMOUNT as u64,
                    script_public_key: s.fee_spk.clone(),
                    covenant: None,
                },
            ],
            0,
        );

        let mut sb = ScriptBuilder::new();
        sb.add_op(OpFalse).unwrap();
        sb.add_data(&s.redeem).unwrap();
        tx.inputs[0].signature_script = sb.drain();

        assert!(verify_script(&tx, &utxo).is_err());
    }

    #[test]
    fn seller_amount_too_low_fails() {
        let s = setup();
        let (mut tx, utxo) = build_mock_tx(
            s.p2sh,
            INPUT_VALUE,
            vec![],
            vec![
                TransactionOutput {
                    value: SELLER_AMOUNT as u64 - 1,
                    script_public_key: s.seller_spk.clone(),
                    covenant: None,
                },
                TransactionOutput {
                    value: FEE_AMOUNT as u64,
                    script_public_key: s.fee_spk.clone(),
                    covenant: None,
                },
            ],
            0,
        );

        let mut sb = ScriptBuilder::new();
        sb.add_op(OpFalse).unwrap();
        sb.add_data(&s.redeem).unwrap();
        tx.inputs[0].signature_script = sb.drain();

        assert!(verify_script(&tx, &utxo).is_err());
    }

    #[test]
    fn wrong_fee_address_fails() {
        let s = setup();
        let (_, wrong_pk) = generate_keypair();

        let (mut tx, utxo) = build_mock_tx(
            s.p2sh,
            INPUT_VALUE,
            vec![],
            vec![
                TransactionOutput {
                    value: SELLER_AMOUNT as u64,
                    script_public_key: s.seller_spk.clone(),
                    covenant: None,
                },
                TransactionOutput {
                    value: FEE_AMOUNT as u64,
                    script_public_key: p2pk_spk(&wrong_pk),
                    covenant: None,
                },
            ],
            0,
        );

        let mut sb = ScriptBuilder::new();
        sb.add_op(OpFalse).unwrap();
        sb.add_data(&s.redeem).unwrap();
        tx.inputs[0].signature_script = sb.drain();

        assert!(verify_script(&tx, &utxo).is_err());
    }

    #[test]
    fn fee_amount_too_low_fails() {
        let s = setup();
        let (mut tx, utxo) = build_mock_tx(
            s.p2sh,
            INPUT_VALUE,
            vec![],
            vec![
                TransactionOutput {
                    value: SELLER_AMOUNT as u64,
                    script_public_key: s.seller_spk.clone(),
                    covenant: None,
                },
                TransactionOutput {
                    value: FEE_AMOUNT as u64 - 1,
                    script_public_key: s.fee_spk.clone(),
                    covenant: None,
                },
            ],
            0,
        );

        let mut sb = ScriptBuilder::new();
        sb.add_op(OpFalse).unwrap();
        sb.add_data(&s.redeem).unwrap();
        tx.inputs[0].signature_script = sb.drain();

        assert!(verify_script(&tx, &utxo).is_err());
    }
}
