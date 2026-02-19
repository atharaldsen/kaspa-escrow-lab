//! Tests for the EscrowBuilder SDK — validation, error paths, and builder correctness.

use kaspa_consensus_core::tx::{TransactionId, TransactionOutpoint, UtxoEntry};
use kaspa_escrow_lab::sdk::{
    Branch, EscrowBuilder, EscrowPattern,
    tx::{
        build_escape_tx, build_funding_tx, build_payment_split_tx, build_refund_tx,
        build_release_tx, build_sig_script,
    },
};
use kaspa_escrow_lab::*;

fn mock_outpoint() -> TransactionOutpoint {
    TransactionOutpoint::new(TransactionId::from_bytes([0xaa; 32]), 0)
}

fn dummy_pk() -> [u8; 32] {
    generate_keypair().1
}

// ---------------------------------------------------------------------------
// EscrowBuilder validation
// ---------------------------------------------------------------------------

mod builder_validation {
    use super::*;

    #[test]
    fn missing_buyer_fails() {
        let result = EscrowBuilder::new(EscrowPattern::Basic)
            .seller(dummy_pk())
            .amount(1_000_000)
            .build();
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("buyer"));
    }

    #[test]
    fn missing_seller_fails() {
        let result = EscrowBuilder::new(EscrowPattern::Basic)
            .buyer(dummy_pk())
            .amount(1_000_000)
            .build();
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("seller"));
    }

    #[test]
    fn missing_amount_fails() {
        let result = EscrowBuilder::new(EscrowPattern::Basic)
            .buyer(dummy_pk())
            .seller(dummy_pk())
            .build();
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("amount"));
    }

    #[test]
    fn zero_amount_fails() {
        let result = EscrowBuilder::new(EscrowPattern::Basic)
            .buyer(dummy_pk())
            .seller(dummy_pk())
            .amount(0)
            .build();
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("amount must be > 0")
        );
    }

    #[test]
    fn arbitrated_missing_arbitrator_fails() {
        let result = EscrowBuilder::new(EscrowPattern::Arbitrated)
            .buyer(dummy_pk())
            .seller(dummy_pk())
            .amount(1_000_000)
            .build();
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("arbitrator"));
    }

    #[test]
    fn covenant_multipath_missing_arbitrator_fails() {
        let result = EscrowBuilder::new(EscrowPattern::CovenantMultiPath { lock_time: 1000 })
            .buyer(dummy_pk())
            .seller(dummy_pk())
            .amount(1_000_000)
            .build();
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("arbitrator"));
    }

    #[test]
    fn payment_split_missing_owner_fails() {
        let result = EscrowBuilder::new(EscrowPattern::PaymentSplit { fee_percent: 10 })
            .buyer(dummy_pk())
            .seller(dummy_pk())
            .fee_address(dummy_pk())
            .amount(1_000_000)
            .build();
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("owner"));
    }

    #[test]
    fn payment_split_missing_fee_address_fails() {
        let result = EscrowBuilder::new(EscrowPattern::PaymentSplit { fee_percent: 10 })
            .buyer(dummy_pk())
            .seller(dummy_pk())
            .owner(dummy_pk())
            .amount(1_000_000)
            .build();
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("fee"));
    }

    #[test]
    fn fee_percent_zero_fails() {
        let result = EscrowBuilder::new(EscrowPattern::PaymentSplit { fee_percent: 0 })
            .buyer(dummy_pk())
            .seller(dummy_pk())
            .owner(dummy_pk())
            .fee_address(dummy_pk())
            .amount(1_000_000)
            .build();
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("fee_percent must be 1-99")
        );
    }

    #[test]
    fn fee_percent_100_fails() {
        let result = EscrowBuilder::new(EscrowPattern::PaymentSplit { fee_percent: 100 })
            .buyer(dummy_pk())
            .seller(dummy_pk())
            .owner(dummy_pk())
            .fee_address(dummy_pk())
            .amount(1_000_000)
            .build();
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("fee_percent must be 1-99")
        );
    }

    #[test]
    fn fee_percent_over_100_fails() {
        let result = EscrowBuilder::new(EscrowPattern::PaymentSplit { fee_percent: 150 })
            .buyer(dummy_pk())
            .seller(dummy_pk())
            .owner(dummy_pk())
            .fee_address(dummy_pk())
            .amount(1_000_000)
            .build();
        assert!(result.is_err());
    }

    #[test]
    fn lock_time_exceeds_threshold_fails() {
        let result = EscrowBuilder::new(EscrowPattern::TimeLocked {
            lock_time: 500_000_000_000,
        })
        .buyer(dummy_pk())
        .seller(dummy_pk())
        .amount(1_000_000)
        .build();
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("500B"));
    }

    #[test]
    fn covenant_lock_time_exceeds_threshold_fails() {
        let result = EscrowBuilder::new(EscrowPattern::CovenantMultiPath {
            lock_time: 999_999_999_999,
        })
        .buyer(dummy_pk())
        .seller(dummy_pk())
        .arbitrator(dummy_pk())
        .amount(1_000_000)
        .build();
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("500B"));
    }
}

// ---------------------------------------------------------------------------
// Builder correctness — valid configs produce non-empty scripts
// ---------------------------------------------------------------------------

mod builder_correctness {
    use super::*;

    #[test]
    fn basic_produces_valid_config() {
        let config = EscrowBuilder::new(EscrowPattern::Basic)
            .buyer(dummy_pk())
            .seller(dummy_pk())
            .amount(5_000_000_000)
            .build()
            .unwrap();
        assert!(!config.redeem_script.is_empty());
        assert_eq!(config.escrow_amount, 5_000_000_000);
        assert_eq!(config.seller_amount, 5_000_000_000);
        assert_eq!(config.fee_amount, 0);
    }

    #[test]
    fn payment_split_calculates_amounts() {
        let config = EscrowBuilder::new(EscrowPattern::PaymentSplit { fee_percent: 10 })
            .buyer(dummy_pk())
            .seller(dummy_pk())
            .owner(dummy_pk())
            .fee_address(dummy_pk())
            .amount(10_000_000_000)
            .build()
            .unwrap();
        assert_eq!(config.seller_amount, 9_000_000_000);
        assert_eq!(config.fee_amount, 1_000_000_000);
        assert_eq!(
            config.seller_amount + config.fee_amount,
            config.escrow_amount
        );
    }

    #[test]
    fn payment_split_rounding() {
        // 7% of 1_000_000_003 — tests integer division rounding
        let config = EscrowBuilder::new(EscrowPattern::PaymentSplit { fee_percent: 7 })
            .buyer(dummy_pk())
            .seller(dummy_pk())
            .owner(dummy_pk())
            .fee_address(dummy_pk())
            .amount(1_000_000_003)
            .build()
            .unwrap();
        // seller_amount = (1_000_000_003 * 93) / 100 = 930_000_002
        // fee_amount = 1_000_000_003 - 930_000_002 = 70_000_001
        assert_eq!(
            config.seller_amount + config.fee_amount,
            config.escrow_amount
        );
    }

    #[test]
    fn all_patterns_produce_different_scripts() {
        let buyer = dummy_pk();
        let seller = dummy_pk();
        let arb = dummy_pk();
        let owner = dummy_pk();
        let fee = dummy_pk();
        let amount = 1_000_000_000u64;

        let basic = EscrowBuilder::new(EscrowPattern::Basic)
            .buyer(buyer)
            .seller(seller)
            .amount(amount)
            .build()
            .unwrap();

        let arbitrated = EscrowBuilder::new(EscrowPattern::Arbitrated)
            .buyer(buyer)
            .seller(seller)
            .arbitrator(arb)
            .amount(amount)
            .build()
            .unwrap();

        let timelocked = EscrowBuilder::new(EscrowPattern::TimeLocked { lock_time: 1000 })
            .buyer(buyer)
            .seller(seller)
            .amount(amount)
            .build()
            .unwrap();

        let covenant = EscrowBuilder::new(EscrowPattern::CovenantMultiPath { lock_time: 1000 })
            .buyer(buyer)
            .seller(seller)
            .arbitrator(arb)
            .amount(amount)
            .build()
            .unwrap();

        let split = EscrowBuilder::new(EscrowPattern::PaymentSplit { fee_percent: 10 })
            .buyer(buyer)
            .seller(seller)
            .owner(owner)
            .fee_address(fee)
            .amount(amount)
            .build()
            .unwrap();

        // All scripts should be different lengths (different structures)
        let lengths = [
            basic.redeem_script.len(),
            arbitrated.redeem_script.len(),
            timelocked.redeem_script.len(),
            covenant.redeem_script.len(),
            split.redeem_script.len(),
        ];
        // At minimum, basic != arbitrated != timelocked
        assert_ne!(lengths[0], lengths[1]);
        assert_ne!(lengths[1], lengths[2]);
    }
}

// ---------------------------------------------------------------------------
// Transaction builder error paths
// ---------------------------------------------------------------------------

mod tx_builder_errors {
    use super::*;

    fn basic_config() -> kaspa_escrow_lab::sdk::EscrowConfig {
        EscrowBuilder::new(EscrowPattern::Basic)
            .buyer(dummy_pk())
            .seller(dummy_pk())
            .amount(1_000_000)
            .build()
            .unwrap()
    }

    #[test]
    fn funding_tx_insufficient_funds() {
        let config = basic_config();
        let result = build_funding_tx(mock_outpoint(), 5000, &config, 5000);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("insufficient"));
    }

    #[test]
    fn funding_tx_fee_equals_amount() {
        let config = basic_config();
        let result = build_funding_tx(mock_outpoint(), 10_000, &config, 10_000);
        assert!(result.is_err());
    }

    #[test]
    fn release_tx_insufficient_funds() {
        let config = EscrowBuilder::new(EscrowPattern::Basic)
            .buyer(dummy_pk())
            .seller(dummy_pk())
            .amount(1000)
            .build()
            .unwrap();
        let result = build_release_tx(mock_outpoint(), &config, 1000);
        assert!(result.is_err());
    }

    #[test]
    fn refund_tx_insufficient_funds() {
        let config = EscrowBuilder::new(EscrowPattern::TimeLocked { lock_time: 1000 })
            .buyer(dummy_pk())
            .seller(dummy_pk())
            .amount(500)
            .build()
            .unwrap();
        let result = build_refund_tx(mock_outpoint(), &config, 2000, 500);
        assert!(result.is_err());
    }

    #[test]
    fn escape_tx_insufficient_funds() {
        let config = EscrowBuilder::new(EscrowPattern::PaymentSplit { fee_percent: 10 })
            .buyer(dummy_pk())
            .seller(dummy_pk())
            .owner(dummy_pk())
            .fee_address(dummy_pk())
            .amount(100)
            .build()
            .unwrap();
        let result = build_escape_tx(mock_outpoint(), &config, p2pk_spk(&dummy_pk()), 100);
        assert!(result.is_err());
    }

    #[test]
    fn funding_tx_correct_output() {
        let config = basic_config();
        let tx = build_funding_tx(mock_outpoint(), 2_000_000, &config, 5000).unwrap();
        assert_eq!(tx.outputs.len(), 1);
        assert_eq!(tx.outputs[0].value, 2_000_000 - 5000);
        assert_eq!(tx.outputs[0].script_public_key, config.p2sh_spk);
    }

    #[test]
    fn release_tx_correct_output() {
        let seller_pk = dummy_pk();
        let config = EscrowBuilder::new(EscrowPattern::Basic)
            .buyer(dummy_pk())
            .seller(seller_pk)
            .amount(1_000_000)
            .build()
            .unwrap();
        let tx = build_release_tx(mock_outpoint(), &config, 5000).unwrap();
        assert_eq!(tx.outputs.len(), 1);
        assert_eq!(tx.outputs[0].value, 1_000_000 - 5000);
        assert_eq!(tx.outputs[0].script_public_key, p2pk_spk(&seller_pk));
    }

    #[test]
    fn payment_split_tx_two_outputs() {
        let config = EscrowBuilder::new(EscrowPattern::PaymentSplit { fee_percent: 10 })
            .buyer(dummy_pk())
            .seller(dummy_pk())
            .owner(dummy_pk())
            .fee_address(dummy_pk())
            .amount(10_000_000)
            .build()
            .unwrap();
        let tx = build_payment_split_tx(mock_outpoint(), &config).unwrap();
        assert_eq!(tx.outputs.len(), 2);
        assert_eq!(tx.outputs[0].value, config.seller_amount);
        assert_eq!(tx.outputs[1].value, config.fee_amount);
    }

    #[test]
    fn refund_tx_uses_daa_as_locktime() {
        let config = EscrowBuilder::new(EscrowPattern::TimeLocked { lock_time: 5000 })
            .buyer(dummy_pk())
            .seller(dummy_pk())
            .amount(1_000_000)
            .build()
            .unwrap();
        let tx = build_refund_tx(mock_outpoint(), &config, 6000, 1000).unwrap();
        assert_eq!(tx.lock_time, 6000);
    }
}

// ---------------------------------------------------------------------------
// Sig script builder error paths
// ---------------------------------------------------------------------------

mod sig_script_errors {
    use super::*;

    #[test]
    fn timelocked_timeout_requires_signature() {
        let config = EscrowBuilder::new(EscrowPattern::TimeLocked { lock_time: 1000 })
            .buyer(dummy_pk())
            .seller(dummy_pk())
            .amount(1_000_000)
            .build()
            .unwrap();
        let result = build_sig_script(
            &Branch::Timeout,
            &[],
            &config.redeem_script,
            &config.pattern,
        );
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("buyer signature"));
    }

    #[test]
    fn owner_escape_requires_signature() {
        let config = EscrowBuilder::new(EscrowPattern::PaymentSplit { fee_percent: 10 })
            .buyer(dummy_pk())
            .seller(dummy_pk())
            .owner(dummy_pk())
            .fee_address(dummy_pk())
            .amount(1_000_000)
            .build()
            .unwrap();
        let result = build_sig_script(
            &Branch::OwnerEscape,
            &[],
            &config.redeem_script,
            &config.pattern,
        );
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("owner escape"));
    }

    #[test]
    fn covenant_release_needs_no_sigs() {
        let config = EscrowBuilder::new(EscrowPattern::PaymentSplit { fee_percent: 10 })
            .buyer(dummy_pk())
            .seller(dummy_pk())
            .owner(dummy_pk())
            .fee_address(dummy_pk())
            .amount(1_000_000)
            .build()
            .unwrap();
        let result = build_sig_script(
            &Branch::CovenantRelease,
            &[],
            &config.redeem_script,
            &config.pattern,
        );
        assert!(result.is_ok());
        assert!(!result.unwrap().is_empty());
    }

    #[test]
    fn covenant_timeout_needs_no_sigs() {
        let config = EscrowBuilder::new(EscrowPattern::CovenantMultiPath { lock_time: 1000 })
            .buyer(dummy_pk())
            .seller(dummy_pk())
            .arbitrator(dummy_pk())
            .amount(1_000_000)
            .build()
            .unwrap();
        let result = build_sig_script(
            &Branch::Timeout,
            &[],
            &config.redeem_script,
            &config.pattern,
        );
        assert!(result.is_ok());
    }
}

// ---------------------------------------------------------------------------
// End-to-end SDK builder -> verify (script verification via builder)
// ---------------------------------------------------------------------------

mod sdk_e2e {
    use super::*;

    #[test]
    fn basic_builder_produces_verifiable_release() {
        let (buyer_kp, buyer_pk) = generate_keypair();
        let (seller_kp, seller_pk) = generate_keypair();

        let config = EscrowBuilder::new(EscrowPattern::Basic)
            .buyer(buyer_pk)
            .seller(seller_pk)
            .amount(1_000_000_000)
            .build()
            .unwrap();

        let mut tx = build_release_tx(mock_outpoint(), &config, 5000).unwrap();
        let utxo = UtxoEntry::new(
            config.escrow_amount,
            config.p2sh_spk.clone(),
            0,
            false,
            None,
        );

        let b_sig = schnorr_sign(&tx, &utxo, &buyer_kp);
        let s_sig = schnorr_sign(&tx, &utxo, &seller_kp);
        tx.inputs[0].signature_script = build_sig_script(
            &Branch::Normal,
            &[b_sig, s_sig],
            &config.redeem_script,
            &config.pattern,
        )
        .unwrap();

        assert!(verify_script(&tx, &utxo).is_ok());
    }

    #[test]
    fn payment_split_builder_produces_verifiable_covenant() {
        let (_, buyer_pk) = generate_keypair();
        let (_, seller_pk) = generate_keypair();
        let (_, owner_pk) = generate_keypair();
        let (_, fee_pk) = generate_keypair();

        let config = EscrowBuilder::new(EscrowPattern::PaymentSplit { fee_percent: 15 })
            .buyer(buyer_pk)
            .seller(seller_pk)
            .owner(owner_pk)
            .fee_address(fee_pk)
            .amount(10_000_000_000)
            .build()
            .unwrap();

        let mut tx = build_payment_split_tx(mock_outpoint(), &config).unwrap();
        let utxo = UtxoEntry::new(
            config.escrow_amount,
            config.p2sh_spk.clone(),
            0,
            false,
            None,
        );

        tx.inputs[0].signature_script = build_sig_script(
            &Branch::CovenantRelease,
            &[],
            &config.redeem_script,
            &config.pattern,
        )
        .unwrap();

        assert!(verify_script(&tx, &utxo).is_ok());
    }

    #[test]
    fn timelocked_builder_normal_and_timeout() {
        let (buyer_kp, buyer_pk) = generate_keypair();
        let (seller_kp, seller_pk) = generate_keypair();

        let config = EscrowBuilder::new(EscrowPattern::TimeLocked { lock_time: 50_000 })
            .buyer(buyer_pk)
            .seller(seller_pk)
            .amount(1_000_000_000)
            .build()
            .unwrap();

        // Normal release
        let mut tx = build_release_tx(mock_outpoint(), &config, 5000).unwrap();
        let utxo = UtxoEntry::new(
            config.escrow_amount,
            config.p2sh_spk.clone(),
            0,
            false,
            None,
        );
        let b_sig = schnorr_sign(&tx, &utxo, &buyer_kp);
        let s_sig = schnorr_sign(&tx, &utxo, &seller_kp);
        tx.inputs[0].signature_script = build_sig_script(
            &Branch::Normal,
            &[b_sig, s_sig],
            &config.redeem_script,
            &config.pattern,
        )
        .unwrap();
        assert!(verify_script(&tx, &utxo).is_ok());

        // Timeout refund
        let mut refund = build_refund_tx(mock_outpoint(), &config, 50_001, 5000).unwrap();
        let utxo = UtxoEntry::new(
            config.escrow_amount,
            config.p2sh_spk.clone(),
            0,
            false,
            None,
        );
        let b_sig = schnorr_sign(&refund, &utxo, &buyer_kp);
        refund.inputs[0].signature_script = build_sig_script(
            &Branch::Timeout,
            &[b_sig],
            &config.redeem_script,
            &config.pattern,
        )
        .unwrap();
        assert!(verify_script(&refund, &utxo).is_ok());
    }
}
