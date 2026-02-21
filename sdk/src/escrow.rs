use kaspa_consensus_core::tx::ScriptPublicKey;
use kaspa_txscript::pay_to_script_hash_script;

use crate::error::EscrowError;
use crate::helpers::{p2pk_spk, spk_to_bytes};
use crate::script;

/// Buffer subtracted from escrow_amount for covenant minimum refund,
/// leaving room for the transaction fee (~200-byte tx).
const COVENANT_FEE_BUFFER: u64 = 10_000;

/// High-level escrow pattern selection.
#[derive(Debug, Clone)]
pub enum EscrowPattern {
    /// 2-of-2 multisig: buyer + seller must both sign.
    Basic,
    /// 2-of-3: any 2 of buyer/seller/arbitrator.
    Arbitrated,
    /// 2-of-2 normal OR buyer-only after CLTV timeout.
    TimeLocked { lock_time: u64 },
    /// 2-of-2 normal OR 2-of-3 dispute OR timeout with covenant output constraints.
    CovenantMultiPath { lock_time: u64 },
    /// Owner escape OR covenant-enforced payment split (seller + platform fee).
    PaymentSplit { fee_percent: u64 },
}

/// Fully resolved escrow configuration with computed script.
#[derive(Debug, Clone)]
pub struct EscrowConfig {
    pub pattern: EscrowPattern,
    pub buyer_pk: [u8; 32],
    pub seller_pk: [u8; 32],
    pub arbitrator_pk: Option<[u8; 32]>,
    pub owner_pk: Option<[u8; 32]>,
    pub fee_pk: Option<[u8; 32]>,
    pub escrow_amount: u64,
    pub seller_amount: u64,
    pub fee_amount: u64,
    pub redeem_script: Vec<u8>,
    pub p2sh_spk: ScriptPublicKey,
}

/// Builder for constructing escrow configurations.
pub struct EscrowBuilder {
    pattern: EscrowPattern,
    buyer_pk: Option<[u8; 32]>,
    seller_pk: Option<[u8; 32]>,
    arbitrator_pk: Option<[u8; 32]>,
    owner_pk: Option<[u8; 32]>,
    fee_pk: Option<[u8; 32]>,
    amount: Option<u64>,
}

impl EscrowBuilder {
    pub fn new(pattern: EscrowPattern) -> Self {
        Self {
            pattern,
            buyer_pk: None,
            seller_pk: None,
            arbitrator_pk: None,
            owner_pk: None,
            fee_pk: None,
            amount: None,
        }
    }

    pub fn buyer(mut self, pk: [u8; 32]) -> Self {
        self.buyer_pk = Some(pk);
        self
    }

    pub fn seller(mut self, pk: [u8; 32]) -> Self {
        self.seller_pk = Some(pk);
        self
    }

    pub fn arbitrator(mut self, pk: [u8; 32]) -> Self {
        self.arbitrator_pk = Some(pk);
        self
    }

    pub fn owner(mut self, pk: [u8; 32]) -> Self {
        self.owner_pk = Some(pk);
        self
    }

    pub fn fee_address(mut self, pk: [u8; 32]) -> Self {
        self.fee_pk = Some(pk);
        self
    }

    pub fn amount(mut self, sompi: u64) -> Self {
        self.amount = Some(sompi);
        self
    }

    pub fn build(self) -> Result<EscrowConfig, EscrowError> {
        let buyer_pk = self
            .buyer_pk
            .ok_or_else(|| EscrowError::InvalidConfig("buyer pubkey required".into()))?;
        let seller_pk = self
            .seller_pk
            .ok_or_else(|| EscrowError::InvalidConfig("seller pubkey required".into()))?;
        let escrow_amount = self
            .amount
            .ok_or_else(|| EscrowError::InvalidConfig("escrow amount required".into()))?;

        if escrow_amount == 0 {
            return Err(EscrowError::InvalidConfig(
                "escrow amount must be > 0".into(),
            ));
        }

        // Validate pattern-specific constraints
        match &self.pattern {
            EscrowPattern::PaymentSplit { fee_percent } => {
                if *fee_percent == 0 || *fee_percent >= 100 {
                    return Err(EscrowError::InvalidConfig(format!(
                        "fee_percent must be 1-99, got {fee_percent}"
                    )));
                }
            }
            EscrowPattern::TimeLocked { lock_time }
            | EscrowPattern::CovenantMultiPath { lock_time } => {
                if *lock_time >= 500_000_000_000 {
                    return Err(EscrowError::InvalidConfig(format!(
                        "lock_time must be < 500B (DAA score threshold), got {lock_time}"
                    )));
                }
            }
            _ => {}
        }

        let mut seller_amount = escrow_amount;
        let mut fee_amount = 0u64;

        let redeem_script = match &self.pattern {
            EscrowPattern::Basic => script::build_basic_script(&buyer_pk, &seller_pk)?,

            EscrowPattern::Arbitrated => {
                let arb = self.arbitrator_pk.ok_or_else(|| {
                    EscrowError::InvalidConfig("arbitrator pubkey required for Arbitrated".into())
                })?;
                script::build_arbitrated_script(&buyer_pk, &seller_pk, &arb)?
            }

            EscrowPattern::TimeLocked { lock_time } => {
                script::build_timelocked_script(&buyer_pk, &seller_pk, *lock_time)?
            }

            EscrowPattern::CovenantMultiPath { lock_time } => {
                let arb = self.arbitrator_pk.ok_or_else(|| {
                    EscrowError::InvalidConfig(
                        "arbitrator pubkey required for CovenantMultiPath".into(),
                    )
                })?;
                let buyer_spk = p2pk_spk(&buyer_pk);
                let buyer_spk_bytes = spk_to_bytes(&buyer_spk);
                let min_refund = escrow_amount.saturating_sub(COVENANT_FEE_BUFFER);
                script::build_covenant_multipath_script(
                    &buyer_pk,
                    &seller_pk,
                    &arb,
                    *lock_time,
                    &buyer_spk_bytes,
                    min_refund,
                )?
            }

            EscrowPattern::PaymentSplit { fee_percent } => {
                let owner = self.owner_pk.ok_or_else(|| {
                    EscrowError::InvalidConfig("owner pubkey required for PaymentSplit".into())
                })?;
                let fee_pk = self.fee_pk.ok_or_else(|| {
                    EscrowError::InvalidConfig("fee pubkey required for PaymentSplit".into())
                })?;

                seller_amount = (escrow_amount * (100 - fee_percent)) / 100;
                fee_amount = escrow_amount - seller_amount;

                let seller_spk = p2pk_spk(&seller_pk);
                let seller_spk_bytes = spk_to_bytes(&seller_spk);
                let fee_spk = p2pk_spk(&fee_pk);
                let fee_spk_bytes = spk_to_bytes(&fee_spk);

                script::build_payment_split_script(
                    &owner,
                    &seller_spk_bytes,
                    seller_amount,
                    &fee_spk_bytes,
                    fee_amount,
                )?
            }
        };

        let p2sh_spk = pay_to_script_hash_script(&redeem_script);

        Ok(EscrowConfig {
            pattern: self.pattern,
            buyer_pk,
            seller_pk,
            arbitrator_pk: self.arbitrator_pk,
            owner_pk: self.owner_pk,
            fee_pk: self.fee_pk,
            escrow_amount,
            seller_amount,
            fee_amount,
            redeem_script,
            p2sh_spk,
        })
    }
}
