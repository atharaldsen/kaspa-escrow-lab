//! Kaspa Escrow Lab
//!
//! Experimental project for learning covenant and escrow patterns on Kaspa Testnet 12.
//!
//! ## Goals
//! - Understand covenant script construction (txscript opcodes)
//! - Experiment with programmable UTXOs (multi-sig, timelocks, conditional paths)
//! - Test covenant introspection for enforcing output constraints
//!
//! ## Running Examples
//! ```bash
//! cargo run --example basic_escrow
//! cargo run --example multisig_escrow
//! cargo run --example timelock_escrow
//! cargo run --example covenant_escrow
//! cargo run --example amount_constrained_escrow
//!
//! # Live (requires TN12 node)
//! cargo run --example connect_test
//! cargo run --example live_escrow
//! ```

fn main() {
    println!("Kaspa Escrow Lab");
    println!("================");
    println!();
    println!("Local script verification examples:");
    println!();
    println!("  cargo run --example basic_escrow");
    println!("    2-of-2 multisig: buyer + seller must both sign");
    println!();
    println!("  cargo run --example multisig_escrow");
    println!("    2-of-3 with arbitrator: any 2 of buyer/seller/arbitrator");
    println!();
    println!("  cargo run --example timelock_escrow");
    println!("    Time-locked: both sign OR buyer refund after timeout");
    println!();
    println!("  cargo run --example covenant_escrow");
    println!("    Multi-path covenant: normal/dispute/timeout with output enforcement");
    println!();
    println!("  cargo run --example amount_constrained_escrow");
    println!("    Payment splits: covenant enforces seller + fee amounts/destinations");
    println!();
    println!("Live examples (requires TN12 node):");
    println!();
    println!("  cargo run --example connect_test");
    println!("    Test connection to local TN12 node");
    println!();
    println!("  cargo run --example live_escrow");
    println!("    End-to-end 2-of-2 escrow on testnet");
    println!();
    println!("  cargo run --example live_covenant_escrow");
    println!("    Covenant timeout refund with on-chain introspection");
}
