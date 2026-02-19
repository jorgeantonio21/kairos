//! Kairos SDK - Rust client for the Kairos blockchain
//!
//! This SDK provides a high-level API for interacting with the Kairos network.
//!
//! # Quick Start
//!
//! ```ignore
//! use kairos_sdk::{KairosClient, Wallet, TxBuilder};
//! use std::time::Duration;
//!
//! #[tokio::main]
//! async fn main() -> kairos_sdk::Result<()> {
//!     // Connect to a node
//!     let client = KairosClient::connect("http://localhost:50051").await?;
//!
//!     // Create or load a wallet
//!     let wallet = Wallet::generate();
//!     println!("Address: {}", wallet.address());
//!
//!     // Get current nonce
//!     let nonce = client.account().get_nonce(wallet.address()).await?;
//!
//!     // Build and sign a transaction
//!     let recipient = Address::from_hex("...")?;
//!     let tx = TxBuilder::transfer(recipient, 1000)
//!         .with_fee(10)
//!         .sign(&wallet, nonce)?;
//!
//!     // Submit and wait for confirmation
//!     let receipt = client.submit_and_wait(tx, Duration::from_secs(30)).await?;
//!     println!("Tx included in block: {}", receipt.block_height);
//!
//!     Ok(())
//! }
//! ```

pub mod account;
pub mod block;
pub mod client;
pub mod error;
pub mod subscription;
pub mod transaction;
pub mod types;
pub mod wallet;

// Re-exports for convenience
pub use account::{Account, AccountClient};
pub use block::{Block, BlockClient};
pub use client::{ClientConfig, KairosClient};
pub use error::{Error, Result};
pub use subscription::SubscriptionClient;
pub use transaction::{SignedTransaction, TxBuilder, TxInfo, TxReceipt, TxStatus, TxType};
pub use types::{Address, Hash};
pub use wallet::Wallet;
