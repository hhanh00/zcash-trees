//! Zcash Merkle tree structures and warp sync primitives.
//!
//! Provides Merkle tree types, witness management, and hashers for the
//! Sapling and Orchard shielded pools, as well as transparent transaction types.

/// A 32-byte hash (e.g. a Merkle node, leaf commitment, or block hash).
pub type Hash32 = [u8; 32];

pub mod network;
pub mod types;
pub mod warp;
