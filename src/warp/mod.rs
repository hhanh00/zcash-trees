//! Merkle tree structures, witness management, and transparent transaction types
//! for Zcash warp sync.

pub mod edge;
pub mod hasher;
pub mod legacy;
mod orchard;
mod sapling;
pub mod witnesses;

use crate::Hash32;
use bincode::{Decode, Encode};
use secp256k1::SecretKey;

/// Depth of the Zcash note commitment Merkle tree.
pub const MERKLE_DEPTH: u8 = 32;

/// A compact Merkle tree edge: one slot per level holding an optional node hash.
///
/// This is a "Merkle frontier" representation — it stores only the rightmost
/// subtree hashes at each level, which is sufficient to compute the root and
/// append new leaves incrementally.
///
/// When an entry is on the "right" node, this has the left node
/// Otherwise, the sibling is the empty root and we store None
#[derive(Clone, Default, Encode, Decode, PartialEq, Debug)]
pub struct Edge(pub [Option<Hash32>; MERKLE_DEPTH as usize]);

/// A full Merkle authentication path (sibling hashes at every level).
/// All the hashes are resolved to actual values (including the empty roots)
#[derive(Encode, Decode, Default, Debug)]
pub struct AuthPath(pub [Hash32; MERKLE_DEPTH as usize]);

/// An authentication path together with the tree position it is valid for.
#[derive(Encode, Decode, Default, Debug)]
pub struct FragmentAuthPath(pub AuthPath, pub u32);

/// A Merkle tree witness for a single leaf.
///
/// Tracks the leaf value, its position, the ommers (sibling subtrees), and the
/// tree anchor (root at the time the witness was created).
#[derive(Clone, Default, Encode, Decode, PartialEq, Debug)]
pub struct Witness {
    pub value: Hash32,
    pub position: u32,
    pub ommers: Edge,
    /// Tree root at the time this witness was recorded (for debugging).
    pub anchor: Hash32,
}

impl std::fmt::Display for Witness {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{} {} {}", self.position, hex::encode(self.value), hex::encode(self.anchor))
    }
}

/// A block header with hash and parent hash as fixed-size arrays.
#[derive(Clone, Default, Encode, Decode, Debug)]
pub struct BlockHeader {
    pub height: u32,
    pub hash: Hash32,
    pub prev_hash: Hash32,
    pub timestamp: u32,
}

/// Trait for pool-specific Merkle hash functions (Sapling / Orchard).
pub trait Hasher: std::fmt::Debug + Default {
    /// Returns the empty leaf hash for this tree.
    fn empty(&self) -> Hash32;
    /// Combines two child hashes at the given depth into a parent hash.
    fn combine(&self, depth: u8, l: &Hash32, r: &Hash32) -> Hash32;
    /// Combines pairs of hashes in a layer in parallel.
    fn parallel_combine(&self, depth: u8, layer: &[Hash32], pairs: usize) -> Vec<Hash32>;
    /// Like [`parallel_combine`] but operates on optional hashes.
    fn parallel_combine_opt(
        &self,
        depth: u8,
        layer: &[Option<Hash32>],
        pairs: usize,
    ) -> Vec<Option<Hash32>>;
}

/// Reference to a transaction output (txid + output index).
#[derive(Clone, Default, Encode, Decode, Debug)]
pub struct OutPoint {
    pub txid: Hash32,
    pub vout: u32,
}

/// A transparent transaction output with a parsed address.
#[derive(Default, Debug)]
pub struct TxOut {
    pub address: Option<TransparentAddress>,
    pub value: u64,
    pub vout: u32,
}

/// A transparent transaction output with a string-encoded address.
#[derive(Clone, Default, Encode, Decode, Debug)]
pub struct TxOut2 {
    pub address: Option<String>,
    pub value: u64,
    pub vout: u32,
}

/// A fully resolved transparent transaction.
#[derive(Debug)]
pub struct TransparentTx {
    pub account: u32,
    pub external: u32,
    pub addr_index: u32,
    pub address: TransparentAddress,
    pub height: u32,
    pub timestamp: u32,
    pub txid: Hash32,
    pub vins: Vec<OutPoint>,
    pub vouts: Vec<TxOut>,
}

/// A spent transparent output.
#[derive(Debug)]
pub struct STXO {
    pub account: u32,
    pub txid: Hash32,
    pub vout: u32,
    pub address: String,
    pub value: u64,
}

/// An unspent transparent output.
#[derive(Debug)]
pub struct UTXO {
    pub is_new: bool,
    pub id: u32,
    pub account: u32,
    pub external: u32,
    pub addr_index: u32,
    pub height: u32,
    pub timestamp: u32,
    pub txid: Hash32,
    pub vout: u32,
    pub address: String,
    pub value: u64,
}

/// A transparent address together with its spending key.
#[derive(Debug)]
pub struct TransparentSK {
    pub address: String,
    pub sk: SecretKey,
}

use zcash_transparent::address::TransparentAddress;
