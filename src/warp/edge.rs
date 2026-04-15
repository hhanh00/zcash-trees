use crate::warp::FragmentAuthPath;
use std::io::{Read, Write};
use zcash_encoding::Optional;

use super::{AuthPath, Edge, Hash32, Hasher, MERKLE_DEPTH};

impl Edge {
    /// Deserializes an edge from the Zcash consensus-encoded format.
    pub fn read<R: Read>(mut reader: R) -> std::io::Result<Self> {
        let mut edge = [None; MERKLE_DEPTH as usize];
        for e in edge.iter_mut() {
            *e = Optional::read(&mut reader, |r| {
                let mut repr = [0u8; 32];
                r.read_exact(&mut repr)?;
                Ok(repr)
            })?;
        }
        Ok(Edge(edge))
    }

    /// Serializes the edge in Zcash consensus-encoded format.
    pub fn write<W: Write>(&self, mut writer: W) -> std::io::Result<()> {
        for e in self.0.iter() {
            Optional::write(&mut writer, e.as_ref(), |w, h| w.write_all(h))?;
        }
        Ok(())
    }

    /// Appends a new leaf hash to the edge, merging full subtrees upward.
    pub fn append<H: Hasher>(&mut self, h: &H, leaf: Hash32) {
        let mut carry = leaf;
        for (depth, e) in self.0.iter_mut().enumerate() {
            match e {
                Some(existing) => {
                    carry = h.combine(depth as u8, existing, &carry);
                    *e = None;
                }
                None => {
                    *e = Some(carry);
                    return;
                }
            }
        }
    }

    /// Returns the total number of leaves represented by this edge.
    pub fn size(&self) -> usize {
        self.0.iter().enumerate().fold(0usize, |acc, (i, e)| {
            if e.is_some() { acc + (1 << i) } else { acc }
        })
    }

    /// Computes the Merkle root of the tree represented by this edge.
    pub fn root<H: Hasher>(&self, h: &H) -> Hash32 {
        let mut empty = h.empty();
        let mut hash = h.empty();
        for (depth, n) in self.0.iter().enumerate() {
            match n {
                Some(n) => {
                    hash = h.combine(depth as u8, n, &hash);
                }
                None => {
                    hash = h.combine(depth as u8, &hash, &empty);
                }
            }
            empty = h.combine(depth as u8, &empty, &empty);
        }
        hash
    }

    /// Converts the edge into an authentication path for its rightmost leaf,
    /// also returning the position of that leaf.
    pub fn to_auth_path<H: Hasher>(&self, h: &H) -> FragmentAuthPath {
        let mut position = 0;
        let mut empty = h.empty();
        let mut hash = h.empty();
        let mut path = AuthPath::default();
        for (depth, n) in self.0.iter().enumerate() {
            path.0[depth] = hash;
            match n {
                Some(n) => {
                    hash = h.combine(depth as u8, n, &hash);
                    position |= 1 << depth;
                }
                None => {
                    hash = h.combine(depth as u8, &hash, &empty);
                }
            }
            empty = h.combine(depth as u8, &empty, &empty);
        }
        FragmentAuthPath(path, position)
    }
}
