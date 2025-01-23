// Copyright (C) 2013-2020 Blockstack PBC, a public benefit corporation
// Copyright (C) 2020 Stacks Open Internet Foundation
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program.  If not, see <http://www.gnu.org/licenses/>.

use std::hash::Hash;
use std::io::{Seek, SeekFrom};
use std::{error, fmt, io, ptr};

use sha2::{Digest, Sha512_256 as TrieHasher};
use stacks_common::types::chainstate::{
    BlockHeaderHash, BurnchainHeaderHash, SortitionId, StacksBlockId, TrieHash,
    TRIEHASH_ENCODED_SIZE,
};
use stacks_common::util::hash::to_hex;
use stacks_common::util::log;

use crate::util_lib::db::Error as db_error;

pub mod bits;
pub mod cache;
pub mod file;
pub mod marf;
pub mod node;
pub mod profile;
pub mod proofs;
pub mod storage;
pub mod trie;
pub mod trie_sql;

#[cfg(test)]
pub mod test;

#[derive(Debug)]
pub struct TrieMerkleProof<T: MarfTrieId>(pub Vec<TrieMerkleProofType<T>>);

pub trait ClarityMarfTrieId:
    PartialEq + Clone + std::fmt::Display + std::fmt::Debug + std::convert::From<[u8; 32]>
{
    fn as_bytes(&self) -> &[u8];
    fn to_bytes(self) -> [u8; 32];
    fn from_bytes(from: [u8; 32]) -> Self;
    fn sentinel() -> Self;
}

#[derive(Clone)]
pub enum TrieMerkleProofType<T> {
    Node4((u8, ProofTrieNode<T>, [TrieHash; 3])),
    Node16((u8, ProofTrieNode<T>, [TrieHash; 15])),
    Node48((u8, ProofTrieNode<T>, [TrieHash; 47])),
    Node256((u8, ProofTrieNode<T>, [TrieHash; 255])),
    Leaf((u8, TrieLeaf)),
    Shunt((i64, Vec<TrieHash>)),
}

/// Merkle Proof Trie Pointers have a different structure
///   than the runtime representation --- the proof includes
///   the block header hash for back pointers.
#[derive(Debug, Clone, PartialEq)]
pub struct ProofTrieNode<T> {
    pub id: u8,
    pub path: Vec<u8>,
    pub ptrs: Vec<ProofTriePtr<T>>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct ProofTriePtr<T> {
    pub id: u8,
    pub chr: u8,
    pub back_block: T,
}

/// Leaf of a Trie.
#[derive(Clone)]
pub struct TrieLeaf {
    pub path: Vec<u8>,   // path to be lazily expanded
    pub data: MARFValue, // the actual data
}

pub trait MarfTrieId:
    ClarityMarfTrieId
    + rusqlite::types::ToSql
    + rusqlite::types::FromSql
    + stacks_common::codec::StacksMessageCodec
    + std::convert::From<MARFValue>
    + PartialEq
    + Eq
    + Hash
{
}

pub const SENTINEL_ARRAY: [u8; 32] = [255u8; 32];

macro_rules! impl_clarity_marf_trie_id {
    ($thing:ident) => {
        impl ClarityMarfTrieId for $thing {
            fn as_bytes(&self) -> &[u8] {
                self.as_ref()
            }
            fn to_bytes(self) -> [u8; 32] {
                self.0
            }
            fn sentinel() -> Self {
                Self(SENTINEL_ARRAY.clone())
            }
            fn from_bytes(bytes: [u8; 32]) -> Self {
                Self(bytes)
            }
        }

        impl From<MARFValue> for $thing {
            fn from(m: MARFValue) -> Self {
                let h = m.0;
                let mut d = [0u8; 32];
                for i in 0..32 {
                    d[i] = h[i];
                }
                for i in 32..h.len() {
                    if h[i] != 0 {
                        panic!(
                            "Failed to convert MARF value into BHH: data stored after 32nd byte"
                        );
                    }
                }
                Self(d)
            }
        }
    };
}

impl_clarity_marf_trie_id!(BurnchainHeaderHash);
impl_clarity_marf_trie_id!(StacksBlockId);
impl_clarity_marf_trie_id!(SortitionId);
#[cfg(test)]
impl_clarity_marf_trie_id!(BlockHeaderHash);

impl MarfTrieId for SortitionId {}
impl MarfTrieId for StacksBlockId {}
impl MarfTrieId for BurnchainHeaderHash {}
#[cfg(test)]
impl MarfTrieId for BlockHeaderHash {}

/// Structure that holds the actual data in a MARF leaf node.
/// It only stores the hash of some value string, but we add 8 extra bytes for future extensions.
/// If not used (the rule today), then they should all be 0.
pub struct MARFValue(pub [u8; 40]);
impl_array_newtype!(MARFValue, u8, 40);
impl_array_hexstring_fmt!(MARFValue);
impl_byte_array_newtype!(MARFValue, u8, 40);
impl_byte_array_message_codec!(MARFValue, 40);
pub const MARF_VALUE_ENCODED_SIZE: u32 = 40;

impl From<u32> for MARFValue {
    fn from(value: u32) -> MARFValue {
        let h = value.to_le_bytes();
        let mut d = [0u8; MARF_VALUE_ENCODED_SIZE as usize];
        if h.len() > MARF_VALUE_ENCODED_SIZE as usize {
            panic!("Cannot convert a u32 into a MARF Value.");
        }
        d[..h.len()].copy_from_slice(&h[..]);
        MARFValue(d)
    }
}

impl<T: MarfTrieId> From<T> for MARFValue {
    fn from(bhh: T) -> MARFValue {
        let h = bhh.to_bytes();
        let mut d = [0u8; MARF_VALUE_ENCODED_SIZE as usize];
        if h.len() > MARF_VALUE_ENCODED_SIZE as usize {
            panic!("Cannot convert a BHH into a MARF Value.");
        }
        d[..h.len()].copy_from_slice(&h[..]);
        MARFValue(d)
    }
}

impl From<MARFValue> for u32 {
    fn from(m: MARFValue) -> u32 {
        let h = m.0;
        let mut d = [0u8; 4];

        d[..4].copy_from_slice(&h[..4]);
        for i in 4..h.len() {
            if h[i] != 0 {
                panic!("Failed to convert MARF value into u32: data stored after 4th byte");
            }
        }
        u32::from_le_bytes(d)
    }
}

impl MARFValue {
    /// Construct from a TRIEHASH_ENCODED_SIZE-length slice
    pub fn from_value_hash_bytes(h: &[u8; TRIEHASH_ENCODED_SIZE]) -> MARFValue {
        let mut d = [0u8; MARF_VALUE_ENCODED_SIZE as usize];
        d[..TRIEHASH_ENCODED_SIZE].copy_from_slice(&h[..TRIEHASH_ENCODED_SIZE]);
        MARFValue(d)
    }

    /// Construct from a TrieHash
    pub fn from_value_hash(h: &TrieHash) -> MARFValue {
        MARFValue::from_value_hash_bytes(h.as_bytes())
    }

    /// Construct from a String that encodes a value inserted into the underlying data store
    pub fn from_value(s: &str) -> MARFValue {
        let mut tmp = [0u8; 32];

        let mut hasher = TrieHasher::new();
        hasher.update(s.as_bytes());
        tmp.copy_from_slice(hasher.finalize().as_slice());

        MARFValue::from_value_hash_bytes(&tmp)
    }

    /// Convert to a byte vector
    pub fn to_vec(&self) -> Vec<u8> {
        self.as_bytes().to_vec()
    }

    /// Extract the value hash from the MARF value
    pub fn to_value_hash(&self) -> TrieHash {
        let mut h = [0u8; TRIEHASH_ENCODED_SIZE];
        h.copy_from_slice(&self.0[0..TRIEHASH_ENCODED_SIZE]);
        TrieHash(h)
    }
}

#[derive(Debug)]
pub enum Error {
    NotOpenedError,
    IOError(io::Error),
    SQLError(rusqlite::Error),
    RequestedIdentifierForExtensionTrie,
    NotFoundError,
    BackptrNotFoundError,
    ExistsError,
    BadSeekValue,
    CorruptionError(String),
    BlockHashMapCorruptionError(Option<Box<Error>>),
    ReadOnlyError,
    UnconfirmedError,
    NotDirectoryError,
    PartialWriteError,
    InProgressError,
    WriteNotBegunError,
    CursorError(node::CursorError),
    RestoreMarfBlockError(Box<Error>),
    NonMatchingForks([u8; 32], [u8; 32]),
}

impl From<io::Error> for Error {
    fn from(err: io::Error) -> Self {
        Error::IOError(err)
    }
}

impl From<rusqlite::Error> for Error {
    fn from(err: rusqlite::Error) -> Self {
        if let rusqlite::Error::QueryReturnedNoRows = err {
            Error::NotFoundError
        } else {
            Error::SQLError(err)
        }
    }
}

impl From<db_error> for Error {
    fn from(e: db_error) -> Error {
        match e {
            db_error::SqliteError(se) => Error::SQLError(se),
            db_error::NotFoundError => Error::NotFoundError,
            _ => Error::CorruptionError(format!("{}", &e)),
        }
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            Error::IOError(ref e) => fmt::Display::fmt(e, f),
            Error::SQLError(ref e) => fmt::Display::fmt(e, f),
            Error::CorruptionError(ref s) => fmt::Display::fmt(s, f),
            Error::CursorError(ref e) => fmt::Display::fmt(e, f),
            Error::BlockHashMapCorruptionError(ref opt_e) => {
                f.write_str("Corrupted MARF BlockHashMap")?;
                match opt_e {
                    Some(e) => write!(f, ": {}", e),
                    None => Ok(()),
                }
            }
            Error::NotOpenedError => write!(f, "Tried to read data from unopened storage"),
            Error::NotFoundError => write!(f, "Object not found"),
            Error::BackptrNotFoundError => write!(f, "Object not found from backptrs"),
            Error::ExistsError => write!(f, "Object exists"),
            Error::BadSeekValue => write!(f, "Bad seek value"),
            Error::ReadOnlyError => write!(f, "Storage is in read-only mode"),
            Error::UnconfirmedError => write!(f, "Storage is in unconfirmed mode"),
            Error::NotDirectoryError => write!(f, "Not a directory"),
            Error::PartialWriteError => {
                write!(f, "Data is partially written and not yet recovered")
            }
            Error::InProgressError => write!(f, "Write was in progress"),
            Error::WriteNotBegunError => write!(f, "Write has not begun"),
            Error::RestoreMarfBlockError(_) => write!(
                f,
                "Failed to restore previous open block during block header check"
            ),
            Error::NonMatchingForks(_, _) => {
                write!(f, "The supplied blocks are not in the same fork")
            }
            Error::RequestedIdentifierForExtensionTrie => {
                write!(f, "BUG: MARF requested the identifier for a RAM trie")
            }
        }
    }
}

impl error::Error for Error {
    fn cause(&self) -> Option<&dyn error::Error> {
        match *self {
            Error::IOError(ref e) => Some(e),
            Error::SQLError(ref e) => Some(e),
            Error::RestoreMarfBlockError(ref e) => Some(e),
            Error::BlockHashMapCorruptionError(Some(ref e)) => Some(e),
            _ => None,
        }
    }
}

pub trait BlockMap {
    type TrieId: MarfTrieId;
    fn get_block_hash(&self, id: u32) -> Result<Self::TrieId, Error>;
    fn get_block_hash_caching(&mut self, id: u32) -> Result<&Self::TrieId, Error>;
    fn is_block_hash_cached(&self, id: u32) -> bool;
    fn get_block_id(&self, bhh: &Self::TrieId) -> Result<u32, Error>;
    fn get_block_id_caching(&mut self, bhh: &Self::TrieId) -> Result<u32, Error>;
}

#[cfg(test)]
impl BlockMap for () {
    type TrieId = BlockHeaderHash;
    fn get_block_hash(&self, _id: u32) -> Result<BlockHeaderHash, Error> {
        Err(Error::NotFoundError)
    }
    fn get_block_hash_caching(&mut self, _id: u32) -> Result<&BlockHeaderHash, Error> {
        Err(Error::NotFoundError)
    }
    fn is_block_hash_cached(&self, _id: u32) -> bool {
        false
    }
    fn get_block_id(&self, _bhh: &BlockHeaderHash) -> Result<u32, Error> {
        Err(Error::NotFoundError)
    }
    fn get_block_id_caching(&mut self, _bhh: &BlockHeaderHash) -> Result<u32, Error> {
        Err(Error::NotFoundError)
    }
}
