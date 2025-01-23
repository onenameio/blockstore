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

#[cfg(feature = "canonical")]
use rusqlite::Connection;
use stacks_common::types::chainstate::{StacksBlockId, TrieHash};
use stacks_common::util::hash::{hex_bytes, to_hex, Sha512Trunc256Sum};

use crate::vm::analysis::AnalysisDatabase;
use crate::vm::contexts::GlobalContext;
#[cfg(feature = "canonical")]
use crate::vm::database::{
    ClarityDatabase, ClarityDeserializable, ClaritySerializable, NULL_BURN_STATE_DB, NULL_HEADER_DB,
};
use crate::vm::errors::{InterpreterError, InterpreterResult as Result};
use crate::vm::types::{PrincipalData, QualifiedContractIdentifier};
use crate::vm::Value;

pub struct NullBackingStore {}

pub type SpecialCaseHandler = &'static dyn Fn(
    // the current Clarity global context
    &mut GlobalContext,
    // the current sender
    Option<&PrincipalData>,
    // the current sponsor
    Option<&PrincipalData>,
    // the invoked contract
    &QualifiedContractIdentifier,
    // the invoked function name
    &str,
    // the function parameters
    &[Value],
    // the result of the function call
    &Value,
) -> Result<()>;

// These functions generally _do not_ return errors, rather, any errors in the underlying storage
//    will _panic_. The rationale for this is that under no condition should the interpreter
//    attempt to continue processing in the event of an unexpected storage error.
pub trait ClarityBackingStore {
    /// put K-V data into the committed datastore
    fn put_all_data(&mut self, items: Vec<(String, String)>) -> Result<()>;
    /// fetch K-V out of the committed datastore
    fn get_data(&mut self, key: &str) -> Result<Option<String>>;
    /// fetch Hash(K)-V out of the commmitted datastore
    fn get_data_from_path(&mut self, hash: &TrieHash) -> Result<Option<String>>;
    /// fetch K-V out of the committed datastore, along with the byte representation
    ///  of the Merkle proof for that key-value pair
    fn get_data_with_proof(&mut self, key: &str) -> Result<Option<(String, Vec<u8>)>>;
    fn get_data_with_proof_from_path(
        &mut self,
        hash: &TrieHash,
    ) -> Result<Option<(String, Vec<u8>)>>;
    fn has_entry(&mut self, key: &str) -> Result<bool> {
        Ok(self.get_data(key)?.is_some())
    }

    /// change the current MARF context to service reads from a different chain_tip
    ///   used to implement time-shifted evaluation.
    /// returns the previous block header hash on success
    fn set_block_hash(&mut self, bhh: StacksBlockId) -> Result<StacksBlockId>;

    /// Is None if `block_height` >= the "currently" under construction Stacks block height.
    fn get_block_at_height(&mut self, height: u32) -> Option<StacksBlockId>;

    /// this function returns the current block height, as viewed by this marfed-kv structure,
    ///  i.e., it changes on time-shifted evaluation. the open_chain_tip functions always
    ///   return data about the chain tip that is currently open for writing.
    fn get_current_block_height(&mut self) -> u32;

    fn get_open_chain_tip_height(&mut self) -> u32;
    fn get_open_chain_tip(&mut self) -> StacksBlockId;

    #[cfg(feature = "canonical")]
    fn get_side_store(&mut self) -> &Connection;

    fn get_cc_special_cases_handler(&self) -> Option<SpecialCaseHandler> {
        None
    }

    /// The contract commitment is the hash of the contract, plus the block height in
    ///   which the contract was initialized.
    fn make_contract_commitment(&mut self, contract_hash: Sha512Trunc256Sum) -> String {
        let block_height = self.get_open_chain_tip_height();
        let cc = ContractCommitment {
            hash: contract_hash,
            block_height,
        };
        cc.serialize()
    }

    /// This function is used to obtain a committed contract hash, and the block header hash of the block
    ///   in which the contract was initialized. This data is used to store contract metadata in the side
    ///   store.
    fn get_contract_hash(
        &mut self,
        contract: &QualifiedContractIdentifier,
    ) -> Result<(StacksBlockId, Sha512Trunc256Sum)>;

    fn insert_metadata(
        &mut self,
        contract: &QualifiedContractIdentifier,
        key: &str,
        value: &str,
    ) -> Result<()>;

    fn get_metadata(
        &mut self,
        contract: &QualifiedContractIdentifier,
        key: &str,
    ) -> Result<Option<String>>;

    fn get_metadata_manual(
        &mut self,
        at_height: u32,
        contract: &QualifiedContractIdentifier,
        key: &str,
    ) -> Result<Option<String>>;

    fn put_all_metadata(
        &mut self,
        items: Vec<((QualifiedContractIdentifier, String), String)>,
    ) -> Result<()> {
        for ((contract, key), value) in items.into_iter() {
            self.insert_metadata(&contract, &key, &value)?;
        }
        Ok(())
    }
}

// TODO: Figure out where this belongs
pub fn make_contract_hash_key(contract: &QualifiedContractIdentifier) -> String {
    format!("clarity-contract::{}", contract)
}

pub struct ContractCommitment {
    pub hash: Sha512Trunc256Sum,
    pub block_height: u32,
}

impl ClaritySerializable for ContractCommitment {
    fn serialize(&self) -> String {
        format!("{}{}", self.hash, to_hex(&self.block_height.to_be_bytes()))
    }
}

impl ClarityDeserializable<ContractCommitment> for ContractCommitment {
    fn deserialize(input: &str) -> Result<ContractCommitment> {
        if input.len() != 72 {
            return Err(InterpreterError::Expect("Unexpected input length".into()).into());
        }
        let hash = Sha512Trunc256Sum::from_hex(&input[0..64])
            .map_err(|_| InterpreterError::Expect("Hex decode fail.".into()))?;
        let height_bytes = hex_bytes(&input[64..72])
            .map_err(|_| InterpreterError::Expect("Hex decode fail.".into()))?;
        let block_height = u32::from_be_bytes(
            height_bytes
                .as_slice()
                .try_into()
                .map_err(|_| InterpreterError::Expect("Block height decode fail.".into()))?,
        );
        Ok(ContractCommitment { hash, block_height })
    }
}

impl Default for NullBackingStore {
    fn default() -> Self {
        NullBackingStore::new()
    }
}

impl NullBackingStore {
    pub fn new() -> Self {
        NullBackingStore {}
    }

    pub fn as_clarity_db(&mut self) -> ClarityDatabase {
        ClarityDatabase::new(self, &NULL_HEADER_DB, &NULL_BURN_STATE_DB)
    }

    pub fn as_analysis_db(&mut self) -> AnalysisDatabase {
        AnalysisDatabase::new(self)
    }
}

#[allow(clippy::panic)]
impl ClarityBackingStore for NullBackingStore {
    fn set_block_hash(&mut self, _bhh: StacksBlockId) -> Result<StacksBlockId> {
        panic!("NullBackingStore can't set block hash")
    }

    fn get_data(&mut self, _key: &str) -> Result<Option<String>> {
        panic!("NullBackingStore can't retrieve data")
    }

    fn get_data_from_path(&mut self, _hash: &TrieHash) -> Result<Option<String>> {
        panic!("NullBackingStore can't retrieve data")
    }

    fn get_data_with_proof(&mut self, _key: &str) -> Result<Option<(String, Vec<u8>)>> {
        panic!("NullBackingStore can't retrieve data")
    }

    fn get_data_with_proof_from_path(
        &mut self,
        _hash: &TrieHash,
    ) -> Result<Option<(String, Vec<u8>)>> {
        panic!("NullBackingStore can't retrieve data")
    }

    #[cfg(feature = "canonical")]
    fn get_side_store(&mut self) -> &Connection {
        panic!("NullBackingStore has no side store")
    }

    fn get_block_at_height(&mut self, _height: u32) -> Option<StacksBlockId> {
        panic!("NullBackingStore can't get block at height")
    }

    fn get_open_chain_tip(&mut self) -> StacksBlockId {
        panic!("NullBackingStore can't open chain tip")
    }

    fn get_open_chain_tip_height(&mut self) -> u32 {
        panic!("NullBackingStore can't get open chain tip height")
    }

    fn get_current_block_height(&mut self) -> u32 {
        panic!("NullBackingStore can't get current block height")
    }

    fn put_all_data(&mut self, mut _items: Vec<(String, String)>) -> Result<()> {
        panic!("NullBackingStore cannot put")
    }

    fn get_contract_hash(
        &mut self,
        _contract: &QualifiedContractIdentifier,
    ) -> Result<(StacksBlockId, Sha512Trunc256Sum)> {
        panic!("NullBackingStore cannot get_contract_hash")
    }

    fn insert_metadata(
        &mut self,
        _contract: &QualifiedContractIdentifier,
        _key: &str,
        _value: &str,
    ) -> Result<()> {
        panic!("NullBackingStore cannot insert_metadata")
    }

    fn get_metadata(
        &mut self,
        _contract: &QualifiedContractIdentifier,
        _key: &str,
    ) -> Result<Option<String>> {
        panic!("NullBackingStore cannot get_metadata")
    }

    fn get_metadata_manual(
        &mut self,
        _at_height: u32,
        _contract: &QualifiedContractIdentifier,
        _key: &str,
    ) -> Result<Option<String>> {
        panic!("NullBackingStore cannot get_metadata_manual")
    }
}
