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

use std::collections::{BTreeMap, BTreeSet};

use stacks_common::types::StacksEpochId;

use crate::vm::analysis::errors::{CheckErrors, CheckResult};
use crate::vm::analysis::type_checker::ContractAnalysis;
use crate::vm::database::{
    ClarityBackingStore, ClarityDeserializable, ClaritySerializable, RollbackWrapper,
};
use crate::vm::representations::ClarityName;
use crate::vm::types::signatures::FunctionSignature;
use crate::vm::types::{FunctionType, QualifiedContractIdentifier, TraitIdentifier};
use crate::vm::ClarityVersion;

pub struct AnalysisDatabase<'a> {
    store: RollbackWrapper<'a>,
}

impl<'a> AnalysisDatabase<'a> {
    pub fn new(store: &'a mut dyn ClarityBackingStore) -> AnalysisDatabase<'a> {
        AnalysisDatabase {
            store: RollbackWrapper::new(store),
        }
    }
    pub fn new_with_rollback_wrapper(store: RollbackWrapper<'a>) -> AnalysisDatabase<'a> {
        AnalysisDatabase { store }
    }

    pub fn execute<F, T, E>(&mut self, f: F) -> Result<T, E>
    where
        F: FnOnce(&mut Self) -> Result<T, E>,
        E: From<CheckErrors>,
    {
        self.begin();
        let result = f(self).or_else(|e| {
            self.roll_back()
                .map_err(|e| CheckErrors::Expects(format!("{e:?}")))?;
            Err(e)
        })?;
        self.commit()
            .map_err(|e| CheckErrors::Expects(format!("{e:?}")))?;
        Ok(result)
    }

    pub fn begin(&mut self) {
        self.store.nest();
    }

    pub fn commit(&mut self) -> CheckResult<()> {
        self.store
            .commit()
            .map_err(|e| CheckErrors::Expects(format!("{e:?}")).into())
    }

    pub fn roll_back(&mut self) -> CheckResult<()> {
        self.store
            .rollback()
            .map_err(|e| CheckErrors::Expects(format!("{e:?}")).into())
    }

    pub fn storage_key() -> &'static str {
        "analysis"
    }

    // used by tests to ensure that
    //   the contract -> contract hash key exists in the marf
    //    even if the contract isn't published.
    #[cfg(test)]
    pub fn test_insert_contract_hash(&mut self, contract_identifier: &QualifiedContractIdentifier) {
        use stacks_common::util::hash::Sha512Trunc256Sum;
        self.store
            .prepare_for_contract_metadata(contract_identifier, Sha512Trunc256Sum([0; 32]))
            .unwrap();
    }

    pub fn has_contract(&mut self, contract_identifier: &QualifiedContractIdentifier) -> bool {
        self.store
            .has_metadata_entry(contract_identifier, AnalysisDatabase::storage_key())
    }

    /// Load a contract from the database, without canonicalizing its types.
    pub fn load_contract_non_canonical(
        &mut self,
        contract_identifier: &QualifiedContractIdentifier,
    ) -> CheckResult<Option<ContractAnalysis>> {
        self.store
            .get_metadata(contract_identifier, AnalysisDatabase::storage_key())
            // treat NoSuchContract error thrown by get_metadata as an Option::None --
            //    the analysis will propagate that as a CheckError anyways.
            .ok()
            .flatten()
            .map(|x| {
                ContractAnalysis::deserialize(&x).map_err(|_| {
                    CheckErrors::Expects("Bad data deserialized from DB".into()).into()
                })
            })
            .transpose()
    }

    pub fn load_contract(
        &mut self,
        contract_identifier: &QualifiedContractIdentifier,
        epoch: &StacksEpochId,
    ) -> CheckResult<Option<ContractAnalysis>> {
        Ok(self
            .store
            .get_metadata(contract_identifier, AnalysisDatabase::storage_key())
            // treat NoSuchContract error thrown by get_metadata as an Option::None --
            //    the analysis will propagate that as a CheckError anyways.
            .ok()
            .flatten()
            .map(|x| {
                ContractAnalysis::deserialize(&x)
                    .map_err(|_| CheckErrors::Expects("Bad data deserialized from DB".into()))
            })
            .transpose()?
            .map(|mut x| {
                x.canonicalize_types(epoch);
                x
            }))
    }

    pub fn insert_contract(
        &mut self,
        contract_identifier: &QualifiedContractIdentifier,
        contract: &ContractAnalysis,
    ) -> CheckResult<()> {
        let key = AnalysisDatabase::storage_key();
        if self.store.has_metadata_entry(contract_identifier, key) {
            return Err(CheckErrors::ContractAlreadyExists(contract_identifier.to_string()).into());
        }

        self.store
            .insert_metadata(contract_identifier, key, &contract.serialize())
            .map_err(|e| CheckErrors::Expects(format!("{e:?}")))?;
        Ok(())
    }

    pub fn get_clarity_version(
        &mut self,
        contract_identifier: &QualifiedContractIdentifier,
    ) -> CheckResult<ClarityVersion> {
        // TODO: this function loads the whole contract to obtain the function type.
        //         but it doesn't need to -- rather this information can just be
        //         stored as its own entry. the analysis cost tracking currently only
        //         charges based on the function type size.
        let contract = self
            .load_contract_non_canonical(contract_identifier)?
            .ok_or(CheckErrors::NoSuchContract(contract_identifier.to_string()))?;
        Ok(contract.clarity_version)
    }

    pub fn get_public_function_type(
        &mut self,
        contract_identifier: &QualifiedContractIdentifier,
        function_name: &str,
        epoch: &StacksEpochId,
    ) -> CheckResult<Option<FunctionType>> {
        // TODO: this function loads the whole contract to obtain the function type.
        //         but it doesn't need to -- rather this information can just be
        //         stored as its own entry. the analysis cost tracking currently only
        //         charges based on the function type size.
        let contract = self
            .load_contract_non_canonical(contract_identifier)?
            .ok_or(CheckErrors::NoSuchContract(contract_identifier.to_string()))?;
        Ok(contract
            .get_public_function_type(function_name)
            .map(|x| x.canonicalize(epoch)))
    }

    pub fn get_read_only_function_type(
        &mut self,
        contract_identifier: &QualifiedContractIdentifier,
        function_name: &str,
        epoch: &StacksEpochId,
    ) -> CheckResult<Option<FunctionType>> {
        // TODO: this function loads the whole contract to obtain the function type.
        //         but it doesn't need to -- rather this information can just be
        //         stored as its own entry. the analysis cost tracking currently only
        //         charges based on the function type size.
        let contract = self
            .load_contract_non_canonical(contract_identifier)?
            .ok_or(CheckErrors::NoSuchContract(contract_identifier.to_string()))?;
        Ok(contract
            .get_read_only_function_type(function_name)
            .map(|x| x.canonicalize(epoch)))
    }

    pub fn get_defined_trait(
        &mut self,
        contract_identifier: &QualifiedContractIdentifier,
        trait_name: &str,
        epoch: &StacksEpochId,
    ) -> CheckResult<Option<BTreeMap<ClarityName, FunctionSignature>>> {
        // TODO: this function loads the whole contract to obtain the function type.
        //         but it doesn't need to -- rather this information can just be
        //         stored as its own entry. the analysis cost tracking currently only
        //         charges based on the function type size.
        let contract = self
            .load_contract_non_canonical(contract_identifier)?
            .ok_or(CheckErrors::NoSuchContract(contract_identifier.to_string()))?;
        Ok(contract.get_defined_trait(trait_name).map(|trait_map| {
            trait_map
                .iter()
                .map(|(name, sig)| (name.clone(), sig.canonicalize(epoch)))
                .collect()
        }))
    }

    pub fn get_implemented_traits(
        &mut self,
        contract_identifier: &QualifiedContractIdentifier,
    ) -> CheckResult<BTreeSet<TraitIdentifier>> {
        let contract = self
            .load_contract_non_canonical(contract_identifier)?
            .ok_or(CheckErrors::NoSuchContract(contract_identifier.to_string()))?;
        Ok(contract.implemented_traits)
    }

    pub fn destroy(self) -> RollbackWrapper<'a> {
        self.store
    }
}
