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

use std::collections::BTreeMap;

use hashbrown::{HashMap, HashSet};

use crate::vm::analysis::errors::{CheckError, CheckErrors, CheckResult};
use crate::vm::analysis::type_checker::is_reserved_word;
use crate::vm::analysis::types::ContractAnalysis;
use crate::vm::representations::ClarityName;
use crate::vm::types::signatures::FunctionSignature;
use crate::vm::types::{FunctionType, QualifiedContractIdentifier, TraitIdentifier, TypeSignature};
use crate::vm::ClarityVersion;

enum TraitContext {
    /// Traits stored in this context use the trait type-checking behavior defined in Clarity1
    Clarity1(HashMap<ClarityName, BTreeMap<ClarityName, FunctionSignature>>),
    /// Traits stored in this context use the new trait type-checking behavior defined in Clarity2
    Clarity2 {
        /// Aliases for locally defined traits and traits imported with `use-trait`
        defined: HashSet<ClarityName>,
        /// All traits which are defined or used in a contract
        all: HashMap<TraitIdentifier, BTreeMap<ClarityName, FunctionSignature>>,
    },
}

impl TraitContext {
    pub fn new(clarity_version: ClarityVersion) -> TraitContext {
        match clarity_version {
            ClarityVersion::Clarity1 => Self::Clarity1(HashMap::new()),
            ClarityVersion::Clarity2 | ClarityVersion::Clarity3 => Self::Clarity2 {
                defined: HashSet::new(),
                all: HashMap::new(),
            },
        }
    }

    pub fn is_name_used(&self, name: &str) -> bool {
        match self {
            Self::Clarity1(map) => map.contains_key(name),
            Self::Clarity2 { defined, all: _ } => defined.contains(name),
        }
    }

    pub fn add_defined_trait(
        &mut self,
        contract_identifier: QualifiedContractIdentifier,
        trait_name: ClarityName,
        trait_signature: BTreeMap<ClarityName, FunctionSignature>,
    ) -> CheckResult<()> {
        match self {
            Self::Clarity1(map) => {
                map.insert(trait_name, trait_signature);
            }
            Self::Clarity2 { defined, all } => {
                defined.insert(trait_name.clone());
                all.insert(
                    TraitIdentifier {
                        name: trait_name,
                        contract_identifier,
                    },
                    trait_signature,
                );
            }
        }
        Ok(())
    }

    pub fn add_used_trait(
        &mut self,
        alias: ClarityName,
        trait_id: TraitIdentifier,
        trait_signature: BTreeMap<ClarityName, FunctionSignature>,
    ) -> CheckResult<()> {
        match self {
            Self::Clarity1(map) => {
                map.insert(trait_id.name, trait_signature);
            }
            Self::Clarity2 { defined, all } => {
                defined.insert(alias);
                all.insert(trait_id, trait_signature);
            }
        }
        Ok(())
    }

    pub fn get_trait(
        &self,
        trait_id: &TraitIdentifier,
    ) -> Option<&BTreeMap<ClarityName, FunctionSignature>> {
        match self {
            Self::Clarity1(map) => map.get(&trait_id.name),
            Self::Clarity2 { defined: _, all } => all.get(trait_id),
        }
    }

    #[allow(clippy::wrong_self_convention)]
    pub fn into_contract_analysis(&mut self, contract_analysis: &mut ContractAnalysis) {
        match self {
            Self::Clarity1(map) => {
                for (name, trait_signature) in map.drain() {
                    contract_analysis.add_defined_trait(name, trait_signature);
                }
            }
            Self::Clarity2 { defined: _, all } => {
                for (trait_id, trait_signature) in all.drain() {
                    if trait_id.contract_identifier == contract_analysis.contract_identifier {
                        contract_analysis.add_defined_trait(trait_id.name, trait_signature);
                    }
                }
            }
        }
    }
}

pub struct ContractContext {
    clarity_version: ClarityVersion,
    contract_identifier: QualifiedContractIdentifier,
    map_types: HashMap<ClarityName, (TypeSignature, TypeSignature)>,
    variable_types: HashMap<ClarityName, TypeSignature>,
    private_function_types: HashMap<ClarityName, FunctionType>,
    public_function_types: HashMap<ClarityName, FunctionType>,
    read_only_function_types: HashMap<ClarityName, FunctionType>,
    persisted_variable_types: HashMap<ClarityName, TypeSignature>,
    fungible_tokens: HashSet<ClarityName>,
    non_fungible_tokens: HashMap<ClarityName, TypeSignature>,
    traits: TraitContext,
    pub implemented_traits: HashSet<TraitIdentifier>,
}

impl ContractContext {
    pub fn new(
        contract_identifier: QualifiedContractIdentifier,
        clarity_version: ClarityVersion,
    ) -> ContractContext {
        ContractContext {
            clarity_version,
            contract_identifier,
            variable_types: HashMap::new(),
            private_function_types: HashMap::new(),
            public_function_types: HashMap::new(),
            read_only_function_types: HashMap::new(),
            map_types: HashMap::new(),
            persisted_variable_types: HashMap::new(),
            fungible_tokens: HashSet::new(),
            non_fungible_tokens: HashMap::new(),
            traits: TraitContext::new(clarity_version),
            implemented_traits: HashSet::new(),
        }
    }

    /// Checks if the contract represented by this `ContractContext` is the
    /// same contract referenced by `other`
    pub fn is_contract(&self, other: &QualifiedContractIdentifier) -> bool {
        &self.contract_identifier == other
    }

    pub fn check_name_used(&self, name: &str) -> CheckResult<()> {
        if is_reserved_word(name, self.clarity_version) {
            return Err(CheckError::new(CheckErrors::ReservedWord(name.to_string())));
        }

        if self.variable_types.contains_key(name)
            || self.persisted_variable_types.contains_key(name)
            || self.private_function_types.contains_key(name)
            || self.public_function_types.contains_key(name)
            || self.fungible_tokens.contains(name)
            || self.non_fungible_tokens.contains_key(name)
            || self.traits.is_name_used(name)
            || self.map_types.contains_key(name)
        {
            Err(CheckError::new(CheckErrors::NameAlreadyUsed(
                name.to_string(),
            )))
        } else {
            Ok(())
        }
    }

    fn check_function_type(&mut self, f_name: &str) -> CheckResult<()> {
        self.check_name_used(f_name)?;
        Ok(())
    }

    pub fn ft_exists(&self, name: &str) -> bool {
        self.fungible_tokens.contains(name)
    }

    pub fn get_nft_type(&self, name: &str) -> Option<&TypeSignature> {
        self.non_fungible_tokens.get(name)
    }

    pub fn add_public_function_type(
        &mut self,
        name: ClarityName,
        func_type: FunctionType,
    ) -> CheckResult<()> {
        self.check_function_type(&name)?;
        self.public_function_types.insert(name, func_type);
        Ok(())
    }

    pub fn add_read_only_function_type(
        &mut self,
        name: ClarityName,
        func_type: FunctionType,
    ) -> CheckResult<()> {
        self.check_function_type(&name)?;
        self.read_only_function_types.insert(name, func_type);
        Ok(())
    }

    pub fn add_private_function_type(
        &mut self,
        name: ClarityName,
        func_type: FunctionType,
    ) -> CheckResult<()> {
        self.check_function_type(&name)?;
        self.private_function_types.insert(name, func_type);
        Ok(())
    }

    pub fn add_map_type(
        &mut self,
        map_name: ClarityName,
        map_type: (TypeSignature, TypeSignature),
    ) -> CheckResult<()> {
        self.check_name_used(&map_name)?;
        self.map_types.insert(map_name, map_type);
        Ok(())
    }

    pub fn add_variable_type(
        &mut self,
        const_name: ClarityName,
        var_type: TypeSignature,
    ) -> CheckResult<()> {
        self.check_name_used(&const_name)?;
        self.variable_types.insert(const_name, var_type);
        Ok(())
    }

    pub fn add_persisted_variable_type(
        &mut self,
        var_name: ClarityName,
        var_type: TypeSignature,
    ) -> CheckResult<()> {
        self.check_name_used(&var_name)?;
        self.persisted_variable_types.insert(var_name, var_type);
        Ok(())
    }

    pub fn add_ft(&mut self, token_name: ClarityName) -> CheckResult<()> {
        self.check_name_used(&token_name)?;
        self.fungible_tokens.insert(token_name);
        Ok(())
    }

    pub fn add_nft(
        &mut self,
        token_name: ClarityName,
        token_type: TypeSignature,
    ) -> CheckResult<()> {
        self.check_name_used(&token_name)?;
        self.non_fungible_tokens.insert(token_name, token_type);
        Ok(())
    }

    pub fn add_defined_trait(
        &mut self,
        trait_name: ClarityName,
        trait_signature: BTreeMap<ClarityName, FunctionSignature>,
    ) -> CheckResult<()> {
        if self.clarity_version >= ClarityVersion::Clarity3 {
            self.check_name_used(&trait_name)?;
        }

        self.traits.add_defined_trait(
            self.contract_identifier.clone(),
            trait_name,
            trait_signature,
        )
    }

    pub fn add_used_trait(
        &mut self,
        alias: ClarityName,
        trait_id: TraitIdentifier,
        trait_signature: BTreeMap<ClarityName, FunctionSignature>,
    ) -> CheckResult<()> {
        if self.clarity_version >= ClarityVersion::Clarity3 {
            self.check_name_used(&alias)?;
        }

        self.traits.add_used_trait(alias, trait_id, trait_signature)
    }

    pub fn add_implemented_trait(&mut self, trait_identifier: TraitIdentifier) -> CheckResult<()> {
        self.implemented_traits.insert(trait_identifier);
        Ok(())
    }

    pub fn get_trait(
        &self,
        trait_id: &TraitIdentifier,
    ) -> Option<&BTreeMap<ClarityName, FunctionSignature>> {
        self.traits.get_trait(trait_id)
    }

    pub fn get_map_type(&self, map_name: &str) -> Option<&(TypeSignature, TypeSignature)> {
        self.map_types.get(map_name)
    }

    pub fn get_variable_type(&self, name: &str) -> Option<&TypeSignature> {
        self.variable_types.get(name)
    }

    pub fn get_persisted_variable_type(&self, name: &str) -> Option<&TypeSignature> {
        self.persisted_variable_types.get(name)
    }

    pub fn get_function_type(&self, name: &str) -> Option<&FunctionType> {
        if let Some(f_type) = self.public_function_types.get(name) {
            Some(f_type)
        } else if let Some(f_type) = self.private_function_types.get(name) {
            Some(f_type)
        } else {
            self.read_only_function_types.get(name)
        }
    }

    /// This function consumes the ContractContext, and puts the relevant information
    ///  into the provided ContractAnalysis
    pub fn into_contract_analysis(mut self, contract_analysis: &mut ContractAnalysis) {
        for (name, function_type) in self.public_function_types.drain() {
            contract_analysis.add_public_function(name, function_type);
        }

        for (name, function_type) in self.read_only_function_types.drain() {
            contract_analysis.add_read_only_function(name, function_type);
        }

        for (name, (key_type, map_type)) in self.map_types.drain() {
            contract_analysis.add_map_type(name, key_type, map_type);
        }

        for (name, function_type) in self.private_function_types.drain() {
            contract_analysis.add_private_function(name, function_type);
        }

        for (name, variable_type) in self.variable_types.drain() {
            contract_analysis.add_variable_type(name, variable_type);
        }

        for (name, persisted_variable_type) in self.persisted_variable_types.drain() {
            contract_analysis.add_persisted_variable_type(name, persisted_variable_type);
        }

        for name in self.fungible_tokens.drain() {
            contract_analysis.add_fungible_token(name);
        }

        for (name, nft_type) in self.non_fungible_tokens.drain() {
            contract_analysis.add_non_fungible_token(name, nft_type);
        }

        self.traits.into_contract_analysis(contract_analysis);

        for trait_identifier in self.implemented_traits.drain() {
            contract_analysis.add_implemented_trait(trait_identifier);
        }
    }
}
