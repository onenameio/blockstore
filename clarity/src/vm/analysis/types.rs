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

use crate::vm::analysis::analysis_db::AnalysisDatabase;
use crate::vm::analysis::contract_interface_builder::ContractInterface;
use crate::vm::analysis::errors::{CheckErrors, CheckResult};
use crate::vm::analysis::type_checker::contexts::TypeMap;
use crate::vm::costs::LimitedCostTracker;
use crate::vm::types::signatures::FunctionSignature;
use crate::vm::types::{FunctionType, QualifiedContractIdentifier, TraitIdentifier, TypeSignature};
use crate::vm::{ClarityName, ClarityVersion, SymbolicExpression};

const DESERIALIZE_FAIL_MESSAGE: &str =
    "PANIC: Failed to deserialize bad database data in contract analysis.";
const SERIALIZE_FAIL_MESSAGE: &str =
    "PANIC: Failed to deserialize bad database data in contract analysis.";

pub trait AnalysisPass {
    fn run_pass(
        epoch: &StacksEpochId,
        contract_analysis: &mut ContractAnalysis,
        analysis_db: &mut AnalysisDatabase,
    ) -> CheckResult<()>;
}

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq)]
pub struct ContractAnalysis {
    pub contract_identifier: QualifiedContractIdentifier,
    pub private_function_types: BTreeMap<ClarityName, FunctionType>,
    pub variable_types: BTreeMap<ClarityName, TypeSignature>,
    pub public_function_types: BTreeMap<ClarityName, FunctionType>,
    pub read_only_function_types: BTreeMap<ClarityName, FunctionType>,
    pub map_types: BTreeMap<ClarityName, (TypeSignature, TypeSignature)>,
    pub persisted_variable_types: BTreeMap<ClarityName, TypeSignature>,
    pub fungible_tokens: BTreeSet<ClarityName>,
    pub non_fungible_tokens: BTreeMap<ClarityName, TypeSignature>,
    pub defined_traits: BTreeMap<ClarityName, BTreeMap<ClarityName, FunctionSignature>>,
    pub implemented_traits: BTreeSet<TraitIdentifier>,
    pub contract_interface: Option<ContractInterface>,
    pub is_cost_contract_eligible: bool,
    pub epoch: StacksEpochId,
    pub clarity_version: ClarityVersion,
    #[serde(skip)]
    pub expressions: Vec<SymbolicExpression>,
    #[serde(skip)]
    pub type_map: Option<TypeMap>,
    #[serde(skip)]
    pub cost_track: Option<LimitedCostTracker>,
}

impl ContractAnalysis {
    pub fn new(
        contract_identifier: QualifiedContractIdentifier,
        expressions: Vec<SymbolicExpression>,
        cost_track: LimitedCostTracker,
        epoch: StacksEpochId,
        clarity_version: ClarityVersion,
    ) -> ContractAnalysis {
        ContractAnalysis {
            contract_identifier,
            expressions,
            type_map: None,
            contract_interface: None,
            private_function_types: BTreeMap::new(),
            public_function_types: BTreeMap::new(),
            read_only_function_types: BTreeMap::new(),
            variable_types: BTreeMap::new(),
            map_types: BTreeMap::new(),
            persisted_variable_types: BTreeMap::new(),
            defined_traits: BTreeMap::new(),
            implemented_traits: BTreeSet::new(),
            fungible_tokens: BTreeSet::new(),
            non_fungible_tokens: BTreeMap::new(),
            cost_track: Some(cost_track),
            is_cost_contract_eligible: false,
            epoch,
            clarity_version,
        }
    }

    #[allow(clippy::expect_used)]
    pub fn take_contract_cost_tracker(&mut self) -> LimitedCostTracker {
        self.cost_track
            .take()
            .expect("BUG: contract analysis attempted to take a cost tracker already claimed.")
    }

    pub fn replace_contract_cost_tracker(&mut self, cost_track: LimitedCostTracker) {
        assert!(self.cost_track.is_none());
        self.cost_track.replace(cost_track);
    }

    pub fn add_map_type(
        &mut self,
        name: ClarityName,
        key_type: TypeSignature,
        map_type: TypeSignature,
    ) {
        self.map_types.insert(name, (key_type, map_type));
    }

    pub fn add_variable_type(&mut self, name: ClarityName, variable_type: TypeSignature) {
        self.variable_types.insert(name, variable_type);
    }

    pub fn add_persisted_variable_type(
        &mut self,
        name: ClarityName,
        persisted_variable_type: TypeSignature,
    ) {
        self.persisted_variable_types
            .insert(name, persisted_variable_type);
    }

    pub fn add_read_only_function(&mut self, name: ClarityName, function_type: FunctionType) {
        self.read_only_function_types.insert(name, function_type);
    }

    pub fn add_public_function(&mut self, name: ClarityName, function_type: FunctionType) {
        self.public_function_types.insert(name, function_type);
    }

    pub fn add_private_function(&mut self, name: ClarityName, function_type: FunctionType) {
        self.private_function_types.insert(name, function_type);
    }

    pub fn add_non_fungible_token(&mut self, name: ClarityName, nft_type: TypeSignature) {
        self.non_fungible_tokens.insert(name, nft_type);
    }

    pub fn add_fungible_token(&mut self, name: ClarityName) {
        self.fungible_tokens.insert(name);
    }

    pub fn add_defined_trait(
        &mut self,
        name: ClarityName,
        function_types: BTreeMap<ClarityName, FunctionSignature>,
    ) {
        self.defined_traits.insert(name, function_types);
    }

    pub fn add_implemented_trait(&mut self, trait_identifier: TraitIdentifier) {
        self.implemented_traits.insert(trait_identifier);
    }

    pub fn get_public_function_type(&self, name: &str) -> Option<&FunctionType> {
        self.public_function_types.get(name)
    }

    pub fn get_read_only_function_type(&self, name: &str) -> Option<&FunctionType> {
        self.read_only_function_types.get(name)
    }

    pub fn get_private_function(&self, name: &str) -> Option<&FunctionType> {
        self.private_function_types.get(name)
    }

    pub fn get_map_type(&self, name: &str) -> Option<&(TypeSignature, TypeSignature)> {
        self.map_types.get(name)
    }

    pub fn get_variable_type(&self, name: &str) -> Option<&TypeSignature> {
        self.variable_types.get(name)
    }

    pub fn get_persisted_variable_type(&self, name: &str) -> Option<&TypeSignature> {
        self.persisted_variable_types.get(name)
    }

    pub fn get_defined_trait(
        &self,
        name: &str,
    ) -> Option<&BTreeMap<ClarityName, FunctionSignature>> {
        self.defined_traits.get(name)
    }

    /// Canonicalize all types in the contract analysis.
    pub fn canonicalize_types(&mut self, epoch: &StacksEpochId) {
        for (_, function_type) in self.private_function_types.iter_mut() {
            *function_type = function_type.canonicalize(epoch);
        }
        for (_, variable_type) in self.variable_types.iter_mut() {
            *variable_type = variable_type.canonicalize(epoch);
        }
        for (_, function_type) in self.public_function_types.iter_mut() {
            *function_type = function_type.canonicalize(epoch);
        }
        for (_, function_type) in self.read_only_function_types.iter_mut() {
            *function_type = function_type.canonicalize(epoch);
        }
        for (_, (key_type, value_type)) in self.map_types.iter_mut() {
            *key_type = key_type.canonicalize(epoch);
            *value_type = value_type.canonicalize(epoch);
        }
        for (_, var_type) in self.persisted_variable_types.iter_mut() {
            *var_type = var_type.canonicalize(epoch);
        }
        for (_, nft_type) in self.non_fungible_tokens.iter_mut() {
            *nft_type = nft_type.canonicalize(epoch);
        }
        for (_, trait_definition) in self.defined_traits.iter_mut() {
            for (_, function_signature) in trait_definition.iter_mut() {
                *function_signature = function_signature.canonicalize(epoch);
            }
        }
    }

    pub fn check_trait_compliance(
        &self,
        epoch: &StacksEpochId,
        trait_identifier: &TraitIdentifier,
        trait_definition: &BTreeMap<ClarityName, FunctionSignature>,
    ) -> CheckResult<()> {
        let trait_name = trait_identifier.name.to_string();

        for (func_name, expected_sig) in trait_definition.iter() {
            match (
                self.get_public_function_type(func_name),
                self.get_read_only_function_type(func_name),
            ) {
                (Some(FunctionType::Fixed(func)), None)
                | (None, Some(FunctionType::Fixed(func))) => {
                    let args_sig = func.args.iter().map(|a| a.signature.clone()).collect();
                    if !expected_sig.check_args_trait_compliance(epoch, args_sig)? {
                        return Err(CheckErrors::BadTraitImplementation(
                            trait_name,
                            func_name.to_string(),
                        )
                        .into());
                    }

                    if !expected_sig.returns.admits_type(epoch, &func.returns)? {
                        return Err(CheckErrors::BadTraitImplementation(
                            trait_name,
                            func_name.to_string(),
                        )
                        .into());
                    }
                }
                (_, _) => {
                    return Err(CheckErrors::BadTraitImplementation(
                        trait_name,
                        func_name.to_string(),
                    )
                    .into())
                }
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::vm::analysis::ContractAnalysis;
    use crate::vm::costs::LimitedCostTracker;
    use crate::vm::types::signatures::CallableSubtype;
    use crate::vm::types::{
        FixedFunction, FunctionArg, QualifiedContractIdentifier, StandardPrincipalData,
    };

    #[test]
    fn test_canonicalize_contract_analysis() {
        let mut contract_analysis = ContractAnalysis::new(
            QualifiedContractIdentifier::local("foo").unwrap(),
            vec![],
            LimitedCostTracker::new_free(),
            StacksEpochId::Epoch20,
            ClarityVersion::Clarity1,
        );
        let trait_id = TraitIdentifier::new(
            StandardPrincipalData::transient(),
            "my-contract".into(),
            "my-trait".into(),
        );
        let mut trait_functions = BTreeMap::new();
        trait_functions.insert(
            "alpha".into(),
            FunctionSignature {
                args: vec![TypeSignature::TraitReferenceType(trait_id.clone())],
                returns: TypeSignature::ResponseType(Box::new((
                    TypeSignature::UIntType,
                    TypeSignature::UIntType,
                ))),
            },
        );
        contract_analysis.add_defined_trait("foo".into(), trait_functions);

        contract_analysis.add_public_function(
            "bar".into(),
            FunctionType::Fixed(FixedFunction {
                args: vec![FunctionArg {
                    signature: TypeSignature::TraitReferenceType(trait_id.clone()),
                    name: "t".into(),
                }],
                returns: TypeSignature::new_response(
                    TypeSignature::BoolType,
                    TypeSignature::UIntType,
                )
                .unwrap(),
            }),
        );

        contract_analysis.add_read_only_function(
            "baz".into(),
            FunctionType::Fixed(FixedFunction {
                args: vec![
                    FunctionArg {
                        signature: TypeSignature::UIntType,
                        name: "u".into(),
                    },
                    FunctionArg {
                        signature: TypeSignature::TraitReferenceType(trait_id.clone()),
                        name: "t".into(),
                    },
                ],
                returns: TypeSignature::BoolType,
            }),
        );

        contract_analysis.canonicalize_types(&StacksEpochId::Epoch21);

        let trait_type = contract_analysis
            .get_defined_trait("foo")
            .unwrap()
            .get("alpha")
            .unwrap();
        assert_eq!(
            trait_type.args[0],
            TypeSignature::CallableType(CallableSubtype::Trait(trait_id.clone()))
        );

        if let FunctionType::Fixed(fixed) =
            contract_analysis.get_public_function_type("bar").unwrap()
        {
            assert_eq!(
                fixed.args[0].signature,
                TypeSignature::CallableType(CallableSubtype::Trait(trait_id.clone()))
            );
        } else {
            panic!("Expected fixed function type");
        }

        if let FunctionType::Fixed(fixed) = contract_analysis
            .get_read_only_function_type("baz")
            .unwrap()
        {
            assert_eq!(
                fixed.args[1].signature,
                TypeSignature::CallableType(CallableSubtype::Trait(trait_id))
            );
        } else {
            panic!("Expected fixed function type");
        }
    }
}
