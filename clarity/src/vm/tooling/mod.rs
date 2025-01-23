use stacks_common::types::StacksEpochId;

use super::analysis::ContractAnalysis;
use super::types::TypeSignature;
use super::ClarityVersion;
use crate::vm::analysis::{run_analysis, CheckResult};
use crate::vm::ast::{build_ast_with_rules, ASTRules};
use crate::vm::costs::LimitedCostTracker;
use crate::vm::database::MemoryBackingStore;
use crate::vm::types::QualifiedContractIdentifier;

/// Used by CLI tools like the docs generator. Not used in production
pub fn mem_type_check(
    snippet: &str,
    version: ClarityVersion,
    epoch: StacksEpochId,
) -> CheckResult<(Option<TypeSignature>, ContractAnalysis)> {
    let contract_identifier = QualifiedContractIdentifier::transient();
    let contract = build_ast_with_rules(
        &contract_identifier,
        snippet,
        &mut (),
        version,
        epoch,
        ASTRules::PrecheckSize,
    )
    .unwrap()
    .expressions;

    let mut marf = MemoryBackingStore::new();
    let mut analysis_db = marf.as_analysis_db();
    let cost_tracker = LimitedCostTracker::new_free();
    match run_analysis(
        &QualifiedContractIdentifier::transient(),
        &contract,
        &mut analysis_db,
        false,
        cost_tracker,
        epoch,
        version,
        true,
    ) {
        Ok(x) => {
            // return the first type result of the type checker
            let first_type = x
                .type_map
                .as_ref()
                .unwrap()
                .get_type_expected(x.expressions.last().unwrap())
                .cloned();
            Ok((first_type, x))
        }
        Err((e, _)) => Err(e),
    }
}
