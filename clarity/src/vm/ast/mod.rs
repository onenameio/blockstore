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

pub mod definition_sorter;
pub mod expression_identifier;
pub mod parser;
pub mod traits_resolver;

pub mod errors;
pub mod stack_depth_checker;
pub mod sugar_expander;
pub mod types;
use stacks_common::types::StacksEpochId;

use self::definition_sorter::DefinitionSorter;
use self::errors::ParseResult;
use self::expression_identifier::ExpressionIdentifier;
use self::parser::v1::{parse as parse_v1, parse_no_stack_limit as parse_v1_no_stack_limit};
use self::parser::v2::parse as parse_v2;
use self::stack_depth_checker::{StackDepthChecker, VaryStackDepthChecker};
use self::sugar_expander::SugarExpander;
use self::traits_resolver::TraitsResolver;
use self::types::BuildASTPass;
pub use self::types::ContractAST;
use crate::vm::costs::cost_functions::ClarityCostFunction;
use crate::vm::costs::{runtime_cost, CostTracker};
use crate::vm::diagnostic::{Diagnostic, Level};
use crate::vm::representations::PreSymbolicExpression;
use crate::vm::types::QualifiedContractIdentifier;
use crate::vm::ClarityVersion;

/// Legacy function
#[cfg(any(test, feature = "testing"))]
pub fn parse(
    contract_identifier: &QualifiedContractIdentifier,
    source_code: &str,
    version: ClarityVersion,
    epoch: StacksEpochId,
) -> Result<Vec<crate::vm::representations::SymbolicExpression>, crate::vm::errors::Error> {
    let ast = build_ast(contract_identifier, source_code, &mut (), version, epoch)?;
    Ok(ast.expressions)
}

// AST parser rulesets to apply.
define_u8_enum!(ASTRules {
    Typical = 0,
    PrecheckSize = 1
});

/// Parse a program based on which epoch is active
fn parse_in_epoch(
    source_code: &str,
    epoch_id: StacksEpochId,
    ast_rules: ASTRules,
) -> ParseResult<Vec<PreSymbolicExpression>> {
    if epoch_id >= StacksEpochId::Epoch21 {
        parse_v2(source_code)
    } else if ast_rules == ASTRules::Typical {
        parse_v1_no_stack_limit(source_code)
    } else {
        parse_v1(source_code)
    }
}

/// This is the part of the AST parser that runs without respect to cost analysis, specifically
/// pertaining to verifying that the AST is reasonably-sized.
/// Used mainly to filter transactions that might be too costly, as an optimization heuristic.
pub fn ast_check_size(
    contract_identifier: &QualifiedContractIdentifier,
    source_code: &str,
    clarity_version: ClarityVersion,
    epoch_id: StacksEpochId,
) -> ParseResult<ContractAST> {
    let pre_expressions = parse_in_epoch(source_code, epoch_id, ASTRules::PrecheckSize)?;
    let mut contract_ast = ContractAST::new(contract_identifier.clone(), pre_expressions);
    StackDepthChecker::run_pass(&mut contract_ast, clarity_version)?;
    VaryStackDepthChecker::run_pass(&mut contract_ast, clarity_version)?;
    Ok(contract_ast)
}

/// Build an AST according to a ruleset
pub fn build_ast_with_rules<T: CostTracker>(
    contract_identifier: &QualifiedContractIdentifier,
    source_code: &str,
    cost_track: &mut T,
    clarity_version: ClarityVersion,
    epoch: StacksEpochId,
    ruleset: ASTRules,
) -> ParseResult<ContractAST> {
    match ruleset {
        // After epoch 2.1, prechecking the size is required
        ASTRules::Typical if epoch < StacksEpochId::Epoch21 => build_ast_typical(
            contract_identifier,
            source_code,
            cost_track,
            clarity_version,
            epoch,
        ),
        _ => build_ast_precheck_size(
            contract_identifier,
            source_code,
            cost_track,
            clarity_version,
            epoch,
        ),
    }
}

/// Build an AST with the typical rules
fn build_ast_typical<T: CostTracker>(
    contract_identifier: &QualifiedContractIdentifier,
    source_code: &str,
    cost_track: &mut T,
    clarity_version: ClarityVersion,
    epoch: StacksEpochId,
) -> ParseResult<ContractAST> {
    let (contract, _, _) = inner_build_ast(
        contract_identifier,
        source_code,
        cost_track,
        clarity_version,
        epoch,
        ASTRules::Typical,
        true,
    )?;
    Ok(contract)
}

/// Used by developer tools only. Continues on through errors by inserting
/// placeholders into the AST. Collects as many diagnostics as possible.
/// Always returns a ContractAST, a vector of diagnostics, and a boolean
/// that indicates if the build was successful.
#[allow(clippy::unwrap_used)]
pub fn build_ast_with_diagnostics<T: CostTracker>(
    contract_identifier: &QualifiedContractIdentifier,
    source_code: &str,
    cost_track: &mut T,
    clarity_version: ClarityVersion,
    epoch: StacksEpochId,
) -> (ContractAST, Vec<Diagnostic>, bool) {
    inner_build_ast(
        contract_identifier,
        source_code,
        cost_track,
        clarity_version,
        epoch,
        ASTRules::PrecheckSize,
        false,
    )
    .unwrap()
}

fn inner_build_ast<T: CostTracker>(
    contract_identifier: &QualifiedContractIdentifier,
    source_code: &str,
    cost_track: &mut T,
    clarity_version: ClarityVersion,
    epoch: StacksEpochId,
    ast_rules: ASTRules,
    error_early: bool,
) -> ParseResult<(ContractAST, Vec<Diagnostic>, bool)> {
    let cost_err = match runtime_cost(
        ClarityCostFunction::AstParse,
        cost_track,
        source_code.len() as u64,
    ) {
        Err(e) if error_early => return Err(e.into()),
        Err(e) => Some(e),
        _ => None,
    };

    let (pre_expressions, mut diagnostics, mut success) = if epoch >= StacksEpochId::Epoch21 {
        if error_early {
            let exprs = parser::v2::parse(source_code)?;
            (exprs, Vec::new(), true)
        } else {
            parser::v2::parse_collect_diagnostics(source_code)
        }
    } else {
        let parse_result = match ast_rules {
            ASTRules::Typical => parse_v1_no_stack_limit(source_code),
            ASTRules::PrecheckSize => parse_v1(source_code),
        };
        match parse_result {
            Ok(pre_expressions) => (pre_expressions, vec![], true),
            Err(error) if error_early => return Err(error),
            Err(error) => (vec![], vec![error.diagnostic], false),
        }
    };

    if let Some(e) = cost_err {
        diagnostics.insert(
            0,
            Diagnostic {
                level: Level::Error,
                message: format!("runtime_cost error: {:?}", e),
                spans: vec![],
                suggestion: None,
            },
        );
    }

    let mut contract_ast = ContractAST::new(contract_identifier.clone(), pre_expressions);
    match StackDepthChecker::run_pass(&mut contract_ast, clarity_version) {
        Err(e) if error_early => return Err(e),
        Err(e) => {
            diagnostics.push(e.diagnostic);
            success = false;
        }
        _ => (),
    }

    if ast_rules != ASTRules::Typical {
        // run extra stack-depth pass for tuples
        match VaryStackDepthChecker::run_pass(&mut contract_ast, clarity_version) {
            Err(e) if error_early => return Err(e),
            Err(e) => {
                diagnostics.push(e.diagnostic);
                success = false;
            }
            _ => (),
        }
    }

    match ExpressionIdentifier::run_pre_expression_pass(&mut contract_ast, clarity_version) {
        Err(e) if error_early => return Err(e),
        Err(e) => {
            diagnostics.push(e.diagnostic);
            success = false;
        }
        _ => (),
    }
    match DefinitionSorter::run_pass(&mut contract_ast, cost_track, clarity_version) {
        Err(e) if error_early => return Err(e),
        Err(e) => {
            diagnostics.push(e.diagnostic);
            success = false;
        }
        _ => (),
    }
    match TraitsResolver::run_pass(&mut contract_ast, clarity_version) {
        Err(e) if error_early => return Err(e),
        Err(e) => {
            diagnostics.push(e.diagnostic);
            success = false;
        }
        _ => (),
    }
    match SugarExpander::run_pass(&mut contract_ast, clarity_version) {
        Err(e) if error_early => return Err(e),
        Err(e) => {
            diagnostics.push(e.diagnostic);
            success = false;
        }
        _ => (),
    }
    match ExpressionIdentifier::run_expression_pass(&mut contract_ast, clarity_version) {
        Err(e) if error_early => return Err(e),
        Err(e) => {
            diagnostics.push(e.diagnostic);
            success = false;
        }
        _ => (),
    }
    Ok((contract_ast, diagnostics, success))
}

/// Built an AST, but pre-check the size of the AST before doing more work
fn build_ast_precheck_size<T: CostTracker>(
    contract_identifier: &QualifiedContractIdentifier,
    source_code: &str,
    cost_track: &mut T,
    clarity_version: ClarityVersion,
    epoch: StacksEpochId,
) -> ParseResult<ContractAST> {
    let (contract, _, _) = inner_build_ast(
        contract_identifier,
        source_code,
        cost_track,
        clarity_version,
        epoch,
        ASTRules::PrecheckSize,
        true,
    )?;
    Ok(contract)
}

/// Test compatibility
#[cfg(any(test, feature = "testing"))]
pub fn build_ast<T: CostTracker>(
    contract_identifier: &QualifiedContractIdentifier,
    source_code: &str,
    cost_track: &mut T,
    clarity_version: ClarityVersion,
    epoch_id: StacksEpochId,
) -> ParseResult<ContractAST> {
    build_ast_typical(
        contract_identifier,
        source_code,
        cost_track,
        clarity_version,
        epoch_id,
    )
}

#[cfg(test)]
mod test {
    use hashbrown::HashMap;
    use stacks_common::types::StacksEpochId;

    use crate::vm::ast::errors::ParseErrors;
    use crate::vm::ast::stack_depth_checker::AST_CALL_STACK_DEPTH_BUFFER;
    use crate::vm::ast::{build_ast, build_ast_with_rules, ASTRules};
    use crate::vm::costs::{LimitedCostTracker, *};
    use crate::vm::representations::depth_traverse;
    use crate::vm::types::QualifiedContractIdentifier;
    use crate::vm::{ClarityCostFunction, ClarityName, ClarityVersion, MAX_CALL_STACK_DEPTH};

    #[derive(PartialEq, Debug)]
    struct UnitTestTracker {
        invoked_functions: Vec<(ClarityCostFunction, Vec<u64>)>,
        invocation_count: u64,
        cost_addition_count: u64,
    }
    impl UnitTestTracker {
        pub fn new() -> Self {
            UnitTestTracker {
                invoked_functions: vec![],
                invocation_count: 0,
                cost_addition_count: 0,
            }
        }
    }
    impl CostTracker for UnitTestTracker {
        fn compute_cost(
            &mut self,
            cost_f: ClarityCostFunction,
            input: &[u64],
        ) -> std::result::Result<ExecutionCost, CostErrors> {
            self.invoked_functions.push((cost_f, input.to_vec()));
            self.invocation_count += 1;
            Ok(ExecutionCost::ZERO)
        }
        fn add_cost(&mut self, _cost: ExecutionCost) -> std::result::Result<(), CostErrors> {
            self.cost_addition_count += 1;
            Ok(())
        }
        fn add_memory(&mut self, _memory: u64) -> std::result::Result<(), CostErrors> {
            Ok(())
        }
        fn drop_memory(&mut self, _memory: u64) -> std::result::Result<(), CostErrors> {
            Ok(())
        }
        fn reset_memory(&mut self) {}
        fn short_circuit_contract_call(
            &mut self,
            _contract: &QualifiedContractIdentifier,
            _function: &ClarityName,
            _input: &[u64],
        ) -> Result<bool, CostErrors> {
            Ok(false)
        }
    }

    #[test]
    fn test_cost_tracking_deep_contracts_2_05() {
        let clarity_version = ClarityVersion::Clarity1;
        let stack_limit =
            (AST_CALL_STACK_DEPTH_BUFFER + (MAX_CALL_STACK_DEPTH as u64) + 1) as usize;
        let exceeds_stack_depth_tuple = format!(
            "{}u1 {}",
            "{ a : ".repeat(stack_limit + 1),
            "} ".repeat(stack_limit + 1)
        );

        // for deep lists, a test like this works:
        //   it can assert a limit, that you can also verify
        //   by disabling `VaryStackDepthChecker` and arbitrarily bumping up the parser lexer limits
        //   and see that it produces the same result
        let exceeds_stack_depth_list = format!(
            "{}u1 {}",
            "(list ".repeat(stack_limit + 1),
            ")".repeat(stack_limit + 1)
        );

        // with old rules, this is just ExpressionStackDepthTooDeep
        let mut cost_track = UnitTestTracker::new();
        let err = build_ast_with_rules(
            &QualifiedContractIdentifier::transient(),
            &exceeds_stack_depth_list,
            &mut cost_track,
            clarity_version,
            StacksEpochId::Epoch2_05,
            ASTRules::Typical,
        )
        .expect_err("Contract should error in parsing");

        let expected_err = ParseErrors::ExpressionStackDepthTooDeep;
        let expected_list_cost_state = UnitTestTracker {
            invoked_functions: vec![(ClarityCostFunction::AstParse, vec![500])],
            invocation_count: 1,
            cost_addition_count: 1,
        };

        assert_eq!(&expected_err, &err.err);
        assert_eq!(expected_list_cost_state, cost_track);

        // with new rules, this is now VaryExpressionStackDepthTooDeep
        let mut cost_track = UnitTestTracker::new();
        let err = build_ast_with_rules(
            &QualifiedContractIdentifier::transient(),
            &exceeds_stack_depth_list,
            &mut cost_track,
            clarity_version,
            StacksEpochId::Epoch2_05,
            ASTRules::PrecheckSize,
        )
        .expect_err("Contract should error in parsing");

        let expected_err = ParseErrors::VaryExpressionStackDepthTooDeep;
        let expected_list_cost_state = UnitTestTracker {
            invoked_functions: vec![(ClarityCostFunction::AstParse, vec![500])],
            invocation_count: 1,
            cost_addition_count: 1,
        };

        assert_eq!(&expected_err, &err.err);
        assert_eq!(expected_list_cost_state, cost_track);

        // you cannot do the same for tuples!
        // in ASTRules::Typical, this passes
        let mut cost_track = UnitTestTracker::new();
        let _ = build_ast_with_rules(
            &QualifiedContractIdentifier::transient(),
            &exceeds_stack_depth_tuple,
            &mut cost_track,
            clarity_version,
            StacksEpochId::Epoch2_05,
            ASTRules::Typical,
        )
        .expect("Contract should parse with ASTRules::Typical");

        // this actually won't even error without
        //  the VaryStackDepthChecker changes.
        let mut cost_track = UnitTestTracker::new();
        let err = build_ast_with_rules(
            &QualifiedContractIdentifier::transient(),
            &exceeds_stack_depth_tuple,
            &mut cost_track,
            clarity_version,
            StacksEpochId::Epoch2_05,
            ASTRules::PrecheckSize,
        )
        .expect_err("Contract should error in parsing with ASTRules::PrecheckSize");

        let expected_err = ParseErrors::VaryExpressionStackDepthTooDeep;
        let expected_list_cost_state = UnitTestTracker {
            invoked_functions: vec![(ClarityCostFunction::AstParse, vec![571])],
            invocation_count: 1,
            cost_addition_count: 1,
        };

        assert_eq!(&expected_err, &err.err);
        assert_eq!(expected_list_cost_state, cost_track);
    }

    #[test]
    fn test_cost_tracking_deep_contracts_2_1() {
        for clarity_version in &[ClarityVersion::Clarity1, ClarityVersion::Clarity2] {
            let stack_limit =
                (AST_CALL_STACK_DEPTH_BUFFER + (MAX_CALL_STACK_DEPTH as u64) + 1) as usize;
            let exceeds_stack_depth_tuple = format!(
                "{}u1 {}",
                "{ a : ".repeat(stack_limit + 1),
                "} ".repeat(stack_limit + 1)
            );

            // for deep lists, a test like this works:
            //   it can assert a limit, that you can also verify
            //   by disabling `VaryStackDepthChecker` and arbitrarily bumping up the parser lexer limits
            //   and see that it produces the same result
            let exceeds_stack_depth_list = format!(
                "{}u1 {}",
                "(list ".repeat(stack_limit + 1),
                ")".repeat(stack_limit + 1)
            );

            // with old rules, this is just ExpressionStackDepthTooDeep
            let mut cost_track = UnitTestTracker::new();
            let err = build_ast_with_rules(
                &QualifiedContractIdentifier::transient(),
                &exceeds_stack_depth_list,
                &mut cost_track,
                *clarity_version,
                StacksEpochId::Epoch21,
                ASTRules::Typical,
            )
            .expect_err("Contract should error in parsing");

            let expected_err = ParseErrors::ExpressionStackDepthTooDeep;
            let expected_list_cost_state = UnitTestTracker {
                invoked_functions: vec![(ClarityCostFunction::AstParse, vec![500])],
                invocation_count: 1,
                cost_addition_count: 1,
            };

            assert_eq!(&expected_err, &err.err);
            assert_eq!(expected_list_cost_state, cost_track);

            // in 2.1, this is still ExpressionStackDepthTooDeep
            let mut cost_track = UnitTestTracker::new();
            let err = build_ast_with_rules(
                &QualifiedContractIdentifier::transient(),
                &exceeds_stack_depth_list,
                &mut cost_track,
                *clarity_version,
                StacksEpochId::Epoch21,
                ASTRules::PrecheckSize,
            )
            .expect_err("Contract should error in parsing");

            let expected_err = ParseErrors::ExpressionStackDepthTooDeep;
            let expected_list_cost_state = UnitTestTracker {
                invoked_functions: vec![(ClarityCostFunction::AstParse, vec![500])],
                invocation_count: 1,
                cost_addition_count: 1,
            };

            assert_eq!(&expected_err, &err.err);
            assert_eq!(expected_list_cost_state, cost_track);

            // in 2.1, ASTRules::Typical is ignored -- this still fails to parse
            let mut cost_track = UnitTestTracker::new();
            let _ = build_ast_with_rules(
                &QualifiedContractIdentifier::transient(),
                &exceeds_stack_depth_tuple,
                &mut cost_track,
                *clarity_version,
                StacksEpochId::Epoch21,
                ASTRules::Typical,
            )
            .expect_err("Contract should error in parsing");

            let expected_err = ParseErrors::ExpressionStackDepthTooDeep;
            let expected_list_cost_state = UnitTestTracker {
                invoked_functions: vec![(ClarityCostFunction::AstParse, vec![571])],
                invocation_count: 1,
                cost_addition_count: 1,
            };

            assert_eq!(&expected_err, &err.err);
            assert_eq!(expected_list_cost_state, cost_track);

            // in 2.1, ASTRules::PrecheckSize is still ignored -- this still fails to parse
            let mut cost_track = UnitTestTracker::new();
            let err = build_ast_with_rules(
                &QualifiedContractIdentifier::transient(),
                &exceeds_stack_depth_tuple,
                &mut cost_track,
                *clarity_version,
                StacksEpochId::Epoch21,
                ASTRules::PrecheckSize,
            )
            .expect_err("Contract should error in parsing");

            let expected_err = ParseErrors::ExpressionStackDepthTooDeep;
            let expected_list_cost_state = UnitTestTracker {
                invoked_functions: vec![(ClarityCostFunction::AstParse, vec![571])],
                invocation_count: 1,
                cost_addition_count: 1,
            };

            assert_eq!(&expected_err, &err.err);
            assert_eq!(expected_list_cost_state, cost_track);
        }
    }

    #[test]
    fn test_expression_identification_tuples() {
        for version in &[ClarityVersion::Clarity1, ClarityVersion::Clarity2] {
            for epoch in &[StacksEpochId::Epoch2_05, StacksEpochId::Epoch21] {
                let progn = "{ a: (+ 1 2 3),
                           b: 1,
                           c: 3 }";

                let mut cost_track = LimitedCostTracker::new_free();
                let ast = build_ast(
                    &QualifiedContractIdentifier::transient(),
                    progn,
                    &mut cost_track,
                    *version,
                    *epoch,
                )
                .unwrap()
                .expressions;

                let mut visited = HashMap::new();

                for expr in ast.iter() {
                    depth_traverse::<_, _, ()>(expr, |x| {
                        assert!(!visited.contains_key(&x.id));
                        visited.insert(x.id, true);
                        Ok(())
                    })
                    .unwrap();
                }
            }
        }
    }
}
