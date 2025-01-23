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

use crate::vm::ast::errors::{ParseErrors, ParseResult};
use crate::vm::ast::types::{BuildASTPass, ContractAST};
use crate::vm::representations::PreSymbolicExpression;
use crate::vm::representations::PreSymbolicExpressionType::{List, Tuple};
use crate::vm::{ClarityVersion, MAX_CALL_STACK_DEPTH};

// allow  the AST to get deeper than the max call stack depth,
//    but not much deeper (things like tuples would increase the
//    AST depth, without impacting the stack depth).
pub const AST_CALL_STACK_DEPTH_BUFFER: u64 = 5;

fn check(args: &[PreSymbolicExpression], depth: u64) -> ParseResult<()> {
    if depth >= (AST_CALL_STACK_DEPTH_BUFFER + MAX_CALL_STACK_DEPTH as u64) {
        return Err(ParseErrors::ExpressionStackDepthTooDeep.into());
    }
    for expression in args.iter() {
        match expression.pre_expr {
            List(ref exprs) => check(exprs, depth + 1),
            _ => {
                // Other symbolic expressions don't have depth
                //  impacts.
                Ok(())
            }
        }?;
    }
    Ok(())
}

pub struct StackDepthChecker;

impl BuildASTPass for StackDepthChecker {
    fn run_pass(contract_ast: &mut ContractAST, _version: ClarityVersion) -> ParseResult<()> {
        check(&contract_ast.pre_expressions, 0)
    }
}

fn check_vary(args: &[PreSymbolicExpression], depth: u64) -> ParseResult<()> {
    if depth >= (AST_CALL_STACK_DEPTH_BUFFER + MAX_CALL_STACK_DEPTH as u64) {
        return Err(ParseErrors::VaryExpressionStackDepthTooDeep.into());
    }
    for expression in args.iter() {
        match expression.pre_expr {
            List(ref exprs) => check_vary(exprs, depth + 1),
            Tuple(ref exprs) => check_vary(exprs, depth + 1),
            _ => {
                // Other symbolic expressions don't have depth
                //  impacts.
                Ok(())
            }
        }?;
    }
    Ok(())
}

pub struct VaryStackDepthChecker;

impl BuildASTPass for VaryStackDepthChecker {
    fn run_pass(contract_ast: &mut ContractAST, _version: ClarityVersion) -> ParseResult<()> {
        check_vary(&contract_ast.pre_expressions, 0)
    }
}
