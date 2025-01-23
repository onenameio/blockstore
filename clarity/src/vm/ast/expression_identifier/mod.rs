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

use crate::vm::ast::errors::{ParseError, ParseErrors, ParseResult};
use crate::vm::ast::types::ContractAST;
use crate::vm::representations::SymbolicExpressionCommon;
use crate::vm::ClarityVersion;

fn inner_relabel<T: SymbolicExpressionCommon>(args: &mut [T], index: u64) -> ParseResult<u64> {
    let mut current = index
        .checked_add(1)
        .ok_or(ParseError::new(ParseErrors::TooManyExpressions))?;
    for expression in &mut args[..] {
        expression.set_id(current);
        current = if let Some(exprs) = expression.match_list_mut() {
            inner_relabel(exprs, current)
        } else {
            current
                .checked_add(1)
                .ok_or(ParseError::new(ParseErrors::TooManyExpressions))
        }?;
    }
    Ok(current)
}

pub fn update_expression_id<T: SymbolicExpressionCommon>(exprs: &mut [T]) -> ParseResult<()> {
    inner_relabel(exprs, 0)?;
    Ok(())
}

pub struct ExpressionIdentifier;

impl ExpressionIdentifier {
    pub fn run_pre_expression_pass(
        contract_ast: &mut ContractAST,
        _version: ClarityVersion,
    ) -> ParseResult<()> {
        update_expression_id(contract_ast.pre_expressions.as_mut_slice())?;
        Ok(())
    }
    pub fn run_expression_pass(
        contract_ast: &mut ContractAST,
        _version: ClarityVersion,
    ) -> ParseResult<()> {
        update_expression_id(contract_ast.expressions.as_mut_slice())?;
        Ok(())
    }
}
