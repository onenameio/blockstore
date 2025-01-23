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

use stacks_common::types::StacksEpochId;

use crate::vm::analysis::type_checker::v2_1::{
    check_arguments_at_least, CheckError, CheckErrors, TypeChecker, TypeResult, TypingContext,
};
use crate::vm::costs::cost_functions::ClarityCostFunction;
use crate::vm::costs::{analysis_typecheck_cost, runtime_cost};
use crate::vm::representations::SymbolicExpression;
use crate::vm::types::TypeSignature;

pub fn check_special_fetch_entry(
    checker: &mut TypeChecker,
    args: &[SymbolicExpression],
    context: &TypingContext,
) -> TypeResult {
    check_arguments_at_least(2, args)?;

    let map_name = args[0].match_atom().ok_or(CheckErrors::BadMapName)?;

    let key_type = checker.type_check(&args[1], context)?;

    let (expected_key_type, value_type) = checker
        .contract_context
        .get_map_type(map_name)
        .ok_or(CheckErrors::NoSuchMap(map_name.to_string()))?;

    runtime_cost(
        ClarityCostFunction::AnalysisTypeLookup,
        &mut checker.cost_track,
        expected_key_type.type_size()?,
    )?;
    runtime_cost(
        ClarityCostFunction::AnalysisTypeLookup,
        &mut checker.cost_track,
        value_type.type_size()?,
    )?;
    analysis_typecheck_cost(&mut checker.cost_track, expected_key_type, &key_type)?;

    let option_type = TypeSignature::new_option(value_type.clone())?;

    if !expected_key_type.admits_type(&StacksEpochId::Epoch21, &key_type)? {
        Err(CheckError::new(CheckErrors::TypeError(
            expected_key_type.clone(),
            key_type,
        )))
    } else {
        Ok(option_type)
    }
}

pub fn check_special_delete_entry(
    checker: &mut TypeChecker,
    args: &[SymbolicExpression],
    context: &TypingContext,
) -> TypeResult {
    check_arguments_at_least(2, args)?;

    let map_name = args[0].match_atom().ok_or(CheckErrors::BadMapName)?;

    let key_type = checker.type_check(&args[1], context)?;

    let (expected_key_type, _) = checker
        .contract_context
        .get_map_type(map_name)
        .ok_or(CheckErrors::NoSuchMap(map_name.to_string()))?;

    runtime_cost(
        ClarityCostFunction::AnalysisTypeLookup,
        &mut checker.cost_track,
        expected_key_type.type_size()?,
    )?;
    analysis_typecheck_cost(&mut checker.cost_track, expected_key_type, &key_type)?;

    if !expected_key_type.admits_type(&StacksEpochId::Epoch21, &key_type)? {
        Err(CheckError::new(CheckErrors::TypeError(
            expected_key_type.clone(),
            key_type,
        )))
    } else {
        Ok(TypeSignature::BoolType)
    }
}

fn check_set_or_insert_entry(
    checker: &mut TypeChecker,
    args: &[SymbolicExpression],
    context: &TypingContext,
) -> TypeResult {
    check_arguments_at_least(3, args)?;

    let map_name = args[0].match_atom().ok_or(CheckErrors::BadMapName)?;

    let key_type = checker.type_check(&args[1], context)?;
    let value_type = checker.type_check(&args[2], context)?;

    let (expected_key_type, expected_value_type) = checker
        .contract_context
        .get_map_type(map_name)
        .ok_or(CheckErrors::NoSuchMap(map_name.to_string()))?;

    runtime_cost(
        ClarityCostFunction::AnalysisTypeLookup,
        &mut checker.cost_track,
        expected_key_type.type_size()?,
    )?;
    runtime_cost(
        ClarityCostFunction::AnalysisTypeLookup,
        &mut checker.cost_track,
        value_type.type_size()?,
    )?;

    analysis_typecheck_cost(&mut checker.cost_track, expected_key_type, &key_type)?;
    analysis_typecheck_cost(&mut checker.cost_track, expected_value_type, &value_type)?;

    if !expected_key_type.admits_type(&StacksEpochId::Epoch21, &key_type)? {
        Err(CheckError::new(CheckErrors::TypeError(
            expected_key_type.clone(),
            key_type,
        )))
    } else if !expected_value_type.admits_type(&StacksEpochId::Epoch21, &value_type)? {
        Err(CheckError::new(CheckErrors::TypeError(
            expected_value_type.clone(),
            value_type,
        )))
    } else {
        Ok(TypeSignature::BoolType)
    }
}

pub fn check_special_set_entry(
    checker: &mut TypeChecker,
    args: &[SymbolicExpression],
    context: &TypingContext,
) -> TypeResult {
    check_set_or_insert_entry(checker, args, context)
}

pub fn check_special_insert_entry(
    checker: &mut TypeChecker,
    args: &[SymbolicExpression],
    context: &TypingContext,
) -> TypeResult {
    check_set_or_insert_entry(checker, args, context)
}
