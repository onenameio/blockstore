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

use stacks_common::consts::TOKEN_TRANSFER_MEMO_LENGTH;

use super::{TypeChecker, TypeResult, TypingContext};
use crate::vm::analysis::errors::{check_argument_count, CheckErrors};
use crate::vm::costs::cost_functions::ClarityCostFunction;
use crate::vm::costs::runtime_cost;
use crate::vm::representations::SymbolicExpression;
use crate::vm::types::{BufferLength, SequenceSubtype, TypeSignature};

pub fn check_special_get_owner(
    checker: &mut TypeChecker,
    args: &[SymbolicExpression],
    context: &TypingContext,
) -> TypeResult {
    check_argument_count(2, args)?;

    let asset_name = args[0].match_atom().ok_or(CheckErrors::BadTokenName)?;

    let expected_asset_type = checker
        .contract_context
        .get_nft_type(asset_name)
        .cloned()
        .ok_or_else(|| CheckErrors::NoSuchNFT(asset_name.to_string()))?;

    runtime_cost(
        ClarityCostFunction::AnalysisTypeLookup,
        checker,
        expected_asset_type.type_size()?,
    )?;

    checker.type_check_expects(&args[1], context, &expected_asset_type)?;

    Ok(TypeSignature::OptionalType(Box::new(
        TypeSignature::PrincipalType,
    )))
}

pub fn check_special_get_balance(
    checker: &mut TypeChecker,
    args: &[SymbolicExpression],
    context: &TypingContext,
) -> TypeResult {
    check_argument_count(2, args)?;

    let asset_name = args[0].match_atom().ok_or(CheckErrors::BadTokenName)?;

    if !checker.contract_context.ft_exists(asset_name) {
        return Err(CheckErrors::NoSuchFT(asset_name.to_string()).into());
    }

    runtime_cost(ClarityCostFunction::AnalysisTypeLookup, checker, 1)?;

    let expected_owner_type: TypeSignature = TypeSignature::PrincipalType;
    checker.type_check_expects(&args[1], context, &expected_owner_type)?;

    Ok(TypeSignature::UIntType)
}

pub fn check_special_mint_asset(
    checker: &mut TypeChecker,
    args: &[SymbolicExpression],
    context: &TypingContext,
) -> TypeResult {
    check_argument_count(3, args)?;

    let asset_name = args[0].match_atom().ok_or(CheckErrors::BadTokenName)?;

    let expected_owner_type: TypeSignature = TypeSignature::PrincipalType;
    let expected_asset_type = checker
        .contract_context
        .get_nft_type(asset_name)
        .ok_or(CheckErrors::NoSuchNFT(asset_name.to_string()))?
        .clone(); // this clone shouldn't be strictly necessary, but to use `type_check_expects` with this, it would have to be.

    runtime_cost(
        ClarityCostFunction::AnalysisTypeLookup,
        checker,
        expected_asset_type.type_size()?,
    )?;

    checker.type_check_expects(&args[1], context, &expected_asset_type)?;
    checker.type_check_expects(&args[2], context, &expected_owner_type)?;

    Ok(TypeSignature::ResponseType(Box::new((
        TypeSignature::BoolType,
        TypeSignature::UIntType,
    ))))
}

pub fn check_special_mint_token(
    checker: &mut TypeChecker,
    args: &[SymbolicExpression],
    context: &TypingContext,
) -> TypeResult {
    check_argument_count(3, args)?;

    let asset_name = args[0].match_atom().ok_or(CheckErrors::BadTokenName)?;

    let expected_amount: TypeSignature = TypeSignature::UIntType;
    let expected_owner_type: TypeSignature = TypeSignature::PrincipalType;

    runtime_cost(ClarityCostFunction::AnalysisTypeLookup, checker, 1)?;

    checker.type_check_expects(&args[1], context, &expected_amount)?;
    checker.type_check_expects(&args[2], context, &expected_owner_type)?;

    if !checker.contract_context.ft_exists(asset_name) {
        return Err(CheckErrors::NoSuchFT(asset_name.to_string()).into());
    }

    Ok(TypeSignature::ResponseType(Box::new((
        TypeSignature::BoolType,
        TypeSignature::UIntType,
    ))))
}

pub fn check_special_transfer_asset(
    checker: &mut TypeChecker,
    args: &[SymbolicExpression],
    context: &TypingContext,
) -> TypeResult {
    check_argument_count(4, args)?;

    let token_name = args[0].match_atom().ok_or(CheckErrors::BadTokenName)?;

    let expected_owner_type: TypeSignature = TypeSignature::PrincipalType;
    let expected_asset_type = checker
        .contract_context
        .get_nft_type(token_name)
        .ok_or(CheckErrors::NoSuchNFT(token_name.to_string()))?
        .clone();

    runtime_cost(
        ClarityCostFunction::AnalysisTypeLookup,
        checker,
        expected_asset_type.type_size()?,
    )?;

    checker.type_check_expects(&args[1], context, &expected_asset_type)?;
    checker.type_check_expects(&args[2], context, &expected_owner_type)?; // owner
    checker.type_check_expects(&args[3], context, &expected_owner_type)?; // recipient

    Ok(TypeSignature::ResponseType(Box::new((
        TypeSignature::BoolType,
        TypeSignature::UIntType,
    ))))
}

pub fn check_special_transfer_token(
    checker: &mut TypeChecker,
    args: &[SymbolicExpression],
    context: &TypingContext,
) -> TypeResult {
    check_argument_count(4, args)?;

    let token_name = args[0].match_atom().ok_or(CheckErrors::BadTokenName)?;

    let expected_amount: TypeSignature = TypeSignature::UIntType;
    let expected_owner_type: TypeSignature = TypeSignature::PrincipalType;

    runtime_cost(ClarityCostFunction::AnalysisTypeLookup, checker, 1)?;

    checker.type_check_expects(&args[1], context, &expected_amount)?;
    checker.type_check_expects(&args[2], context, &expected_owner_type)?; // owner
    checker.type_check_expects(&args[3], context, &expected_owner_type)?; // recipient

    if !checker.contract_context.ft_exists(token_name) {
        return Err(CheckErrors::NoSuchFT(token_name.to_string()).into());
    }

    Ok(TypeSignature::ResponseType(Box::new((
        TypeSignature::BoolType,
        TypeSignature::UIntType,
    ))))
}

pub fn check_special_stx_transfer(
    checker: &mut TypeChecker,
    args: &[SymbolicExpression],
    context: &TypingContext,
) -> TypeResult {
    check_argument_count(3, args)?;

    let amount_type: TypeSignature = TypeSignature::UIntType;
    let from_type: TypeSignature = TypeSignature::PrincipalType;
    let to_type: TypeSignature = TypeSignature::PrincipalType;

    runtime_cost(ClarityCostFunction::AnalysisTypeLookup, checker, 0)?;

    checker.type_check_expects(&args[0], context, &amount_type)?;
    checker.type_check_expects(&args[1], context, &from_type)?;
    checker.type_check_expects(&args[2], context, &to_type)?;

    Ok(TypeSignature::ResponseType(Box::new((
        TypeSignature::BoolType,
        TypeSignature::UIntType,
    ))))
}

pub fn check_special_stx_transfer_memo(
    checker: &mut TypeChecker,
    args: &[SymbolicExpression],
    context: &TypingContext,
) -> TypeResult {
    check_argument_count(4, args)?;

    let amount_type: TypeSignature = TypeSignature::UIntType;
    let from_type: TypeSignature = TypeSignature::PrincipalType;
    let to_type: TypeSignature = TypeSignature::PrincipalType;
    let memo_type: TypeSignature = TypeSignature::SequenceType(SequenceSubtype::BufferType(
        BufferLength::try_from(TOKEN_TRANSFER_MEMO_LENGTH as u32)
            .map_err(|_| CheckErrors::Expects("Bad constructor".into()))?,
    ));

    runtime_cost(ClarityCostFunction::AnalysisTypeLookup, checker, 0)?;

    checker.type_check_expects(&args[0], context, &amount_type)?;
    checker.type_check_expects(&args[1], context, &from_type)?;
    checker.type_check_expects(&args[2], context, &to_type)?;
    checker.type_check_expects(&args[3], context, &memo_type)?;

    Ok(TypeSignature::ResponseType(Box::new((
        TypeSignature::BoolType,
        TypeSignature::UIntType,
    ))))
}

pub fn check_special_get_token_supply(
    checker: &mut TypeChecker,
    args: &[SymbolicExpression],
    _context: &TypingContext,
) -> TypeResult {
    check_argument_count(1, args)?;

    let asset_name = args[0].match_atom().ok_or(CheckErrors::BadTokenName)?;

    if !checker.contract_context.ft_exists(asset_name) {
        return Err(CheckErrors::NoSuchFT(asset_name.to_string()).into());
    }

    runtime_cost(ClarityCostFunction::AnalysisTypeLookup, checker, 1)?;

    Ok(TypeSignature::UIntType)
}

pub fn check_special_burn_asset(
    checker: &mut TypeChecker,
    args: &[SymbolicExpression],
    context: &TypingContext,
) -> TypeResult {
    check_argument_count(3, args)?;

    let asset_name = args[0].match_atom().ok_or(CheckErrors::BadTokenName)?;

    let expected_owner_type: TypeSignature = TypeSignature::PrincipalType;
    let expected_asset_type = checker
        .contract_context
        .get_nft_type(asset_name)
        .ok_or(CheckErrors::NoSuchNFT(asset_name.to_string()))?
        .clone(); // this clone shouldn't be strictly necessary, but to use `type_check_expects` with this, it would have to be.

    runtime_cost(
        ClarityCostFunction::AnalysisTypeLookup,
        checker,
        expected_asset_type.type_size()?,
    )?;

    checker.type_check_expects(&args[1], context, &expected_asset_type)?;
    checker.type_check_expects(&args[2], context, &expected_owner_type)?;

    Ok(TypeSignature::ResponseType(Box::new((
        TypeSignature::BoolType,
        TypeSignature::UIntType,
    ))))
}

pub fn check_special_burn_token(
    checker: &mut TypeChecker,
    args: &[SymbolicExpression],
    context: &TypingContext,
) -> TypeResult {
    check_argument_count(3, args)?;

    let asset_name = args[0].match_atom().ok_or(CheckErrors::BadTokenName)?;

    let expected_amount: TypeSignature = TypeSignature::UIntType;
    let expected_owner_type: TypeSignature = TypeSignature::PrincipalType;

    runtime_cost(ClarityCostFunction::AnalysisTypeLookup, checker, 1)?;

    checker.type_check_expects(&args[1], context, &expected_amount)?;
    checker.type_check_expects(&args[2], context, &expected_owner_type)?;

    if !checker.contract_context.ft_exists(asset_name) {
        return Err(CheckErrors::NoSuchFT(asset_name.to_string()).into());
    }

    Ok(TypeSignature::ResponseType(Box::new((
        TypeSignature::BoolType,
        TypeSignature::UIntType,
    ))))
}
