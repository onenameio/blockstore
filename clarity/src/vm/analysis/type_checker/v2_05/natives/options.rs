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

use crate::vm::analysis::type_checker::v2_05::{
    check_argument_count, check_arguments_at_least, no_type, CheckErrors, TypeChecker, TypeResult,
    TypingContext,
};
use crate::vm::costs::cost_functions::ClarityCostFunction;
use crate::vm::costs::{analysis_typecheck_cost, runtime_cost};
use crate::vm::representations::{ClarityName, SymbolicExpression};
use crate::vm::types::TypeSignature;

pub fn check_special_okay(
    checker: &mut TypeChecker,
    args: &[SymbolicExpression],
    context: &TypingContext,
) -> TypeResult {
    check_argument_count(1, args)?;

    runtime_cost(ClarityCostFunction::AnalysisOptionCons, checker, 0)?;

    let inner_type = checker.type_check(&args[0], context)?;
    let resp_type = TypeSignature::new_response(inner_type, no_type())?;
    Ok(resp_type)
}

pub fn check_special_some(
    checker: &mut TypeChecker,
    args: &[SymbolicExpression],
    context: &TypingContext,
) -> TypeResult {
    check_argument_count(1, args)?;

    runtime_cost(ClarityCostFunction::AnalysisOptionCons, checker, 0)?;

    let inner_type = checker.type_check(&args[0], context)?;
    let resp_type = TypeSignature::new_option(inner_type)?;
    Ok(resp_type)
}

pub fn check_special_error(
    checker: &mut TypeChecker,
    args: &[SymbolicExpression],
    context: &TypingContext,
) -> TypeResult {
    check_argument_count(1, args)?;

    runtime_cost(ClarityCostFunction::AnalysisOptionCons, checker, 0)?;

    let inner_type = checker.type_check(&args[0], context)?;
    let resp_type = TypeSignature::new_response(no_type(), inner_type)?;
    Ok(resp_type)
}

pub fn check_special_is_response(
    checker: &mut TypeChecker,
    args: &[SymbolicExpression],
    context: &TypingContext,
) -> TypeResult {
    check_argument_count(1, args)?;

    let input = checker.type_check(&args[0], context)?;

    runtime_cost(ClarityCostFunction::AnalysisOptionCheck, checker, 0)?;

    if let TypeSignature::ResponseType(_types) = input {
        Ok(TypeSignature::BoolType)
    } else {
        Err(CheckErrors::ExpectedResponseType(input.clone()).into())
    }
}

pub fn check_special_is_optional(
    checker: &mut TypeChecker,
    args: &[SymbolicExpression],
    context: &TypingContext,
) -> TypeResult {
    check_argument_count(1, args)?;

    let input = checker.type_check(&args[0], context)?;

    runtime_cost(ClarityCostFunction::AnalysisOptionCheck, checker, 0)?;

    if let TypeSignature::OptionalType(_type) = input {
        Ok(TypeSignature::BoolType)
    } else {
        Err(CheckErrors::ExpectedOptionalType(input.clone()).into())
    }
}

pub fn check_special_default_to(
    checker: &mut TypeChecker,
    args: &[SymbolicExpression],
    context: &TypingContext,
) -> TypeResult {
    check_argument_count(2, args)?;

    let default = checker.type_check(&args[0], context)?;
    let input = checker.type_check(&args[1], context)?;

    analysis_typecheck_cost(checker, &default, &input)?;

    if let TypeSignature::OptionalType(input_type) = input {
        let contained_type = *input_type;
        TypeSignature::least_supertype(&StacksEpochId::Epoch2_05, &default, &contained_type)
            .map_err(|_| CheckErrors::DefaultTypesMustMatch(default, contained_type).into())
    } else {
        Err(CheckErrors::ExpectedOptionalType(input).into())
    }
}

pub fn check_special_asserts(
    checker: &mut TypeChecker,
    args: &[SymbolicExpression],
    context: &TypingContext,
) -> TypeResult {
    check_argument_count(2, args)?;

    checker.type_check_expects(&args[0], context, &TypeSignature::BoolType)?;
    let on_error = checker.type_check(&args[1], context)?;

    checker.track_return_type(on_error)?;

    Ok(TypeSignature::BoolType)
}

fn inner_unwrap(input: TypeSignature, checker: &mut TypeChecker) -> TypeResult {
    runtime_cost(ClarityCostFunction::AnalysisOptionCheck, checker, 0)?;

    match input {
        TypeSignature::OptionalType(input_type) => {
            if input_type.is_no_type() {
                Err(CheckErrors::CouldNotDetermineResponseOkType.into())
            } else {
                Ok(*input_type)
            }
        }
        TypeSignature::ResponseType(response_type) => {
            let ok_type = response_type.0;
            if ok_type.is_no_type() {
                Err(CheckErrors::CouldNotDetermineResponseOkType.into())
            } else {
                Ok(ok_type)
            }
        }
        _ => Err(CheckErrors::ExpectedOptionalOrResponseType(input).into()),
    }
}

fn inner_unwrap_err(input: TypeSignature, checker: &mut TypeChecker) -> TypeResult {
    runtime_cost(ClarityCostFunction::AnalysisOptionCheck, checker, 0)?;

    if let TypeSignature::ResponseType(response_type) = input {
        let err_type = response_type.1;
        if err_type.is_no_type() {
            Err(CheckErrors::CouldNotDetermineResponseErrType.into())
        } else {
            Ok(err_type)
        }
    } else {
        Err(CheckErrors::ExpectedResponseType(input).into())
    }
}

pub fn check_special_unwrap_or_ret(
    checker: &mut TypeChecker,
    args: &[SymbolicExpression],
    context: &TypingContext,
) -> TypeResult {
    check_argument_count(2, args)?;

    let input = checker.type_check(&args[0], context)?;
    let on_error = checker.type_check(&args[1], context)?;

    checker.track_return_type(on_error)?;

    inner_unwrap(input, checker)
}

pub fn check_special_unwrap_err_or_ret(
    checker: &mut TypeChecker,
    args: &[SymbolicExpression],
    context: &TypingContext,
) -> TypeResult {
    check_argument_count(2, args)?;

    let input = checker.type_check(&args[0], context)?;
    let on_error = checker.type_check(&args[1], context)?;

    checker.track_return_type(on_error)?;

    inner_unwrap_err(input, checker)
}

pub fn check_special_try_ret(
    checker: &mut TypeChecker,
    args: &[SymbolicExpression],
    context: &TypingContext,
) -> TypeResult {
    check_argument_count(1, args)?;

    let input = checker.type_check(&args[0], context)?;

    runtime_cost(ClarityCostFunction::AnalysisOptionCheck, checker, 0)?;

    match input {
        TypeSignature::OptionalType(input_type) => {
            if input_type.is_no_type() {
                Err(CheckErrors::CouldNotDetermineResponseOkType.into())
            } else {
                checker.track_return_type(TypeSignature::new_option(TypeSignature::NoType)?)?;
                Ok(*input_type)
            }
        }
        TypeSignature::ResponseType(response_type) => {
            let (ok_type, err_type) = *response_type;
            if ok_type.is_no_type() {
                Err(CheckErrors::CouldNotDetermineResponseOkType.into())
            } else if err_type.is_no_type() {
                Err(CheckErrors::CouldNotDetermineResponseErrType.into())
            } else {
                checker.track_return_type(TypeSignature::new_response(
                    TypeSignature::NoType,
                    err_type,
                )?)?;
                Ok(ok_type)
            }
        }
        _ => Err(CheckErrors::ExpectedOptionalOrResponseType(input).into()),
    }
}

pub fn check_special_unwrap(
    checker: &mut TypeChecker,
    args: &[SymbolicExpression],
    context: &TypingContext,
) -> TypeResult {
    check_argument_count(1, args)?;

    let input = checker.type_check(&args[0], context)?;

    inner_unwrap(input, checker)
}

pub fn check_special_unwrap_err(
    checker: &mut TypeChecker,
    args: &[SymbolicExpression],
    context: &TypingContext,
) -> TypeResult {
    check_argument_count(1, args)?;

    let input = checker.type_check(&args[0], context)?;

    inner_unwrap_err(input, checker)
}

fn eval_with_new_binding(
    body: &SymbolicExpression,
    bind_name: ClarityName,
    bind_type: TypeSignature,
    checker: &mut TypeChecker,
    context: &TypingContext,
) -> TypeResult {
    let mut inner_context = context.extend()?;

    runtime_cost(
        ClarityCostFunction::AnalysisBindName,
        checker,
        bind_type.type_size()?,
    )?;

    checker.contract_context.check_name_used(&bind_name)?;

    if inner_context.lookup_variable_type(&bind_name).is_some() {
        return Err(CheckErrors::NameAlreadyUsed(bind_name.into()).into());
    }

    inner_context.variable_types.insert(bind_name, bind_type);

    checker.type_check(body, &inner_context)
}

fn check_special_match_opt(
    option_type: TypeSignature,
    checker: &mut TypeChecker,
    args: &[SymbolicExpression],
    context: &TypingContext,
) -> TypeResult {
    if args.len() != 3 {
        Err(CheckErrors::BadMatchOptionSyntax(Box::new(
            CheckErrors::IncorrectArgumentCount(4, args.len() + 1),
        )))?;
    }

    let bind_name = args[0]
        .match_atom()
        .ok_or_else(|| CheckErrors::BadMatchOptionSyntax(Box::new(CheckErrors::ExpectedName)))?
        .clone();
    let some_branch = &args[1];
    let none_branch = &args[2];

    if option_type.is_no_type() {
        return Err(CheckErrors::CouldNotDetermineMatchTypes.into());
    }

    let some_branch_type =
        eval_with_new_binding(some_branch, bind_name, option_type, checker, context)?;
    let none_branch_type = checker.type_check(none_branch, context)?;

    analysis_typecheck_cost(checker, &some_branch_type, &none_branch_type)?;

    TypeSignature::least_supertype(
        &StacksEpochId::Epoch2_05,
        &some_branch_type,
        &none_branch_type,
    )
    .map_err(|_| CheckErrors::MatchArmsMustMatch(some_branch_type, none_branch_type).into())
}

fn check_special_match_resp(
    resp_type: (TypeSignature, TypeSignature),
    checker: &mut TypeChecker,
    args: &[SymbolicExpression],
    context: &TypingContext,
) -> TypeResult {
    if args.len() != 4 {
        Err(CheckErrors::BadMatchResponseSyntax(Box::new(
            CheckErrors::IncorrectArgumentCount(5, args.len() + 1),
        )))?;
    }

    let ok_bind_name = args[0]
        .match_atom()
        .ok_or_else(|| CheckErrors::BadMatchResponseSyntax(Box::new(CheckErrors::ExpectedName)))?
        .clone();
    let ok_branch = &args[1];
    let err_bind_name = args[2]
        .match_atom()
        .ok_or_else(|| CheckErrors::BadMatchResponseSyntax(Box::new(CheckErrors::ExpectedName)))?
        .clone();
    let err_branch = &args[3];

    let (ok_type, err_type) = resp_type;

    if ok_type.is_no_type() || err_type.is_no_type() {
        return Err(CheckErrors::CouldNotDetermineMatchTypes.into());
    }

    let ok_branch_type = eval_with_new_binding(ok_branch, ok_bind_name, ok_type, checker, context)?;
    let err_branch_type =
        eval_with_new_binding(err_branch, err_bind_name, err_type, checker, context)?;

    analysis_typecheck_cost(checker, &ok_branch_type, &err_branch_type)?;

    TypeSignature::least_supertype(&StacksEpochId::Epoch2_05, &ok_branch_type, &err_branch_type)
        .map_err(|_| CheckErrors::MatchArmsMustMatch(ok_branch_type, err_branch_type).into())
}

pub fn check_special_match(
    checker: &mut TypeChecker,
    args: &[SymbolicExpression],
    context: &TypingContext,
) -> TypeResult {
    check_arguments_at_least(1, args)?;

    let input = checker.type_check(&args[0], context)?;

    match input {
        TypeSignature::OptionalType(option_type) => {
            check_special_match_opt(*option_type, checker, &args[1..], context)
        }
        TypeSignature::ResponseType(resp_type) => {
            check_special_match_resp(*resp_type, checker, &args[1..], context)
        }
        _ => Err(CheckErrors::BadMatchInput(input).into()),
    }
}
