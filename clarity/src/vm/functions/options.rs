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

use crate::vm::contexts::{Environment, LocalContext};
use crate::vm::costs::cost_functions::ClarityCostFunction;
use crate::vm::costs::{runtime_cost, CostTracker, MemoryConsumer};
use crate::vm::errors::{
    check_arguments_at_least, CheckErrors, InterpreterError, InterpreterResult as Result,
    RuntimeErrorType, ShortReturnType,
};
use crate::vm::types::{CallableData, OptionalData, ResponseData, TypeSignature, Value};
use crate::vm::Value::CallableContract;
use crate::vm::{self, ClarityName, ClarityVersion, SymbolicExpression};

fn inner_unwrap(to_unwrap: Value) -> Result<Option<Value>> {
    let result = match to_unwrap {
        Value::Optional(data) => data.data.map(|data| *data),
        Value::Response(data) => {
            if data.committed {
                Some(*data.data)
            } else {
                None
            }
        }
        _ => return Err(CheckErrors::ExpectedOptionalOrResponseValue(to_unwrap).into()),
    };

    Ok(result)
}

fn inner_unwrap_err(to_unwrap: Value) -> Result<Option<Value>> {
    let result = match to_unwrap {
        Value::Response(data) => {
            if !data.committed {
                Some(*data.data)
            } else {
                None
            }
        }
        _ => return Err(CheckErrors::ExpectedResponseValue(to_unwrap).into()),
    };

    Ok(result)
}

pub fn native_unwrap(input: Value) -> Result<Value> {
    inner_unwrap(input).and_then(|opt_value| match opt_value {
        Some(v) => Ok(v),
        None => Err(RuntimeErrorType::UnwrapFailure.into()),
    })
}

pub fn native_unwrap_or_ret(input: Value, thrown: Value) -> Result<Value> {
    inner_unwrap(input).and_then(|opt_value| match opt_value {
        Some(v) => Ok(v),
        None => Err(ShortReturnType::ExpectedValue(thrown).into()),
    })
}

pub fn native_unwrap_err(input: Value) -> Result<Value> {
    inner_unwrap_err(input).and_then(|opt_value| match opt_value {
        Some(v) => Ok(v),
        None => Err(RuntimeErrorType::UnwrapFailure.into()),
    })
}

pub fn native_unwrap_err_or_ret(input: Value, thrown: Value) -> Result<Value> {
    inner_unwrap_err(input).and_then(|opt_value| match opt_value {
        Some(v) => Ok(v),
        None => Err(ShortReturnType::ExpectedValue(thrown).into()),
    })
}

pub fn native_try_ret(input: Value) -> Result<Value> {
    match input {
        Value::Optional(data) => match data.data {
            Some(data) => Ok(*data),
            None => Err(ShortReturnType::ExpectedValue(Value::none()).into()),
        },
        Value::Response(data) => {
            if data.committed {
                Ok(*data.data)
            } else {
                let short_return_val = Value::error(*data.data).map_err(|_| {
                    InterpreterError::Expect(
                        "BUG: Failed to construct new response type from old response type".into(),
                    )
                })?;
                Err(ShortReturnType::ExpectedValue(short_return_val).into())
            }
        }
        _ => Err(CheckErrors::ExpectedOptionalOrResponseValue(input).into()),
    }
}

fn eval_with_new_binding(
    body: &SymbolicExpression,
    bind_name: ClarityName,
    bind_value: Value,
    env: &mut Environment,
    context: &LocalContext,
) -> Result<Value> {
    let mut inner_context = context.extend()?;
    if vm::is_reserved(&bind_name, env.contract_context.get_clarity_version())
        || env.contract_context.lookup_function(&bind_name).is_some()
        || inner_context.lookup_variable(&bind_name).is_some()
    {
        return Err(CheckErrors::NameAlreadyUsed(bind_name.into()).into());
    }

    let memory_use = bind_value.get_memory_use()?;
    env.add_memory(memory_use)?;

    if *env.contract_context.get_clarity_version() >= ClarityVersion::Clarity2 {
        if let CallableContract(trait_data) = &bind_value {
            inner_context.callable_contracts.insert(
                bind_name.clone(),
                CallableData {
                    contract_identifier: trait_data.contract_identifier.clone(),
                    trait_identifier: trait_data.trait_identifier.clone(),
                },
            );
        }
    }
    inner_context.variables.insert(bind_name, bind_value);
    let result = vm::eval(body, env, &inner_context);

    env.drop_memory(memory_use)?;

    result
}

fn special_match_opt(
    input: OptionalData,
    args: &[SymbolicExpression],
    env: &mut Environment,
    context: &LocalContext,
) -> Result<Value> {
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

    match input.data {
        Some(data) => eval_with_new_binding(some_branch, bind_name, *data, env, context),
        None => vm::eval(none_branch, env, context),
    }
}

fn special_match_resp(
    input: ResponseData,
    args: &[SymbolicExpression],
    env: &mut Environment,
    context: &LocalContext,
) -> Result<Value> {
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

    if input.committed {
        eval_with_new_binding(ok_branch, ok_bind_name, *input.data, env, context)
    } else {
        eval_with_new_binding(err_branch, err_bind_name, *input.data, env, context)
    }
}

pub fn special_match(
    args: &[SymbolicExpression],
    env: &mut Environment,
    context: &LocalContext,
) -> Result<Value> {
    check_arguments_at_least(1, args)?;

    let input = vm::eval(&args[0], env, context)?;

    runtime_cost(ClarityCostFunction::Match, env, 0)?;

    match input {
        Value::Response(data) => special_match_resp(data, &args[1..], env, context),
        Value::Optional(data) => special_match_opt(data, &args[1..], env, context),
        _ => Err(CheckErrors::BadMatchInput(TypeSignature::type_of(&input)?).into()),
    }
}

pub fn native_some(input: Value) -> Result<Value> {
    Value::some(input)
}

fn is_some(input: Value) -> Result<bool> {
    match input {
        Value::Optional(ref data) => Ok(data.data.is_some()),
        _ => Err(CheckErrors::ExpectedOptionalValue(input).into()),
    }
}

fn is_okay(input: Value) -> Result<bool> {
    match input {
        Value::Response(data) => Ok(data.committed),
        _ => Err(CheckErrors::ExpectedResponseValue(input).into()),
    }
}

pub fn native_is_some(input: Value) -> Result<Value> {
    is_some(input).map(Value::Bool)
}

pub fn native_is_none(input: Value) -> Result<Value> {
    is_some(input).map(|is_some| Value::Bool(!is_some))
}

pub fn native_is_okay(input: Value) -> Result<Value> {
    is_okay(input).map(Value::Bool)
}

pub fn native_is_err(input: Value) -> Result<Value> {
    is_okay(input).map(|is_ok| Value::Bool(!is_ok))
}

pub fn native_okay(input: Value) -> Result<Value> {
    Value::okay(input)
}

pub fn native_error(input: Value) -> Result<Value> {
    Value::error(input)
}

pub fn native_default_to(default: Value, input: Value) -> Result<Value> {
    match input {
        Value::Optional(data) => match data.data {
            Some(data) => Ok(*data),
            None => Ok(default),
        },
        _ => Err(CheckErrors::ExpectedOptionalValue(input).into()),
    }
}
