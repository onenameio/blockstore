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

use crate::vm::costs::cost_functions::ClarityCostFunction;
use crate::vm::costs::runtime_cost;
use crate::vm::errors::{
    check_argument_count, check_arguments_at_least, CheckErrors, InterpreterError,
    InterpreterResult as Result,
};
use crate::vm::representations::SymbolicExpression;
use crate::vm::types::{TupleData, TypeSignature, Value};
use crate::vm::{eval, Environment, LocalContext};

pub fn tuple_cons(
    args: &[SymbolicExpression],
    env: &mut Environment,
    context: &LocalContext,
) -> Result<Value> {
    //    (tuple (arg-name value)
    //           (arg-name value))
    use super::parse_eval_bindings;

    check_arguments_at_least(1, args)?;

    let bindings = parse_eval_bindings(args, env, context)?;
    runtime_cost(ClarityCostFunction::TupleCons, env, bindings.len())?;

    TupleData::from_data(bindings).map(Value::from)
}

pub fn tuple_get(
    args: &[SymbolicExpression],
    env: &mut Environment,
    context: &LocalContext,
) -> Result<Value> {
    // (get arg-name (tuple ...))
    //    if the tuple argument is an option type, then return option(field-name).
    check_argument_count(2, args)?;

    let arg_name = args[0].match_atom().ok_or(CheckErrors::ExpectedName)?;

    let value = eval(&args[1], env, context)?;

    match value {
        Value::Optional(opt_data) => {
            match opt_data.data {
                Some(data) => {
                    if let Value::Tuple(tuple_data) = *data {
                        runtime_cost(ClarityCostFunction::TupleGet, env, tuple_data.len())?;
                        Ok(Value::some(tuple_data.get_owned(arg_name)?).map_err(|_| {
                            InterpreterError::Expect(
                                "Tuple contents should *always* fit in a some wrapper".into(),
                            )
                        })?)
                    } else {
                        Err(CheckErrors::ExpectedTuple(TypeSignature::type_of(&data)?).into())
                    }
                }
                None => Ok(Value::none()), // just pass through none-types.
            }
        }
        Value::Tuple(tuple_data) => {
            runtime_cost(ClarityCostFunction::TupleGet, env, tuple_data.len())?;
            tuple_data.get_owned(arg_name)
        }
        _ => Err(CheckErrors::ExpectedTuple(TypeSignature::type_of(&value)?).into()),
    }
}

pub fn tuple_merge(base: Value, update: Value) -> Result<Value> {
    let initial_values = match base {
        Value::Tuple(initial_values) => Ok(initial_values),
        _ => Err(CheckErrors::ExpectedTuple(TypeSignature::type_of(&base)?)),
    }?;

    let new_values = match update {
        Value::Tuple(new_values) => Ok(new_values),
        _ => Err(CheckErrors::ExpectedTuple(TypeSignature::type_of(&update)?)),
    }?;

    let combined = TupleData::shallow_merge(initial_values, new_values)?;
    Ok(Value::Tuple(combined))
}
