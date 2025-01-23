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

use std::cmp;

use integer_sqrt::IntegerSquareRoot;

use crate::vm::costs::cost_functions::ClarityCostFunction;
use crate::vm::costs::runtime_cost;
use crate::vm::errors::{
    check_argument_count, CheckErrors, InterpreterError, InterpreterResult, RuntimeErrorType,
};
use crate::vm::representations::SymbolicExpression;
use crate::vm::types::{
    ASCIIData, BuffData, CharType, SequenceData, TypeSignature, UTF8Data, Value,
};
use crate::vm::version::ClarityVersion;
use crate::vm::{eval, Environment, LocalContext};

struct U128Ops();
struct I128Ops();
struct ASCIIOps();
struct UTF8Ops();
struct BuffOps();

impl U128Ops {
    fn make_value(x: u128) -> InterpreterResult<Value> {
        Ok(Value::UInt(x))
    }
}

impl I128Ops {
    fn make_value(x: i128) -> InterpreterResult<Value> {
        Ok(Value::Int(x))
    }
}
impl ASCIIOps {
    fn make_value(x: Vec<u8>) -> InterpreterResult<Value> {
        Ok(Value::Sequence(SequenceData::String(CharType::ASCII(
            ASCIIData { data: x },
        ))))
    }
}
impl UTF8Ops {
    fn make_value(x: Vec<Vec<u8>>) -> InterpreterResult<Value> {
        Ok(Value::Sequence(SequenceData::String(CharType::UTF8(
            UTF8Data { data: x },
        ))))
    }
}

impl BuffOps {
    fn make_value(x: Vec<u8>) -> InterpreterResult<Value> {
        Ok(Value::Sequence(SequenceData::Buffer(BuffData { data: x })))
    }
}

// This macro checks the type of the required two arguments and then dispatches the evaluation
//   to the correct arithmetic type handler (after deconstructing the Clarity Values into
//   the corresponding Rust integer type.
macro_rules! type_force_binary_arithmetic {
    ($function: ident, $x: expr, $y: expr) => {{
        match ($x, $y) {
            (Value::Int(x), Value::Int(y)) => I128Ops::$function(x, y),
            (Value::UInt(x), Value::UInt(y)) => U128Ops::$function(x, y),
            (x, _) => Err(CheckErrors::UnionTypeValueError(
                vec![TypeSignature::IntType, TypeSignature::UIntType],
                x,
            )
            .into()),
        }
    }};
}

// The originally supported comparable types in Clarity1 were Int and UInt.
macro_rules! type_force_binary_comparison_v1 {
    ($function: ident, $x: expr, $y: expr) => {{
        match ($x, $y) {
            (Value::Int(x), Value::Int(y)) => I128Ops::$function(x, y),
            (Value::UInt(x), Value::UInt(y)) => U128Ops::$function(x, y),
            (x, _) => Err(CheckErrors::UnionTypeValueError(
                vec![TypeSignature::IntType, TypeSignature::UIntType],
                x,
            )
            .into()),
        }
    }};
}

// Clarity2 adds supported comparable types ASCII, UTF8 and Buffer. These are only
// accessed if the ClarityVersion, as read by the SpecialFunction, is >= 2.
macro_rules! type_force_binary_comparison_v2 {
    ($function: ident, $x: expr, $y: expr) => {{
        match ($x, $y) {
            (Value::Int(x), Value::Int(y)) => I128Ops::$function(x, y),
            (Value::UInt(x), Value::UInt(y)) => U128Ops::$function(x, y),
            (
                Value::Sequence(SequenceData::String(CharType::ASCII(ASCIIData { data: x }))),
                Value::Sequence(SequenceData::String(CharType::ASCII(ASCIIData { data: y }))),
            ) => ASCIIOps::$function(x, y),
            (
                Value::Sequence(SequenceData::String(CharType::UTF8(UTF8Data { data: x }))),
                Value::Sequence(SequenceData::String(CharType::UTF8(UTF8Data { data: y }))),
            ) => UTF8Ops::$function(x, y),
            (
                Value::Sequence(SequenceData::Buffer(BuffData { data: x })),
                Value::Sequence(SequenceData::Buffer(BuffData { data: y })),
            ) => BuffOps::$function(x, y),
            (x, _) => Err(CheckErrors::UnionTypeValueError(
                vec![
                    TypeSignature::IntType,
                    TypeSignature::UIntType,
                    TypeSignature::max_string_ascii()?,
                    TypeSignature::max_string_utf8()?,
                    TypeSignature::max_buffer()?,
                ],
                x,
            )
            .into()),
        }
    }};
}

macro_rules! type_force_unary_arithmetic {
    ($function: ident, $x: expr) => {{
        match $x {
            Value::Int(x) => I128Ops::$function(x),
            Value::UInt(x) => U128Ops::$function(x),
            x => Err(CheckErrors::UnionTypeValueError(
                vec![TypeSignature::IntType, TypeSignature::UIntType],
                x,
            )
            .into()),
        }
    }};
}

// This macro checks the type of the first argument and then dispatches the evaluation
//   to the correct arithmetic type handler (after deconstructing the Clarity Values into
//   the corresponding Rust integer type.
macro_rules! type_force_variadic_arithmetic {
    ($function: ident, $args: expr) => {{
        let first = $args
            .get(0)
            .ok_or(CheckErrors::IncorrectArgumentCount(1, $args.len()))?;
        match first {
            Value::Int(_) => {
                let typed_args: Result<Vec<_>, _> = $args
                    .drain(..)
                    .map(|x| match x {
                        Value::Int(value) => Ok(value),
                        _ => Err(CheckErrors::TypeValueError(
                            TypeSignature::IntType,
                            x.clone(),
                        )),
                    })
                    .collect();
                let checked_args = typed_args?;
                I128Ops::$function(&checked_args)
            }
            Value::UInt(_) => {
                let typed_args: Result<Vec<_>, _> = $args
                    .drain(..)
                    .map(|x| match x {
                        Value::UInt(value) => Ok(value),
                        _ => Err(CheckErrors::TypeValueError(
                            TypeSignature::UIntType,
                            x.clone(),
                        )),
                    })
                    .collect();
                let checked_args = typed_args?;
                U128Ops::$function(&checked_args)
            }
            _ => Err(CheckErrors::UnionTypeValueError(
                vec![TypeSignature::IntType, TypeSignature::UIntType],
                first.clone(),
            )
            .into()),
        }
    }};
}

// This macro creates comparison operation functions for the supported types:
// uint, int, string-ascii, string-utf8 and buff.
macro_rules! make_comparison_ops {
    ($struct_name: ident, $type:ty) => {
        impl $struct_name {
            fn greater(x: $type, y: $type) -> InterpreterResult<Value> {
                Ok(Value::Bool(x > y))
            }
            fn less(x: $type, y: $type) -> InterpreterResult<Value> {
                Ok(Value::Bool(x < y))
            }
            fn leq(x: $type, y: $type) -> InterpreterResult<Value> {
                Ok(Value::Bool(x <= y))
            }
            fn geq(x: $type, y: $type) -> InterpreterResult<Value> {
                Ok(Value::Bool(x >= y))
            }
        }
    };
}

// This macro creates all of the operation functions for the two arithmetic types
//  (uint128 and int128) -- this is really hard to do generically because there's no
//  "Integer" trait in rust, so macros were the most straight-forward solution to do this
//  without a bunch of code duplication
macro_rules! make_arithmetic_ops {
    ($struct_name: ident, $type:ty) => {
        impl $struct_name {
            fn xor(x: $type, y: $type) -> InterpreterResult<Value> {
                Self::make_value(x ^ y)
            }
            fn bitwise_xor2(args: &[$type]) -> InterpreterResult<Value> {
                let result = args.iter().fold(0, |acc: $type, x: &$type| (acc ^ x));
                Self::make_value(result)
            }
            fn bitwise_and(args: &[$type]) -> InterpreterResult<Value> {
                let first: $type = args[0];
                let result = args
                    .iter()
                    .skip(1)
                    .fold(first, |acc: $type, x: &$type| (acc & x));
                Self::make_value(result)
            }
            fn bitwise_or(args: &[$type]) -> InterpreterResult<Value> {
                let result = args.iter().fold(0, |acc: $type, x: &$type| (acc | x));
                Self::make_value(result)
            }
            fn bitwise_not(x: $type) -> InterpreterResult<Value> {
                Self::make_value(!x)
            }
            fn add(args: &[$type]) -> InterpreterResult<Value> {
                let result = args
                    .iter()
                    .try_fold(0, |acc: $type, x: &$type| acc.checked_add(*x))
                    .ok_or(RuntimeErrorType::ArithmeticOverflow)?;
                Self::make_value(result)
            }
            fn sub(args: &[$type]) -> InterpreterResult<Value> {
                let (first, rest) = args
                    .split_first()
                    .ok_or(CheckErrors::IncorrectArgumentCount(1, 0))?;
                if rest.len() == 0 {
                    // return negation
                    return Self::make_value(
                        first
                            .checked_neg()
                            .ok_or(RuntimeErrorType::ArithmeticUnderflow)?,
                    );
                }

                let result = rest
                    .iter()
                    .try_fold(*first, |acc: $type, x: &$type| acc.checked_sub(*x))
                    .ok_or(RuntimeErrorType::ArithmeticUnderflow)?;
                Self::make_value(result)
            }
            fn mul(args: &[$type]) -> InterpreterResult<Value> {
                let result = args
                    .iter()
                    .try_fold(1, |acc: $type, x: &$type| acc.checked_mul(*x))
                    .ok_or(RuntimeErrorType::ArithmeticOverflow)?;
                Self::make_value(result)
            }
            fn div(args: &[$type]) -> InterpreterResult<Value> {
                let (first, rest) = args
                    .split_first()
                    .ok_or(CheckErrors::IncorrectArgumentCount(1, 0))?;
                let result = rest
                    .iter()
                    .try_fold(*first, |acc: $type, x: &$type| acc.checked_div(*x))
                    .ok_or(RuntimeErrorType::DivisionByZero)?;
                Self::make_value(result)
            }
            fn modulo(numerator: $type, denominator: $type) -> InterpreterResult<Value> {
                let result = numerator
                    .checked_rem(denominator)
                    .ok_or(RuntimeErrorType::DivisionByZero)?;
                Self::make_value(result)
            }
            #[allow(unused_comparisons)]
            fn pow(base: $type, power: $type) -> InterpreterResult<Value> {
                if base == 0 && power == 0 {
                    // Note that 0⁰ (pow(0, 0)) returns 1. Mathematically this is undefined (https://docs.rs/num-traits/0.2.10/num_traits/pow/fn.pow.html)
                    return Self::make_value(1);
                }
                if base == 1 {
                    return Self::make_value(1);
                }

                if base == 0 {
                    return Self::make_value(0);
                }

                if power == 1 {
                    return Self::make_value(base);
                }

                if power < 0 || power > (u32::MAX as $type) {
                    return Err(RuntimeErrorType::Arithmetic(
                        "Power argument to (pow ...) must be a u32 integer".to_string(),
                    )
                    .into());
                }

                let power_u32 = power as u32;

                let result = base
                    .checked_pow(power_u32)
                    .ok_or(RuntimeErrorType::ArithmeticOverflow)?;
                Self::make_value(result)
            }
            fn sqrti(n: $type) -> InterpreterResult<Value> {
                match n.integer_sqrt_checked() {
                    Some(result) => Self::make_value(result),
                    None => {
                        return Err(RuntimeErrorType::Arithmetic(
                            "sqrti must be passed a positive integer".to_string(),
                        )
                        .into())
                    }
                }
            }
            fn log2(n: $type) -> InterpreterResult<Value> {
                if n < 1 {
                    return Err(RuntimeErrorType::Arithmetic(
                        "log2 must be passed a positive integer".to_string(),
                    )
                    .into());
                }
                let size = std::mem::size_of::<$type>() as u32;
                Self::make_value((size * 8 - 1 - n.leading_zeros()) as $type)
            }
        }
    };
}

make_arithmetic_ops!(U128Ops, u128);
make_arithmetic_ops!(I128Ops, i128);

make_comparison_ops!(U128Ops, u128);
make_comparison_ops!(I128Ops, i128);
make_comparison_ops!(ASCIIOps, Vec<u8>);
make_comparison_ops!(UTF8Ops, Vec<Vec<u8>>);
make_comparison_ops!(BuffOps, Vec<u8>);

// Used for the `xor` function.
pub fn native_xor(a: Value, b: Value) -> InterpreterResult<Value> {
    type_force_binary_arithmetic!(xor, a, b)
}

// Used for the `^` xor function.
pub fn native_bitwise_xor(mut args: Vec<Value>) -> InterpreterResult<Value> {
    type_force_variadic_arithmetic!(bitwise_xor2, args)
}

pub fn native_bitwise_and(mut args: Vec<Value>) -> InterpreterResult<Value> {
    type_force_variadic_arithmetic!(bitwise_and, args)
}

pub fn native_bitwise_or(mut args: Vec<Value>) -> InterpreterResult<Value> {
    type_force_variadic_arithmetic!(bitwise_or, args)
}

pub fn native_bitwise_not(a: Value) -> InterpreterResult<Value> {
    type_force_unary_arithmetic!(bitwise_not, a)
}

// This function is 'special', because it must access the context to determine
// the clarity version.
fn special_geq_v1(
    args: &[SymbolicExpression],
    env: &mut Environment,
    context: &LocalContext,
) -> InterpreterResult<Value> {
    check_argument_count(2, args)?;
    let a = eval(&args[0], env, context)?;
    let b = eval(&args[1], env, context)?;
    runtime_cost(ClarityCostFunction::Geq, env, args.len())?;
    type_force_binary_comparison_v1!(geq, a, b)
}

// This function is 'special', because it must access the context to determine
// the clarity version.
fn special_geq_v2(
    args: &[SymbolicExpression],
    env: &mut Environment,
    context: &LocalContext,
) -> InterpreterResult<Value> {
    check_argument_count(2, args)?;
    let a = eval(&args[0], env, context)?;
    let b = eval(&args[1], env, context)?;
    runtime_cost(
        ClarityCostFunction::Geq,
        env,
        cmp::min(a.size()?, b.size()?),
    )?;
    type_force_binary_comparison_v2!(geq, a, b)
}

// This function is 'special', because it must access the context to determine
// the clarity version.
pub fn special_geq(
    args: &[SymbolicExpression],
    env: &mut Environment,
    context: &LocalContext,
) -> InterpreterResult<Value> {
    if *env.contract_context.get_clarity_version() >= ClarityVersion::Clarity2 {
        special_geq_v2(args, env, context)
    } else {
        special_geq_v1(args, env, context)
    }
}

// This function is 'special', because it must access the context to determine
// the clarity version.
// 2.05 and earlier
fn special_leq_v1(
    args: &[SymbolicExpression],
    env: &mut Environment,
    context: &LocalContext,
) -> InterpreterResult<Value> {
    check_argument_count(2, args)?;
    let a = eval(&args[0], env, context)?;
    let b = eval(&args[1], env, context)?;
    runtime_cost(ClarityCostFunction::Leq, env, args.len())?;
    type_force_binary_comparison_v1!(leq, a, b)
}

// This function is 'special', because it must access the context to determine
// the clarity version.
fn special_leq_v2(
    args: &[SymbolicExpression],
    env: &mut Environment,
    context: &LocalContext,
) -> InterpreterResult<Value> {
    check_argument_count(2, args)?;
    let a = eval(&args[0], env, context)?;
    let b = eval(&args[1], env, context)?;
    runtime_cost(
        ClarityCostFunction::Leq,
        env,
        cmp::min(a.size()?, b.size()?),
    )?;
    type_force_binary_comparison_v2!(leq, a, b)
}

// This function is 'special', because it must access the context to determine
// the clarity version.
pub fn special_leq(
    args: &[SymbolicExpression],
    env: &mut Environment,
    context: &LocalContext,
) -> InterpreterResult<Value> {
    if *env.contract_context.get_clarity_version() >= ClarityVersion::Clarity2 {
        special_leq_v2(args, env, context)
    } else {
        special_leq_v1(args, env, context)
    }
}

// This function is 'special', because it must access the context to determine
// the clarity version.
fn special_greater_v1(
    args: &[SymbolicExpression],
    env: &mut Environment,
    context: &LocalContext,
) -> InterpreterResult<Value> {
    check_argument_count(2, args)?;
    let a = eval(&args[0], env, context)?;
    let b = eval(&args[1], env, context)?;
    runtime_cost(ClarityCostFunction::Ge, env, args.len())?;
    type_force_binary_comparison_v1!(greater, a, b)
}

// This function is 'special', because it must access the context to determine
// the clarity version.
fn special_greater_v2(
    args: &[SymbolicExpression],
    env: &mut Environment,
    context: &LocalContext,
) -> InterpreterResult<Value> {
    check_argument_count(2, args)?;
    let a = eval(&args[0], env, context)?;
    let b = eval(&args[1], env, context)?;
    runtime_cost(ClarityCostFunction::Ge, env, cmp::min(a.size()?, b.size()?))?;
    type_force_binary_comparison_v2!(greater, a, b)
}

// This function is 'special', because it must access the context to determine
// the clarity version.
pub fn special_greater(
    args: &[SymbolicExpression],
    env: &mut Environment,
    context: &LocalContext,
) -> InterpreterResult<Value> {
    if *env.contract_context.get_clarity_version() >= ClarityVersion::Clarity2 {
        special_greater_v2(args, env, context)
    } else {
        special_greater_v1(args, env, context)
    }
}

// This function is 'special', because it must access the context to determine
// the clarity version.
fn special_less_v1(
    args: &[SymbolicExpression],
    env: &mut Environment,
    context: &LocalContext,
) -> InterpreterResult<Value> {
    check_argument_count(2, args)?;
    let a = eval(&args[0], env, context)?;
    let b = eval(&args[1], env, context)?;
    runtime_cost(ClarityCostFunction::Le, env, args.len())?;
    type_force_binary_comparison_v1!(less, a, b)
}

// This function is 'special', because it must access the context to determine
// the clarity version.
fn special_less_v2(
    args: &[SymbolicExpression],
    env: &mut Environment,
    context: &LocalContext,
) -> InterpreterResult<Value> {
    check_argument_count(2, args)?;
    let a = eval(&args[0], env, context)?;
    let b = eval(&args[1], env, context)?;
    runtime_cost(ClarityCostFunction::Le, env, cmp::min(a.size()?, b.size()?))?;
    type_force_binary_comparison_v2!(less, a, b)
}

// This function is 'special', because it must access the context to determine
// the clarity version.
pub fn special_less(
    args: &[SymbolicExpression],
    env: &mut Environment,
    context: &LocalContext,
) -> InterpreterResult<Value> {
    if *env.contract_context.get_clarity_version() >= ClarityVersion::Clarity2 {
        special_less_v2(args, env, context)
    } else {
        special_less_v1(args, env, context)
    }
}

pub fn native_add(mut args: Vec<Value>) -> InterpreterResult<Value> {
    type_force_variadic_arithmetic!(add, args)
}
pub fn native_sub(mut args: Vec<Value>) -> InterpreterResult<Value> {
    type_force_variadic_arithmetic!(sub, args)
}
pub fn native_mul(mut args: Vec<Value>) -> InterpreterResult<Value> {
    type_force_variadic_arithmetic!(mul, args)
}
pub fn native_div(mut args: Vec<Value>) -> InterpreterResult<Value> {
    type_force_variadic_arithmetic!(div, args)
}
pub fn native_pow(a: Value, b: Value) -> InterpreterResult<Value> {
    type_force_binary_arithmetic!(pow, a, b)
}
pub fn native_sqrti(n: Value) -> InterpreterResult<Value> {
    type_force_unary_arithmetic!(sqrti, n)
}
pub fn native_log2(n: Value) -> InterpreterResult<Value> {
    type_force_unary_arithmetic!(log2, n)
}
pub fn native_mod(a: Value, b: Value) -> InterpreterResult<Value> {
    type_force_binary_arithmetic!(modulo, a, b)
}

pub fn native_bitwise_left_shift(input: Value, pos: Value) -> InterpreterResult<Value> {
    if let Value::UInt(u128_val) = pos {
        let shamt = u32::try_from(u128_val & 0x7f).map_err(|_| {
            InterpreterError::Expect("FATAL: lower 32 bits did not convert to u32".into())
        })?;

        match input {
            Value::Int(input) => {
                let result = input.wrapping_shl(shamt);
                Ok(Value::Int(result))
            }
            Value::UInt(input) => {
                let result = input.wrapping_shl(shamt);
                Ok(Value::UInt(result))
            }
            _ => Err(CheckErrors::UnionTypeError(
                vec![TypeSignature::IntType, TypeSignature::UIntType],
                TypeSignature::type_of(&input)?,
            )
            .into()),
        }
    } else {
        Err(CheckErrors::TypeValueError(TypeSignature::UIntType, pos).into())
    }
}

pub fn native_bitwise_right_shift(input: Value, pos: Value) -> InterpreterResult<Value> {
    if let Value::UInt(u128_val) = pos {
        let shamt = u32::try_from(u128_val & 0x7f).map_err(|_| {
            InterpreterError::Expect("FATAL: lower 32 bits did not convert to u32".into())
        })?;

        match input {
            Value::Int(input) => {
                let result = input.wrapping_shr(shamt);
                Ok(Value::Int(result))
            }
            Value::UInt(input) => {
                let result = input.wrapping_shr(shamt);
                Ok(Value::UInt(result))
            }
            _ => Err(CheckErrors::UnionTypeError(
                vec![TypeSignature::IntType, TypeSignature::UIntType],
                TypeSignature::type_of(&input)?,
            )
            .into()),
        }
    } else {
        Err(CheckErrors::TypeValueError(TypeSignature::UIntType, pos).into())
    }
}

pub fn native_to_uint(input: Value) -> InterpreterResult<Value> {
    if let Value::Int(int_val) = input {
        let uint_val =
            u128::try_from(int_val).map_err(|_| RuntimeErrorType::ArithmeticUnderflow)?;
        Ok(Value::UInt(uint_val))
    } else {
        Err(CheckErrors::TypeValueError(TypeSignature::IntType, input).into())
    }
}

pub fn native_to_int(input: Value) -> InterpreterResult<Value> {
    if let Value::UInt(uint_val) = input {
        let int_val = i128::try_from(uint_val).map_err(|_| RuntimeErrorType::ArithmeticOverflow)?;
        Ok(Value::Int(int_val))
    } else {
        Err(CheckErrors::TypeValueError(TypeSignature::UIntType, input).into())
    }
}
