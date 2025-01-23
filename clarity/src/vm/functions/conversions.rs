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

use crate::vm::costs::cost_functions::ClarityCostFunction;
use crate::vm::costs::runtime_cost;
use crate::vm::errors::{
    check_argument_count, CheckErrors, InterpreterError, InterpreterResult as Result,
};
use crate::vm::representations::SymbolicExpression;
use crate::vm::types::SequenceSubtype::BufferType;
use crate::vm::types::TypeSignature::SequenceType;
use crate::vm::types::{
    ASCIIData, BufferLength, CharType, SequenceData, TypeSignature, UTF8Data, Value,
};
use crate::vm::{eval, Environment, LocalContext};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum EndianDirection {
    LittleEndian,
    BigEndian,
}

// The functions in this file support conversion from (buff 16) to either 1) int or 2) uint,
// from formats 1) big-endian and 2) little-endian.
//
// The function 'buff_to_int_generic' describes the logic common to these four functions.
// This is a generic function for conversion from a buffer to an int or uint. The four
// versions of Clarity function each call this, with different values for 'conversion_fn'.
//
// This function checks and parses the arguments, and calls 'conversion_fn' to do
// the specific form of conversion required.
pub fn buff_to_int_generic(
    value: Value,
    direction: EndianDirection,
    conversion_fn: fn([u8; 16]) -> Value,
) -> Result<Value> {
    match value {
        Value::Sequence(SequenceData::Buffer(ref sequence_data)) => {
            if sequence_data.len()?
                > BufferLength::try_from(16_u32)
                    .map_err(|_| InterpreterError::Expect("Failed to construct".into()))?
            {
                Err(CheckErrors::TypeValueError(
                    SequenceType(BufferType(BufferLength::try_from(16_u32).map_err(
                        |_| InterpreterError::Expect("Failed to construct".into()),
                    )?)),
                    value,
                )
                .into())
            } else {
                let mut transfer_buffer = [0u8; 16];
                let original_slice = sequence_data.as_slice();
                // 'conversion_fn' expects to receive a 16-byte buffer. If the input is little-endian, it should
                // be zero-padded on the right. If the input is big-endian, it should be zero-padded on the left.
                let offset = if direction == EndianDirection::LittleEndian {
                    0
                } else {
                    transfer_buffer.len() - original_slice.len()
                };
                for (from_index, _) in original_slice.iter().enumerate() {
                    let to_index = from_index + offset;
                    transfer_buffer[to_index] = original_slice[from_index];
                }
                let value = conversion_fn(transfer_buffer);
                Ok(value)
            }
        }
        _ => Err(CheckErrors::TypeValueError(
            SequenceType(BufferType(BufferLength::try_from(16_u32).map_err(
                |_| InterpreterError::Expect("Failed to construct".into()),
            )?)),
            value,
        )
        .into()),
    }
}

pub fn native_buff_to_int_le(value: Value) -> Result<Value> {
    fn convert_to_int_le(buffer: [u8; 16]) -> Value {
        let value = i128::from_le_bytes(buffer);
        Value::Int(value)
    }
    buff_to_int_generic(value, EndianDirection::LittleEndian, convert_to_int_le)
}

pub fn native_buff_to_uint_le(value: Value) -> Result<Value> {
    fn convert_to_uint_le(buffer: [u8; 16]) -> Value {
        let value = u128::from_le_bytes(buffer);
        Value::UInt(value)
    }

    buff_to_int_generic(value, EndianDirection::LittleEndian, convert_to_uint_le)
}

pub fn native_buff_to_int_be(value: Value) -> Result<Value> {
    fn convert_to_int_be(buffer: [u8; 16]) -> Value {
        let value = i128::from_be_bytes(buffer);
        Value::Int(value)
    }
    buff_to_int_generic(value, EndianDirection::BigEndian, convert_to_int_be)
}

pub fn native_buff_to_uint_be(value: Value) -> Result<Value> {
    fn convert_to_uint_be(buffer: [u8; 16]) -> Value {
        let value = u128::from_be_bytes(buffer);
        Value::UInt(value)
    }
    buff_to_int_generic(value, EndianDirection::BigEndian, convert_to_uint_be)
}

// This method represents the unified logic between both "string to int" and "string to uint".
// 'value' is the input value to be converted.
// 'string_to_value_fn' is a function that takes in a Rust-langauge string, and should output
//   either a Int or UInt, depending on the desired result.
pub fn native_string_to_int_generic(
    value: Value,
    string_to_value_fn: fn(String) -> Result<Value>,
) -> Result<Value> {
    match value {
        Value::Sequence(SequenceData::String(CharType::ASCII(ASCIIData { data }))) => {
            match String::from_utf8(data) {
                Ok(as_string) => string_to_value_fn(as_string),
                Err(_error) => Ok(Value::none()),
            }
        }
        Value::Sequence(SequenceData::String(CharType::UTF8(UTF8Data { data }))) => {
            let flattened_bytes = data.into_iter().flatten().collect();
            match String::from_utf8(flattened_bytes) {
                Ok(as_string) => string_to_value_fn(as_string),
                Err(_error) => Ok(Value::none()),
            }
        }
        _ => Err(CheckErrors::UnionTypeValueError(
            vec![
                TypeSignature::max_string_ascii()?,
                TypeSignature::max_string_utf8()?,
            ],
            value,
        )
        .into()),
    }
}

fn safe_convert_string_to_int(raw_string: String) -> Result<Value> {
    let possible_int = raw_string.parse::<i128>();
    match possible_int {
        Ok(val) => Value::some(Value::Int(val)),
        Err(_error) => Ok(Value::none()),
    }
}

pub fn native_string_to_int(value: Value) -> Result<Value> {
    native_string_to_int_generic(value, safe_convert_string_to_int)
}

fn safe_convert_string_to_uint(raw_string: String) -> Result<Value> {
    let possible_int = raw_string.parse::<u128>();
    match possible_int {
        Ok(val) => Value::some(Value::UInt(val)),
        Err(_error) => Ok(Value::none()),
    }
}

pub fn native_string_to_uint(value: Value) -> Result<Value> {
    native_string_to_int_generic(value, safe_convert_string_to_uint)
}

// This method represents the unified logic between both "int to ascii" and "int to utf8".
// 'value' is the input value to be converted.
// 'bytes_to_value_fn' is a function that takes in a Rust-langauge byte sequence, and outputs
//   either an ASCII or UTF8 string, depending on the desired result.
pub fn native_int_to_string_generic(
    value: Value,
    bytes_to_value_fn: fn(bytes: Vec<u8>) -> Result<Value>,
) -> Result<Value> {
    match value {
        Value::Int(ref int_value) => {
            let as_string = int_value.to_string();
            Ok(bytes_to_value_fn(as_string.into()).map_err(|_| {
                InterpreterError::Expect("Unexpected error converting Int to string.".into())
            })?)
        }
        Value::UInt(ref uint_value) => {
            let as_string = uint_value.to_string();
            Ok(bytes_to_value_fn(as_string.into()).map_err(|_| {
                InterpreterError::Expect("Unexpected error converting UInt to string.".into())
            })?)
        }
        _ => Err(CheckErrors::UnionTypeValueError(
            vec![TypeSignature::IntType, TypeSignature::UIntType],
            value,
        )
        .into()),
    }
}

pub fn native_int_to_ascii(value: Value) -> Result<Value> {
    // Given a string representing an integer, convert this to Clarity ASCII value.
    native_int_to_string_generic(value, Value::string_ascii_from_bytes)
}

pub fn native_int_to_utf8(value: Value) -> Result<Value> {
    // Given a string representing an integer, convert this to Clarity UTF8 value.
    native_int_to_string_generic(value, Value::string_utf8_from_bytes)
}

/// Returns `value` consensus serialized into a `(optional buff)` object.
/// If the value cannot fit as serialized into the maximum buffer size,
/// this returns `none`, otherwise, it will be `(some consensus-serialized-buffer)`
pub fn to_consensus_buff(value: Value) -> Result<Value> {
    let mut clar_buff_serialized = vec![];
    value
        .serialize_write(&mut clar_buff_serialized)
        .map_err(|_| InterpreterError::Expect("FATAL: failed to serialize to vec".into()))?;

    let clar_buff_serialized = match Value::buff_from(clar_buff_serialized) {
        Ok(x) => x,
        Err(_) => return Ok(Value::none()),
    };

    match Value::some(clar_buff_serialized) {
        Ok(x) => Ok(x),
        Err(_) => Ok(Value::none()),
    }
}

/// Deserialize a Clarity value from a consensus serialized buffer.
/// If the supplied buffer either fails to deserialize or deserializes
/// to an unexpected type, returns `none`. Otherwise, it will be `(some value)`
pub fn from_consensus_buff(
    args: &[SymbolicExpression],
    env: &mut Environment,
    context: &LocalContext,
) -> Result<Value> {
    check_argument_count(2, args)?;

    let type_arg = TypeSignature::parse_type_repr(*env.epoch(), &args[0], env)?;
    let value = eval(&args[1], env, context)?;

    // get the buffer bytes from the supplied value. if not passed a buffer,
    // this is a type error
    let input_bytes = if let Value::Sequence(SequenceData::Buffer(buff_data)) = value {
        Ok(buff_data.data)
    } else {
        Err(CheckErrors::TypeValueError(
            TypeSignature::max_buffer()?,
            value,
        ))
    }?;

    runtime_cost(
        ClarityCostFunction::FromConsensusBuff,
        env,
        input_bytes.len(),
    )?;

    // Perform the deserialization and check that it deserialized to the expected
    // type. A type mismatch at this point is an error that should be surfaced in
    // Clarity (as a none return).
    let result = match Value::try_deserialize_bytes_exact(
        &input_bytes,
        &type_arg,
        env.epoch().value_sanitizing(),
    ) {
        Ok(value) => value,
        Err(_) => return Ok(Value::none()),
    };
    if !type_arg.admits(env.epoch(), &result)? {
        return Ok(Value::none());
    }

    Value::some(result)
}
