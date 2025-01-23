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

use std::io::{Read, Write};
use std::{cmp, error, str};

use lazy_static::lazy_static;
use stacks_common::codec::{Error as codec_error, StacksMessageCodec};
use stacks_common::types::StacksEpochId;
use stacks_common::util::hash::{hex_bytes, to_hex};
use stacks_common::util::retry::BoundReader;

use super::{ListTypeData, TupleTypeSignature};
use crate::vm::database::{ClarityDeserializable, ClaritySerializable};
use crate::vm::errors::{CheckErrors, Error as ClarityError, IncomparableError, InterpreterError};
use crate::vm::representations::{ClarityName, ContractName, MAX_STRING_LEN};
use crate::vm::types::{
    BufferLength, CallableData, CharType, OptionalData, PrincipalData, QualifiedContractIdentifier,
    SequenceData, SequenceSubtype, StandardPrincipalData, StringSubtype, TupleData, TypeSignature,
    Value, BOUND_VALUE_SERIALIZATION_BYTES, MAX_TYPE_DEPTH, MAX_VALUE_SIZE,
};

/// Errors that may occur in serialization or deserialization
/// If deserialization failed because the described type is a bad type and
///   a CheckError is thrown, it gets wrapped in BadTypeError.
/// Any IOErrrors from the supplied buffer will manifest as IOError variants,
///   except for EOF -- if the deserialization code experiences an EOF, it is caught
///   and rethrown as DeserializationError
#[derive(Debug, PartialEq)]
pub enum SerializationError {
    IOError(IncomparableError<std::io::Error>),
    BadTypeError(CheckErrors),
    DeserializationError(String),
    DeserializeExpected(TypeSignature),
    LeftoverBytesInDeserialization,
    SerializationError(String),
}

lazy_static! {
    pub static ref NONE_SERIALIZATION_LEN: u64 = {
        #[allow(clippy::unwrap_used)]
        u64::try_from(Value::none().serialize_to_vec().unwrap().len()).unwrap()
    };
}

/// Deserialization uses a specific epoch for passing to the type signature checks
/// The reason this is pinned to Epoch21 is so that values stored before epoch-2.4
///  can still be read from the database.
const DESERIALIZATION_TYPE_CHECK_EPOCH: StacksEpochId = StacksEpochId::Epoch21;

/// Pre-sanitization values could end up being larger than the deserializer originally
///  supported, so we increase the bound to a higher level limit imposed by the cost checker.
const SANITIZATION_READ_BOUND: u64 = 15_000_000;

/// Before epoch-2.4, this is the deserialization depth limit.
/// After epoch-2.4, with type sanitization support, the full
///  clarity depth limit is supported.
const UNSANITIZED_DEPTH_CHECK: usize = 16;

impl std::fmt::Display for SerializationError {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            SerializationError::IOError(e) => {
                write!(f, "Serialization error caused by IO: {}", e.err)
            }
            SerializationError::BadTypeError(e) => {
                write!(f, "Deserialization error, bad type, caused by: {}", e)
            }
            SerializationError::DeserializationError(e) => {
                write!(f, "Deserialization error: {}", e)
            }
            SerializationError::SerializationError(e) => {
                write!(f, "Serialization error: {}", e)
            }
            SerializationError::DeserializeExpected(e) => write!(
                f,
                "Deserialization expected the type of the input to be: {}",
                e
            ),
            SerializationError::LeftoverBytesInDeserialization => {
                write!(f, "Deserialization error: bytes left over in buffer")
            }
        }
    }
}

impl error::Error for SerializationError {
    fn source(&self) -> Option<&(dyn error::Error + 'static)> {
        match self {
            SerializationError::IOError(e) => Some(&e.err),
            SerializationError::BadTypeError(e) => Some(e),
            _ => None,
        }
    }
}

// Note: a byte stream that describes a longer type than
//   there are available bytes to read will result in an IOError(UnexpectedEOF)
impl From<std::io::Error> for SerializationError {
    fn from(err: std::io::Error) -> Self {
        SerializationError::IOError(IncomparableError { err })
    }
}

impl From<&str> for SerializationError {
    fn from(e: &str) -> Self {
        SerializationError::DeserializationError(e.into())
    }
}

impl From<CheckErrors> for SerializationError {
    fn from(e: CheckErrors) -> Self {
        SerializationError::BadTypeError(e)
    }
}

define_u8_enum!(TypePrefix {
    Int = 0,
    UInt = 1,
    Buffer = 2,
    BoolTrue = 3,
    BoolFalse = 4,
    PrincipalStandard = 5,
    PrincipalContract = 6,
    ResponseOk = 7,
    ResponseErr = 8,
    OptionalNone = 9,
    OptionalSome = 10,
    List = 11,
    Tuple = 12,
    StringASCII = 13,
    StringUTF8 = 14
});

impl From<&PrincipalData> for TypePrefix {
    fn from(v: &PrincipalData) -> TypePrefix {
        use super::PrincipalData::*;
        match v {
            Standard(_) => TypePrefix::PrincipalStandard,
            Contract(_) => TypePrefix::PrincipalContract,
        }
    }
}

impl From<&Value> for TypePrefix {
    fn from(v: &Value) -> TypePrefix {
        use super::CharType;
        use super::SequenceData::*;
        use super::Value::*;

        match v {
            Int(_) => TypePrefix::Int,
            UInt(_) => TypePrefix::UInt,
            Bool(value) => {
                if *value {
                    TypePrefix::BoolTrue
                } else {
                    TypePrefix::BoolFalse
                }
            }
            Principal(p) => TypePrefix::from(p),
            Response(response) => {
                if response.committed {
                    TypePrefix::ResponseOk
                } else {
                    TypePrefix::ResponseErr
                }
            }
            Optional(OptionalData { data: None }) => TypePrefix::OptionalNone,
            Optional(OptionalData { data: Some(_) }) => TypePrefix::OptionalSome,
            Tuple(_) => TypePrefix::Tuple,
            Sequence(Buffer(_)) => TypePrefix::Buffer,
            Sequence(List(_)) => TypePrefix::List,
            Sequence(String(CharType::ASCII(_))) => TypePrefix::StringASCII,
            Sequence(String(CharType::UTF8(_))) => TypePrefix::StringUTF8,
            &CallableContract(_) => TypePrefix::PrincipalContract,
        }
    }
}

/// Not a public trait,
///   this is just used to simplify serializing some types that
///   are repeatedly serialized or deserialized.
trait ClarityValueSerializable<T: std::marker::Sized> {
    fn serialize_write<W: Write>(&self, w: &mut W) -> std::io::Result<()>;
    fn deserialize_read<R: Read>(r: &mut R) -> Result<T, SerializationError>;
}

impl ClarityValueSerializable<StandardPrincipalData> for StandardPrincipalData {
    fn serialize_write<W: Write>(&self, w: &mut W) -> std::io::Result<()> {
        w.write_all(&[self.0])?;
        w.write_all(&self.1)
    }

    fn deserialize_read<R: Read>(r: &mut R) -> Result<Self, SerializationError> {
        let mut version = [0; 1];
        let mut data = [0; 20];
        r.read_exact(&mut version)?;
        r.read_exact(&mut data)?;
        Ok(StandardPrincipalData(version[0], data))
    }
}

macro_rules! serialize_guarded_string {
    ($Name:ident) => {
        impl ClarityValueSerializable<$Name> for $Name {
            fn serialize_write<W: Write>(&self, w: &mut W) -> std::io::Result<()> {
                w.write_all(&self.len().to_be_bytes())?;
                // self.as_bytes() is always len bytes, because this is only used for GuardedStrings
                //   which are a subset of ASCII
                w.write_all(self.as_str().as_bytes())
            }

            fn deserialize_read<R: Read>(r: &mut R) -> Result<Self, SerializationError> {
                let mut len = [0; 1];
                r.read_exact(&mut len)?;
                let len = u8::from_be_bytes(len);
                if len > MAX_STRING_LEN {
                    return Err(SerializationError::DeserializationError(
                        "String too long".to_string(),
                    ));
                }

                let mut data = vec![0; len as usize];
                r.read_exact(&mut data)?;

                String::from_utf8(data)
                    .map_err(|_| "Non-UTF8 string data".into())
                    .and_then(|x| $Name::try_from(x).map_err(|_| "Illegal Clarity string".into()))
            }
        }
    };
}

serialize_guarded_string!(ClarityName);
serialize_guarded_string!(ContractName);

impl PrincipalData {
    fn inner_consensus_serialize<W: Write>(&self, w: &mut W) -> std::io::Result<()> {
        w.write_all(&[TypePrefix::from(self) as u8])?;
        match self {
            PrincipalData::Standard(p) => p.serialize_write(w),
            PrincipalData::Contract(contract_identifier) => {
                contract_identifier.issuer.serialize_write(w)?;
                contract_identifier.name.serialize_write(w)
            }
        }
    }

    fn inner_consensus_deserialize<R: Read>(
        r: &mut R,
    ) -> Result<PrincipalData, SerializationError> {
        let mut header = [0];
        r.read_exact(&mut header)?;

        let prefix = TypePrefix::from_u8(header[0]).ok_or("Bad principal prefix")?;

        match prefix {
            TypePrefix::PrincipalStandard => {
                StandardPrincipalData::deserialize_read(r).map(PrincipalData::from)
            }
            TypePrefix::PrincipalContract => {
                let issuer = StandardPrincipalData::deserialize_read(r)?;
                let name = ContractName::deserialize_read(r)?;
                Ok(PrincipalData::from(QualifiedContractIdentifier {
                    issuer,
                    name,
                }))
            }
            _ => Err("Bad principal prefix".into()),
        }
    }
}

impl StacksMessageCodec for PrincipalData {
    fn consensus_serialize<W: Write>(&self, fd: &mut W) -> Result<(), codec_error> {
        self.inner_consensus_serialize(fd)
            .map_err(codec_error::WriteError)
    }

    fn consensus_deserialize<R: Read>(fd: &mut R) -> Result<PrincipalData, codec_error> {
        PrincipalData::inner_consensus_deserialize(fd)
            .map_err(|e| codec_error::DeserializeError(e.to_string()))
    }
}

macro_rules! check_match {
    ($item:expr, $Pattern:pat) => {
        match $item {
            None => Ok(()),
            Some($Pattern) => Ok(()),
            Some(x) => Err(SerializationError::DeserializeExpected(x.clone())),
        }
    };
}

/// `DeserializeStackItem` objects are used by the deserializer to indicate
///  how the deserialization loop's current object is to be handled once it is
///  deserialized: i.e., is the object the top-level object for the serialization
///  or is it an entry in a composite type (e.g., a list or tuple)?
enum DeserializeStackItem {
    List {
        items: Vec<Value>,
        expected_len: u32,
        expected_type: Option<ListTypeData>,
    },
    Tuple {
        items: Vec<(ClarityName, Value)>,
        expected_len: u64,
        processed_entries: u64,
        expected_type: Option<TupleTypeSignature>,
        next_name: ClarityName,
        next_sanitize: bool,
    },
    OptionSome {
        inner_expected_type: Option<TypeSignature>,
    },
    ResponseOk {
        inner_expected_type: Option<TypeSignature>,
    },
    ResponseErr {
        inner_expected_type: Option<TypeSignature>,
    },
    TopLevel {
        expected_type: Option<TypeSignature>,
    },
}

impl DeserializeStackItem {
    /// What is the expected type for the child of this deserialization stack item?
    ///
    /// Returns `None` if this stack item either doesn't have an expected type, or the
    ///   next child is going to be sanitized/elided.
    fn next_expected_type(&self) -> Result<Option<TypeSignature>, SerializationError> {
        match self {
            DeserializeStackItem::List { expected_type, .. } => Ok(expected_type
                .as_ref()
                .map(|lt| lt.get_list_item_type())
                .cloned()),
            DeserializeStackItem::Tuple {
                expected_type,
                next_name,
                next_sanitize,
                ..
            } => match expected_type {
                None => Ok(None),
                Some(some_tuple) => {
                    // if we're sanitizing this tuple, and the `next_name` field is to be
                    //  removed, don't return an expected type.
                    if *next_sanitize {
                        return Ok(None);
                    }
                    let field_type = some_tuple.field_type(next_name).ok_or_else(|| {
                        SerializationError::DeserializeExpected(TypeSignature::TupleType(
                            some_tuple.clone(),
                        ))
                    })?;
                    Ok(Some(field_type.clone()))
                }
            },
            DeserializeStackItem::OptionSome {
                inner_expected_type,
            } => Ok(inner_expected_type.clone()),
            DeserializeStackItem::ResponseOk {
                inner_expected_type,
            } => Ok(inner_expected_type.clone()),
            DeserializeStackItem::ResponseErr {
                inner_expected_type,
            } => Ok(inner_expected_type.clone()),
            DeserializeStackItem::TopLevel { expected_type } => Ok(expected_type.clone()),
        }
    }
}

impl TypeSignature {
    /// Return the maximum length of the consensus serialization of a
    /// Clarity value of this type. The returned length *may* not fit
    /// in a Clarity buffer! For example, the maximum serialized
    /// size of a `(buff 1024*1024)` is `1+1024*1024` because of the
    /// type prefix byte. However, that is 1 byte larger than the maximum
    /// buffer size in Clarity.
    pub fn max_serialized_size(&self) -> Result<u32, CheckErrors> {
        let type_prefix_size = 1;

        let max_output_size = match self {
            TypeSignature::NoType => {
                // A `NoType` should *never* actually be evaluated
                // (`NoType` corresponds to the Some branch of a
                // `none` that is never matched with a corresponding
                // `some` or similar with `result` types).  So, when
                // serializing an object with a `NoType`, the other
                // branch should always be used.
                return Err(CheckErrors::CouldNotDetermineSerializationType);
            }
            TypeSignature::IntType => 16,
            TypeSignature::UIntType => 16,
            TypeSignature::BoolType => 0,
            TypeSignature::SequenceType(SequenceSubtype::ListType(list_type)) => {
                // u32 length as big-endian bytes
                let list_length_encode = 4;
                list_type
                    .get_max_len()
                    .checked_mul(list_type.get_list_item_type().max_serialized_size()?)
                    .and_then(|x| x.checked_add(list_length_encode))
                    .ok_or_else(|| CheckErrors::ValueTooLarge)?
            }
            TypeSignature::SequenceType(SequenceSubtype::BufferType(buff_length)) => {
                // u32 length as big-endian bytes
                let buff_length_encode = 4;
                u32::from(buff_length)
                    .checked_add(buff_length_encode)
                    .ok_or_else(|| CheckErrors::ValueTooLarge)?
            }
            TypeSignature::SequenceType(SequenceSubtype::StringType(StringSubtype::ASCII(
                length,
            ))) => {
                // u32 length as big-endian bytes
                let str_length_encode = 4;
                // ascii is 1-byte per character
                u32::from(length)
                    .checked_add(str_length_encode)
                    .ok_or_else(|| CheckErrors::ValueTooLarge)?
            }
            TypeSignature::SequenceType(SequenceSubtype::StringType(StringSubtype::UTF8(
                length,
            ))) => {
                // u32 length as big-endian bytes
                let str_length_encode = 4;
                // utf-8 is maximum 4 bytes per codepoint (which is the length)
                u32::from(length)
                    .checked_mul(4)
                    .and_then(|x| x.checked_add(str_length_encode))
                    .ok_or_else(|| CheckErrors::ValueTooLarge)?
            }
            TypeSignature::PrincipalType
            | TypeSignature::CallableType(_)
            | TypeSignature::TraitReferenceType(_) => {
                // version byte + 20 byte hash160
                let maximum_issuer_size = 21;
                let contract_name_length_encode = 1;
                // contract name maximum length is `MAX_STRING_LEN` (128), and ASCII
                let maximum_contract_name = MAX_STRING_LEN as u32;
                maximum_contract_name + maximum_issuer_size + contract_name_length_encode
            }
            TypeSignature::TupleType(tuple_type) => {
                let type_map = tuple_type.get_type_map();
                // u32 length as big-endian bytes
                let tuple_length_encode: u32 = 4;
                let mut total_size = tuple_length_encode;
                for (key, value) in type_map.iter() {
                    let value_size = value.max_serialized_size()?;
                    total_size = total_size
                        .checked_add(1) // length of key-name
                        .and_then(|x| x.checked_add(key.len() as u32)) // ClarityName is ascii-only, so 1 byte per length
                        .and_then(|x| x.checked_add(value_size))
                        .ok_or_else(|| CheckErrors::ValueTooLarge)?;
                }
                total_size
            }
            TypeSignature::OptionalType(ref some_type) => {
                match some_type.max_serialized_size() {
                    Ok(size) => size,
                    // if NoType, then this is just serializing a none
                    // value, which is only the type prefix
                    Err(CheckErrors::CouldNotDetermineSerializationType) => 0,
                    Err(e) => return Err(e),
                }
            }
            TypeSignature::ResponseType(ref response_types) => {
                let (ok_type, err_type) = response_types.as_ref();
                let (ok_type_max_size, no_ok_type) = match ok_type.max_serialized_size() {
                    Ok(size) => (size, false),
                    Err(CheckErrors::CouldNotDetermineSerializationType) => (0, true),
                    Err(e) => return Err(e),
                };
                let err_type_max_size = match err_type.max_serialized_size() {
                    Ok(size) => size,
                    Err(CheckErrors::CouldNotDetermineSerializationType) => {
                        if no_ok_type {
                            // if both the ok type and the error type are NoType,
                            //  throw a CheckError. This should not be possible, but the check
                            //  is done out of caution.
                            return Err(CheckErrors::CouldNotDetermineSerializationType);
                        } else {
                            0
                        }
                    }
                    Err(e) => return Err(e),
                };
                cmp::max(ok_type_max_size, err_type_max_size)
            }
            TypeSignature::ListUnionType(_) => {
                return Err(CheckErrors::CouldNotDetermineSerializationType)
            }
        };

        max_output_size
            .checked_add(type_prefix_size)
            .ok_or_else(|| CheckErrors::ValueTooLarge)
    }
}

impl Value {
    pub fn deserialize_read<R: Read>(
        r: &mut R,
        expected_type: Option<&TypeSignature>,
        sanitize: bool,
    ) -> Result<Value, SerializationError> {
        Self::deserialize_read_count(r, expected_type, sanitize).map(|(value, _)| value)
    }

    /// Deserialize just like `deserialize_read` but also
    ///  return the bytes read.
    /// If `sanitize` argument is set to true and `expected_type` is supplied,
    ///  this method will remove any extraneous tuple fields which may have been
    ///  allowed by `least_super_type`.
    pub fn deserialize_read_count<R: Read>(
        r: &mut R,
        expected_type: Option<&TypeSignature>,
        sanitize: bool,
    ) -> Result<(Value, u64), SerializationError> {
        let bound_value_serialization_bytes = if sanitize && expected_type.is_some() {
            SANITIZATION_READ_BOUND
        } else {
            BOUND_VALUE_SERIALIZATION_BYTES as u64
        };
        let mut bound_reader = BoundReader::from_reader(r, bound_value_serialization_bytes);
        let value = Value::inner_deserialize_read(&mut bound_reader, expected_type, sanitize)?;
        let bytes_read = bound_reader.num_read();
        if let Some(expected_type) = expected_type {
            let expect_size = match expected_type.max_serialized_size() {
                Ok(x) => x,
                Err(e) => {
                    debug!(
                        "Failed to determine max serialized size when checking expected_type argument";
                        "err" => ?e
                    );
                    return Ok((value, bytes_read));
                }
            };

            if bytes_read > expect_size as u64 {
                // this can happen due to sanitization, so its no longer indicative of a *problem* with the node.
                debug!(
                    "Deserialized more bytes than expected size during deserialization. Expected size = {}, bytes read = {}, type = {}",
                    expect_size,
                    bytes_read,
                    expected_type,
                );
            }
        }

        Ok((value, bytes_read))
    }

    fn inner_deserialize_read<R: Read>(
        r: &mut R,
        top_expected_type: Option<&TypeSignature>,
        sanitize: bool,
    ) -> Result<Value, SerializationError> {
        use super::Value::*;

        let mut stack = vec![DeserializeStackItem::TopLevel {
            expected_type: top_expected_type.cloned(),
        }];

        while !stack.is_empty() {
            let depth_check = if sanitize {
                MAX_TYPE_DEPTH as usize
            } else {
                UNSANITIZED_DEPTH_CHECK
            };
            if stack.len() > depth_check {
                return Err(CheckErrors::TypeSignatureTooDeep.into());
            }

            #[allow(clippy::expect_used)]
            let expected_type = stack
                .last()
                .expect("FATAL: stack.last() should always be some() because of loop condition")
                .next_expected_type()?;

            let mut header = [0];
            r.read_exact(&mut header)?;
            let prefix = TypePrefix::from_u8(header[0]).ok_or("Bad type prefix")?;

            let item = match prefix {
                TypePrefix::Int => {
                    check_match!(expected_type, TypeSignature::IntType)?;
                    let mut buffer = [0; 16];
                    r.read_exact(&mut buffer)?;
                    Ok(Int(i128::from_be_bytes(buffer)))
                }
                TypePrefix::UInt => {
                    check_match!(expected_type, TypeSignature::UIntType)?;
                    let mut buffer = [0; 16];
                    r.read_exact(&mut buffer)?;
                    Ok(UInt(u128::from_be_bytes(buffer)))
                }
                TypePrefix::Buffer => {
                    let mut buffer_len = [0; 4];
                    r.read_exact(&mut buffer_len)?;
                    let buffer_len = BufferLength::try_from(u32::from_be_bytes(buffer_len))?;

                    if let Some(x) = &expected_type {
                        let passed_test = match x {
                            TypeSignature::SequenceType(SequenceSubtype::BufferType(
                                expected_len,
                            )) => u32::from(&buffer_len) <= u32::from(expected_len),
                            _ => false,
                        };
                        if !passed_test {
                            return Err(SerializationError::DeserializeExpected(x.clone()));
                        }
                    }

                    let mut data = vec![0; u32::from(buffer_len) as usize];

                    r.read_exact(&mut data[..])?;

                    Value::buff_from(data).map_err(|_| "Bad buffer".into())
                }
                TypePrefix::BoolTrue => {
                    check_match!(expected_type, TypeSignature::BoolType)?;
                    Ok(Bool(true))
                }
                TypePrefix::BoolFalse => {
                    check_match!(expected_type, TypeSignature::BoolType)?;
                    Ok(Bool(false))
                }
                TypePrefix::PrincipalStandard => {
                    check_match!(expected_type, TypeSignature::PrincipalType)?;
                    StandardPrincipalData::deserialize_read(r).map(Value::from)
                }
                TypePrefix::PrincipalContract => {
                    check_match!(expected_type, TypeSignature::PrincipalType)?;
                    let issuer = StandardPrincipalData::deserialize_read(r)?;
                    let name = ContractName::deserialize_read(r)?;
                    Ok(Value::from(QualifiedContractIdentifier { issuer, name }))
                }
                TypePrefix::ResponseOk | TypePrefix::ResponseErr => {
                    let committed = prefix == TypePrefix::ResponseOk;

                    let expect_contained_type = match &expected_type {
                        None => None,
                        Some(x) => {
                            let contained_type = match (committed, x) {
                                (true, TypeSignature::ResponseType(types)) => Ok(&types.0),
                                (false, TypeSignature::ResponseType(types)) => Ok(&types.1),
                                _ => Err(SerializationError::DeserializeExpected(x.clone())),
                            }?;
                            Some(contained_type)
                        }
                    };

                    let stack_item = if committed {
                        DeserializeStackItem::ResponseOk {
                            inner_expected_type: expect_contained_type.cloned(),
                        }
                    } else {
                        DeserializeStackItem::ResponseErr {
                            inner_expected_type: expect_contained_type.cloned(),
                        }
                    };

                    stack.push(stack_item);
                    continue;
                }
                TypePrefix::OptionalNone => {
                    check_match!(expected_type, TypeSignature::OptionalType(_))?;
                    Ok(Value::none())
                }
                TypePrefix::OptionalSome => {
                    let expect_contained_type = match &expected_type {
                        None => None,
                        Some(x) => {
                            let contained_type = match x {
                                TypeSignature::OptionalType(some_type) => Ok(some_type.as_ref()),
                                _ => Err(SerializationError::DeserializeExpected(x.clone())),
                            }?;
                            Some(contained_type)
                        }
                    };

                    let stack_item = DeserializeStackItem::OptionSome {
                        inner_expected_type: expect_contained_type.cloned(),
                    };

                    stack.push(stack_item);
                    continue;
                }
                TypePrefix::List => {
                    let mut len = [0; 4];
                    r.read_exact(&mut len)?;
                    let len = u32::from_be_bytes(len);

                    if len > MAX_VALUE_SIZE {
                        return Err("Illegal list type".into());
                    }

                    let (list_type, _entry_type) = match expected_type.as_ref() {
                        None => (None, None),
                        Some(TypeSignature::SequenceType(SequenceSubtype::ListType(list_type))) => {
                            if len > list_type.get_max_len() {
                                // unwrap is safe because of the match condition
                                #[allow(clippy::unwrap_used)]
                                return Err(SerializationError::DeserializeExpected(
                                    expected_type.unwrap(),
                                ));
                            }
                            (Some(list_type), Some(list_type.get_list_item_type()))
                        }
                        Some(x) => return Err(SerializationError::DeserializeExpected(x.clone())),
                    };

                    if len > 0 {
                        let items = Vec::with_capacity(len as usize);
                        let stack_item = DeserializeStackItem::List {
                            items,
                            expected_len: len,
                            expected_type: list_type.cloned(),
                        };

                        stack.push(stack_item);
                        continue;
                    } else {
                        let finished_list = if let Some(list_type) = list_type {
                            Value::list_with_type(
                                &DESERIALIZATION_TYPE_CHECK_EPOCH,
                                vec![],
                                list_type.clone(),
                            )
                            .map_err(|_| "Illegal list type")?
                        } else {
                            Value::cons_list_unsanitized(vec![]).map_err(|_| "Illegal list type")?
                        };

                        Ok(finished_list)
                    }
                }
                TypePrefix::Tuple => {
                    let mut len = [0; 4];
                    r.read_exact(&mut len)?;
                    let len = u32::from_be_bytes(len);
                    let expected_len = u64::from(len);

                    if len > MAX_VALUE_SIZE {
                        return Err(SerializationError::DeserializationError(
                            "Illegal tuple type".to_string(),
                        ));
                    }

                    let tuple_type = match expected_type.as_ref() {
                        None => None,
                        Some(TypeSignature::TupleType(tuple_type)) => {
                            if sanitize {
                                if u64::from(len) < tuple_type.len() {
                                    // unwrap is safe because of the match condition
                                    #[allow(clippy::unwrap_used)]
                                    return Err(SerializationError::DeserializeExpected(
                                        expected_type.unwrap(),
                                    ));
                                }
                            } else if u64::from(len) != tuple_type.len() {
                                // unwrap is safe because of the match condition
                                #[allow(clippy::unwrap_used)]
                                return Err(SerializationError::DeserializeExpected(
                                    expected_type.unwrap(),
                                ));
                            }
                            Some(tuple_type)
                        }
                        Some(x) => return Err(SerializationError::DeserializeExpected(x.clone())),
                    };

                    if len > 0 {
                        let items = Vec::with_capacity(expected_len as usize);
                        let first_key = ClarityName::deserialize_read(r)?;
                        // figure out if the next (key, value) pair for this
                        //  tuple will be elided (or sanitized) from the tuple.
                        // the logic here is that the next pair should be elided if:
                        //    * `sanitize` parameter is true
                        //    * `tuple_type` is some (i.e., there is an expected type for the
                        //       tuple)
                        //    * `tuple_type` does not contain an entry for `key`
                        let next_sanitize = sanitize
                            && tuple_type
                                .map(|tt| tt.field_type(&first_key).is_none())
                                .unwrap_or(false);
                        let stack_item = DeserializeStackItem::Tuple {
                            items,
                            expected_len,
                            processed_entries: 0,
                            expected_type: tuple_type.cloned(),
                            next_name: first_key,
                            next_sanitize,
                        };

                        stack.push(stack_item);
                        continue;
                    } else {
                        let finished_tuple = if let Some(tuple_type) = tuple_type {
                            TupleData::from_data_typed(
                                &DESERIALIZATION_TYPE_CHECK_EPOCH,
                                vec![],
                                tuple_type,
                            )
                            .map_err(|_| "Illegal tuple type")
                            .map(Value::from)?
                        } else {
                            TupleData::from_data(vec![])
                                .map_err(|_| "Illegal tuple type")
                                .map(Value::from)?
                        };
                        Ok(finished_tuple)
                    }
                }
                TypePrefix::StringASCII => {
                    let mut buffer_len = [0; 4];
                    r.read_exact(&mut buffer_len)?;
                    let buffer_len = BufferLength::try_from(u32::from_be_bytes(buffer_len))?;

                    if let Some(x) = &expected_type {
                        let passed_test = match x {
                            TypeSignature::SequenceType(SequenceSubtype::StringType(
                                StringSubtype::ASCII(expected_len),
                            )) => u32::from(&buffer_len) <= u32::from(expected_len),
                            _ => false,
                        };
                        if !passed_test {
                            return Err(SerializationError::DeserializeExpected(x.clone()));
                        }
                    }

                    let mut data = vec![0; u32::from(buffer_len) as usize];

                    r.read_exact(&mut data[..])?;

                    Value::string_ascii_from_bytes(data).map_err(|_| "Bad string".into())
                }
                TypePrefix::StringUTF8 => {
                    let mut total_len = [0; 4];
                    r.read_exact(&mut total_len)?;
                    let total_len = BufferLength::try_from(u32::from_be_bytes(total_len))?;

                    let mut data: Vec<u8> = vec![0; u32::from(total_len) as usize];

                    r.read_exact(&mut data[..])?;

                    let value = Value::string_utf8_from_bytes(data)
                        .map_err(|_| "Illegal string_utf8 type".into());

                    if let Some(x) = &expected_type {
                        let passed_test = match (x, &value) {
                            (
                                TypeSignature::SequenceType(SequenceSubtype::StringType(
                                    StringSubtype::UTF8(expected_len),
                                )),
                                Ok(Value::Sequence(SequenceData::String(CharType::UTF8(utf8)))),
                            ) => utf8.data.len() as u32 <= u32::from(expected_len),
                            _ => false,
                        };
                        if !passed_test {
                            return Err(SerializationError::DeserializeExpected(x.clone()));
                        }
                    }

                    value
                }
            }?;

            let mut finished_item = Some(item);
            while let Some(item) = finished_item.take() {
                let stack_bottom = if let Some(stack_item) = stack.pop() {
                    stack_item
                } else {
                    // this should be unreachable!
                    warn!(
                        "Deserializer reached unexpected path: item processed, but deserializer stack does not expect another value";
                        "item" => %item,
                    );
                    return Err("Deserializer processed item, but deserializer stack does not expect another value".into());
                };
                match stack_bottom {
                    DeserializeStackItem::TopLevel { .. } => return Ok(item),
                    DeserializeStackItem::List {
                        mut items,
                        expected_len,
                        expected_type,
                    } => {
                        items.push(item);
                        if expected_len as usize <= items.len() {
                            // list is finished!
                            let finished_list = if let Some(list_type) = expected_type {
                                Value::list_with_type(
                                    &DESERIALIZATION_TYPE_CHECK_EPOCH,
                                    items,
                                    list_type.clone(),
                                )
                                .map_err(|_| "Illegal list type")?
                            } else {
                                Value::cons_list_unsanitized(items)
                                    .map_err(|_| "Illegal list type")?
                            };

                            finished_item.replace(finished_list);
                        } else {
                            // list is not finished, reinsert on stack
                            stack.push(DeserializeStackItem::List {
                                items,
                                expected_len,
                                expected_type,
                            });
                        }
                    }
                    DeserializeStackItem::Tuple {
                        mut items,
                        expected_len,
                        expected_type,
                        next_name,
                        next_sanitize,
                        mut processed_entries,
                    } => {
                        let push_entry = if sanitize {
                            if expected_type.is_some() {
                                // if performing tuple sanitization, don't include a field
                                //  if it was sanitized
                                !next_sanitize
                            } else {
                                // always push the entry if there's no type expectation
                                true
                            }
                        } else {
                            true
                        };
                        let tuple_entry = (next_name, item);
                        if push_entry {
                            items.push(tuple_entry);
                        }
                        processed_entries += 1;
                        if expected_len <= processed_entries {
                            // tuple is finished!
                            let finished_tuple = if let Some(tuple_type) = expected_type {
                                if items.len() != tuple_type.len() as usize {
                                    return Err(SerializationError::DeserializeExpected(
                                        TypeSignature::TupleType(tuple_type),
                                    ));
                                }
                                TupleData::from_data_typed(
                                    &DESERIALIZATION_TYPE_CHECK_EPOCH,
                                    items,
                                    &tuple_type,
                                )
                                .map_err(|_| "Illegal tuple type")
                                .map(Value::from)?
                            } else {
                                TupleData::from_data(items)
                                    .map_err(|_| "Illegal tuple type")
                                    .map(Value::from)?
                            };

                            finished_item.replace(finished_tuple);
                        } else {
                            // tuple is not finished, read the next key name and reinsert on stack
                            let key = ClarityName::deserialize_read(r)?;
                            // figure out if the next (key, value) pair for this
                            //  tuple will be elided (or sanitized) from the tuple.
                            // the logic here is that the next pair should be elided if:
                            //    * `sanitize` parameter is true
                            //    * `tuple_type` is some (i.e., there is an expected type for the
                            //       tuple)
                            //    * `tuple_type` does not contain an entry for `key`
                            let next_sanitize = sanitize
                                && expected_type
                                    .as_ref()
                                    .map(|tt| tt.field_type(&key).is_none())
                                    .unwrap_or(false);
                            stack.push(DeserializeStackItem::Tuple {
                                items,
                                expected_type,
                                expected_len,
                                next_name: key,
                                next_sanitize,
                                processed_entries,
                            });
                        }
                    }
                    DeserializeStackItem::OptionSome { .. } => {
                        let finished_some = Value::some(item).map_err(|_x| "Value too large")?;
                        finished_item.replace(finished_some);
                    }
                    DeserializeStackItem::ResponseOk { .. } => {
                        let finished_some = Value::okay(item).map_err(|_x| "Value too large")?;
                        finished_item.replace(finished_some);
                    }
                    DeserializeStackItem::ResponseErr { .. } => {
                        let finished_some = Value::error(item).map_err(|_x| "Value too large")?;
                        finished_item.replace(finished_some);
                    }
                };
            }
        }

        Err(SerializationError::DeserializationError(
            "Invalid data: stack ran out before finishing parsing".into(),
        ))
    }

    pub fn serialize_write<W: Write>(&self, w: &mut W) -> Result<(), SerializationError> {
        use super::CharType::*;
        use super::PrincipalData::*;
        use super::SequenceData::{self, *};
        use super::Value::*;

        w.write_all(&[TypePrefix::from(self) as u8])?;
        match self {
            Int(value) => w.write_all(&value.to_be_bytes())?,
            UInt(value) => w.write_all(&value.to_be_bytes())?,
            Principal(Standard(data)) => data.serialize_write(w)?,
            Principal(Contract(contract_identifier))
            | CallableContract(CallableData {
                contract_identifier,
                trait_identifier: _,
            }) => {
                contract_identifier.issuer.serialize_write(w)?;
                contract_identifier.name.serialize_write(w)?;
            }
            Response(response) => response.data.serialize_write(w)?,
            // Bool types don't need any more data.
            Bool(_) => {}
            // None types don't need any more data.
            Optional(OptionalData { data: None }) => {}
            Optional(OptionalData { data: Some(value) }) => {
                value.serialize_write(w)?;
            }
            Sequence(List(data)) => {
                let len_bytes = data
                    .len()
                    .map_err(|e| SerializationError::SerializationError(e.to_string()))?
                    .to_be_bytes();
                w.write_all(&len_bytes)?;
                for item in data.data.iter() {
                    item.serialize_write(w)?;
                }
            }
            Sequence(Buffer(value)) => {
                let len_bytes = u32::from(
                    value
                        .len()
                        .map_err(|e| SerializationError::SerializationError(e.to_string()))?,
                )
                .to_be_bytes();
                w.write_all(&len_bytes)?;
                w.write_all(&value.data)?
            }
            Sequence(SequenceData::String(UTF8(value))) => {
                let total_len: u32 = value.data.iter().fold(0u32, |len, c| len + c.len() as u32);
                w.write_all(&(total_len.to_be_bytes()))?;
                for bytes in value.data.iter() {
                    w.write_all(bytes)?
                }
            }
            Sequence(SequenceData::String(ASCII(value))) => {
                let len_bytes = u32::from(
                    value
                        .len()
                        .map_err(|e| SerializationError::SerializationError(e.to_string()))?,
                )
                .to_be_bytes();
                w.write_all(&len_bytes)?;
                w.write_all(&value.data)?
            }
            Tuple(data) => {
                let len_bytes = u32::try_from(data.data_map.len())
                    .map_err(|e| SerializationError::SerializationError(e.to_string()))?
                    .to_be_bytes();
                w.write_all(&len_bytes)?;
                for (key, value) in data.data_map.iter() {
                    key.serialize_write(w)?;
                    value.serialize_write(w)?;
                }
            }
        };

        Ok(())
    }

    /// This function attempts to deserialize a byte buffer into a Clarity Value.
    /// The `expected_type` parameter tells the deserializer to expect (and enforce)
    /// a particular type. `ClarityDB` uses this to ensure that lists, tuples, etc. loaded from the database
    /// have their max-length and other type information set by the type declarations in the contract.
    pub fn try_deserialize_bytes(
        bytes: &Vec<u8>,
        expected: &TypeSignature,
        sanitize: bool,
    ) -> Result<Value, SerializationError> {
        Value::deserialize_read(&mut bytes.as_slice(), Some(expected), sanitize)
    }

    /// This function attempts to deserialize a hex string into a Clarity Value.
    /// The `expected_type` parameter tells the deserializer to expect (and enforce)
    /// a particular type. `ClarityDB` uses this to ensure that lists, tuples, etc. loaded from the database
    /// have their max-length and other type information set by the type declarations in the contract.
    pub fn try_deserialize_hex(
        hex: &str,
        expected: &TypeSignature,
        sanitize: bool,
    ) -> Result<Value, SerializationError> {
        let data = hex_bytes(hex).map_err(|_| "Bad hex string")?;
        Value::try_deserialize_bytes(&data, expected, sanitize)
    }

    /// This function attempts to deserialize a byte buffer into a
    /// Clarity Value, while ensuring that the whole byte buffer is
    /// consumed by the deserialization, erroring if it is not. The
    /// `expected_type` parameter tells the deserializer to expect
    /// (and enforce) a particular type. `ClarityDB` uses this to
    /// ensure that lists, tuples, etc. loaded from the database have
    /// their max-length and other type information set by the type
    /// declarations in the contract.
    pub fn try_deserialize_bytes_exact(
        bytes: &Vec<u8>,
        expected: &TypeSignature,
        sanitize: bool,
    ) -> Result<Value, SerializationError> {
        let input_length = bytes.len();
        let (value, read_count) =
            Value::deserialize_read_count(&mut bytes.as_slice(), Some(expected), sanitize)?;
        if read_count != (input_length as u64) {
            Err(SerializationError::LeftoverBytesInDeserialization)
        } else {
            Ok(value)
        }
    }

    /// Try to deserialize a value without type information. This *does not* perform sanitization
    ///  so it should not be used when decoding clarity database values.
    fn try_deserialize_bytes_untyped(bytes: &Vec<u8>) -> Result<Value, SerializationError> {
        Value::deserialize_read(&mut bytes.as_slice(), None, false)
    }

    /// Try to deserialize a value from a hex string without type information. This *does not*
    /// perform sanitization.
    pub fn try_deserialize_hex_untyped(hex: &str) -> Result<Value, SerializationError> {
        let hex = hex.strip_prefix("0x").unwrap_or(hex);
        let data = hex_bytes(hex).map_err(|_| "Bad hex string")?;
        Value::try_deserialize_bytes_untyped(&data)
    }

    pub fn serialized_size(&self) -> Result<u32, SerializationError> {
        let mut counter = WriteCounter { count: 0 };
        self.serialize_write(&mut counter).map_err(|_| {
            SerializationError::DeserializationError(
                "Error: Failed to count serialization length of Clarity value".into(),
            )
        })?;
        Ok(counter.count)
    }
}

/// A writer that just counts the bytes written
struct WriteCounter {
    count: u32,
}

impl Write for WriteCounter {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        let input: u32 = buf.len().try_into().map_err(|_e| {
            std::io::Error::new(
                std::io::ErrorKind::Other,
                "Serialization size would overflow u32",
            )
        })?;
        self.count = self.count.checked_add(input).ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::Other,
                "Serialization size would overflow u32",
            )
        })?;
        Ok(input as usize)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl Value {
    pub fn serialize_to_vec(&self) -> Result<Vec<u8>, InterpreterError> {
        let mut byte_serialization = Vec::new();
        self.serialize_write(&mut byte_serialization)
            .map_err(|_| InterpreterError::Expect("IOError filling byte buffer.".into()))?;
        Ok(byte_serialization)
    }

    /// This does *not* perform any data sanitization
    pub fn serialize_to_hex(&self) -> Result<String, InterpreterError> {
        let byte_serialization = self.serialize_to_vec()?;
        Ok(to_hex(byte_serialization.as_slice()))
    }

    /// Sanitize `value` against pre-2.4 serialization
    ///
    /// Returns Some if the sanitization is successful, or was not necessary.
    /// Returns None if the sanitization failed.
    ///
    /// Returns the sanitized value _and_ whether or not sanitization was required.
    pub fn sanitize_value(
        epoch: &StacksEpochId,
        expected: &TypeSignature,
        value: Value,
    ) -> Option<(Value, bool)> {
        // in epochs before 2.4, perform no sanitization
        if !epoch.value_sanitizing() {
            return Some((value, false));
        }
        let (output, did_sanitize) = match value {
            Value::Sequence(SequenceData::List(l)) => {
                let lt = match expected {
                    TypeSignature::SequenceType(SequenceSubtype::ListType(lt)) => lt,
                    _ => return None,
                };
                // if cannot compute l.len(), sanitization fails, so use ? operator can short return
                if l.len().ok()? > lt.get_max_len() {
                    return None;
                }
                let mut sanitized_items = Vec::with_capacity(l.data.len());
                let mut did_sanitize_children = false;
                for item in l.data.into_iter() {
                    let (sanitized_item, did_sanitize) =
                        Self::sanitize_value(epoch, lt.get_list_item_type(), item)?;
                    sanitized_items.push(sanitized_item);
                    did_sanitize_children = did_sanitize_children || did_sanitize;
                }
                // do not sanitize list before construction here, because we're already sanitizing
                let output_list = Value::cons_list_unsanitized(sanitized_items).ok()?;
                (output_list, did_sanitize_children)
            }
            Value::Tuple(tuple_data) => {
                let tt = match expected {
                    TypeSignature::TupleType(tt) => tt,
                    _ => return None,
                };
                let type_map = tt.get_type_map();
                let mut sanitized_tuple_entries = Vec::with_capacity(type_map.len());
                let original_tuple_len = tuple_data.len();
                let mut tuple_data_map = tuple_data.data_map;
                let mut did_sanitize_children = false;
                for (key, expect_key_type) in type_map.iter() {
                    let field_data = tuple_data_map.remove(key)?;
                    let (sanitized_field, did_sanitize) =
                        Self::sanitize_value(epoch, expect_key_type, field_data)?;
                    sanitized_tuple_entries.push((key.clone(), sanitized_field));
                    did_sanitize_children = did_sanitize_children || did_sanitize;
                }
                if sanitized_tuple_entries.len() as u64 != tt.len() {
                    // this code should be unreachable, because I think any case that
                    //    could trigger this would have returned None earlier
                    warn!("Sanitizer handled path that should have errored earlier, skipping sanitization");
                    return None;
                }
                let did_sanitize_tuple = did_sanitize_children || (tt.len() != original_tuple_len);
                (
                    Value::Tuple(TupleData::from_data(sanitized_tuple_entries).ok()?),
                    did_sanitize_tuple,
                )
            }
            Value::Optional(opt_data) => {
                let inner_type = match expected {
                    TypeSignature::OptionalType(inner_type) => inner_type,
                    _ => return None,
                };
                let some_data = match opt_data.data {
                    Some(data) => *data,
                    None => return Some((Value::none(), false)),
                };
                let (sanitized_data, did_sanitize_child) =
                    Self::sanitize_value(epoch, inner_type, some_data)?;
                (Value::some(sanitized_data).ok()?, did_sanitize_child)
            }
            Value::Response(response) => {
                let rt = match expected {
                    TypeSignature::ResponseType(rt) => rt,
                    _ => return None,
                };

                let response_ok = response.committed;
                let response_data = *response.data;
                let inner_type = if response_ok { &rt.0 } else { &rt.1 };
                let (sanitized_inner, did_sanitize_child) =
                    Self::sanitize_value(epoch, inner_type, response_data)?;
                let sanitized_resp = if response_ok {
                    Value::okay(sanitized_inner)
                } else {
                    Value::error(sanitized_inner)
                };
                (sanitized_resp.ok()?, did_sanitize_child)
            }
            value => {
                if expected.admits(epoch, &value).ok()? {
                    return Some((value, false));
                } else {
                    return None;
                }
            }
        };

        if expected.admits(epoch, &output).ok()? {
            Some((output, did_sanitize))
        } else {
            None
        }
    }
}

impl ClaritySerializable for u32 {
    fn serialize(&self) -> String {
        to_hex(&self.to_be_bytes())
    }
}

impl ClarityDeserializable<u32> for u32 {
    fn deserialize(input: &str) -> Result<Self, ClarityError> {
        let bytes = hex_bytes(input).map_err(|_| {
            InterpreterError::Expect("u32 deserialization: failed decoding bytes.".into())
        })?;
        assert_eq!(bytes.len(), 4);
        Ok(u32::from_be_bytes(bytes[0..4].try_into().map_err(
            |_| InterpreterError::Expect("u32 deserialization: failed reading.".into()),
        )?))
    }
}

/// Note: the StacksMessageCodec implementation for Clarity values *does not*
///       sanitize its serialization or deserialization.
impl StacksMessageCodec for Value {
    fn consensus_serialize<W: Write>(&self, fd: &mut W) -> Result<(), codec_error> {
        self.serialize_write(fd).map_err(|e| match e {
            SerializationError::IOError(io_e) => codec_error::WriteError(io_e.err),
            other => codec_error::SerializeError(other.to_string()),
        })
    }

    fn consensus_deserialize<R: Read>(fd: &mut R) -> Result<Value, codec_error> {
        Value::deserialize_read(fd, None, false).map_err(|e| match e {
            SerializationError::IOError(e) => codec_error::ReadError(e.err),
            _ => codec_error::DeserializeError(format!("Failed to decode clarity value: {:?}", &e)),
        })
    }
}

#[cfg(test)]
pub mod tests {
    use std::io::Write;

    use rstest::rstest;
    use rstest_reuse::{self, *};
    use stacks_common::types::StacksEpochId;

    use super::super::*;
    use super::SerializationError;
    use crate::vm::database::{ClarityDeserializable, ClaritySerializable, RollbackWrapper};
    use crate::vm::tests::test_clarity_versions;
    use crate::vm::ClarityVersion;

    fn buff_type(size: u32) -> TypeSignature {
        TypeSignature::SequenceType(SequenceSubtype::BufferType(size.try_into().unwrap()))
    }

    fn test_deser_ser(v: Value) {
        assert_eq!(
            &v,
            &Value::try_deserialize_hex(
                &v.serialize_to_hex().unwrap(),
                &TypeSignature::type_of(&v).unwrap(),
                false
            )
            .unwrap()
        );
        assert_eq!(
            &v,
            &Value::try_deserialize_hex_untyped(&v.serialize_to_hex().unwrap()).unwrap()
        );
        // test the serialized_size implementation
        assert_eq!(
            v.serialized_size().unwrap(),
            v.serialize_to_hex().unwrap().len() as u32 / 2,
            "serialized_size() should return the byte length of the serialization (half the length of the hex encoding)",
        );
    }

    fn test_deser_u32_helper(num: u32) {
        assert_eq!(num, u32::deserialize(&num.serialize()).unwrap());
    }

    fn test_bad_expectation(v: Value, e: TypeSignature) {
        assert!(matches!(
            Value::try_deserialize_hex(&v.serialize_to_hex().unwrap(), &e, false).unwrap_err(),
            SerializationError::DeserializeExpected(_)
        ));
    }

    #[test]
    fn test_deser_u32() {
        test_deser_u32_helper(0);
        test_deser_u32_helper(10);
        test_deser_u32_helper(42);
        test_deser_u32_helper(10992);
        test_deser_u32_helper(10992);
        test_deser_u32_helper(262144);
        test_deser_u32_helper(134217728);
    }

    #[apply(test_clarity_versions)]
    fn test_lists(#[case] version: ClarityVersion, #[case] epoch: StacksEpochId) {
        let list_list_int = Value::list_from(vec![Value::list_from(vec![
            Value::Int(1),
            Value::Int(2),
            Value::Int(3),
        ])
        .unwrap()])
        .unwrap();

        // Should be legal!
        Value::try_deserialize_hex(
            &Value::list_from(vec![])
                .unwrap()
                .serialize_to_hex()
                .unwrap(),
            &TypeSignature::from_string("(list 2 (list 3 int))", version, epoch),
            false,
        )
        .unwrap();
        Value::try_deserialize_hex(
            &list_list_int.serialize_to_hex().unwrap(),
            &TypeSignature::from_string("(list 2 (list 3 int))", version, epoch),
            false,
        )
        .unwrap();
        Value::try_deserialize_hex(
            &list_list_int.serialize_to_hex().unwrap(),
            &TypeSignature::from_string("(list 1 (list 4 int))", version, epoch),
            false,
        )
        .unwrap();

        test_deser_ser(list_list_int.clone());
        test_deser_ser(Value::list_from(vec![]).unwrap());
        test_bad_expectation(list_list_int.clone(), TypeSignature::BoolType);
        // inner type isn't expected
        test_bad_expectation(
            list_list_int.clone(),
            TypeSignature::from_string("(list 1 (list 4 uint))", version, epoch),
        );
        // child list longer than expected
        test_bad_expectation(
            list_list_int.clone(),
            TypeSignature::from_string("(list 1 (list 2 uint))", version, epoch),
        );
        // parent list longer than expected
        test_bad_expectation(
            list_list_int,
            TypeSignature::from_string("(list 0 (list 2 uint))", version, epoch),
        );

        // make a list too large for the type itself!
        //   this describes a list of size 1+MAX_VALUE_SIZE of Value::Bool(true)'s
        let mut too_big = vec![3u8; 6 + MAX_VALUE_SIZE as usize];
        // list prefix
        too_big[0] = 11;
        // list length
        Write::write_all(
            &mut too_big.get_mut(1..5).unwrap(),
            &(1 + MAX_VALUE_SIZE).to_be_bytes(),
        )
        .unwrap();

        assert_eq!(
            Value::deserialize_read(&mut too_big.as_slice(), None, false).unwrap_err(),
            "Illegal list type".into()
        );

        // make a list that says it is longer than it is!
        //   this describes a list of size MAX_VALUE_SIZE of Value::Bool(true)'s, but is actually only 59 bools.
        let mut eof = vec![3u8; 64_usize];
        // list prefix
        eof[0] = 11;
        // list length
        Write::write_all(
            &mut eof.get_mut(1..5).unwrap(),
            &(MAX_VALUE_SIZE).to_be_bytes(),
        )
        .unwrap();

        /*
         * jude -- this should return an IOError
        assert_eq!(
            Value::deserialize_read(&mut eof.as_slice(), None).unwrap_err(),
            "Unexpected end of byte stream".into());
        */

        match Value::deserialize_read(&mut eof.as_slice(), None, false) {
            Ok(_) => panic!("Accidentally parsed truncated slice"),
            Err(eres) => match eres {
                SerializationError::IOError(ioe) => match ioe.err.kind() {
                    std::io::ErrorKind::UnexpectedEof => {}
                    _ => panic!("Invalid I/O error: {:?}", &ioe),
                },
                _ => panic!("Invalid deserialize error: {:?}", &eres),
            },
        }
    }

    #[test]
    fn test_bools() {
        test_deser_ser(Value::Bool(false));
        test_deser_ser(Value::Bool(true));

        test_bad_expectation(Value::Bool(false), TypeSignature::IntType);
        test_bad_expectation(Value::Bool(true), TypeSignature::IntType);
    }

    #[test]
    fn test_ints() {
        test_deser_ser(Value::Int(0));
        test_deser_ser(Value::Int(1));
        test_deser_ser(Value::Int(-1));
        test_deser_ser(Value::Int(i128::MAX));
        test_deser_ser(Value::Int(i128::MIN));

        test_bad_expectation(Value::Int(1), TypeSignature::UIntType);
    }

    #[test]
    fn test_uints() {
        test_deser_ser(Value::UInt(0));
        test_deser_ser(Value::UInt(1));
        test_deser_ser(Value::UInt(u128::MAX));
        test_deser_ser(Value::UInt(u128::MIN));

        test_bad_expectation(Value::UInt(1), TypeSignature::IntType);
    }

    #[apply(test_clarity_versions)]
    fn test_opts(#[case] version: ClarityVersion, #[case] epoch: StacksEpochId) {
        test_deser_ser(Value::none());
        test_deser_ser(Value::some(Value::Int(15)).unwrap());

        test_bad_expectation(Value::none(), TypeSignature::IntType);
        test_bad_expectation(Value::some(Value::Int(15)).unwrap(), TypeSignature::IntType);
        // bad expected _contained_ type
        test_bad_expectation(
            Value::some(Value::Int(15)).unwrap(),
            TypeSignature::from_string("(optional uint)", version, epoch),
        );
    }

    #[apply(test_clarity_versions)]
    fn test_resp(#[case] version: ClarityVersion, #[case] epoch: StacksEpochId) {
        test_deser_ser(Value::okay(Value::Int(15)).unwrap());
        test_deser_ser(Value::error(Value::Int(15)).unwrap());

        // Bad expected types.
        test_bad_expectation(Value::okay(Value::Int(15)).unwrap(), TypeSignature::IntType);
        test_bad_expectation(
            Value::okay(Value::Int(15)).unwrap(),
            TypeSignature::from_string("(response uint int)", version, epoch),
        );
        test_bad_expectation(
            Value::error(Value::Int(15)).unwrap(),
            TypeSignature::from_string("(response int uint)", version, epoch),
        );
    }

    #[apply(test_clarity_versions)]
    fn test_buffs(#[case] version: ClarityVersion, #[case] epoch: StacksEpochId) {
        test_deser_ser(Value::buff_from(vec![0, 0, 0, 0]).unwrap());
        test_deser_ser(Value::buff_from(vec![0xde, 0xad, 0xbe, 0xef]).unwrap());
        test_deser_ser(Value::buff_from(vec![0, 0xde, 0xad, 0xbe, 0xef, 0]).unwrap());

        test_bad_expectation(
            Value::buff_from(vec![0, 0xde, 0xad, 0xbe, 0xef, 0]).unwrap(),
            TypeSignature::BoolType,
        );

        // fail because we expect a shorter buffer
        test_bad_expectation(
            Value::buff_from(vec![0, 0xde, 0xad, 0xbe, 0xef, 0]).unwrap(),
            TypeSignature::from_string("(buff 2)", version, epoch),
        );
    }

    #[apply(test_clarity_versions)]
    fn test_string_ascii(#[case] version: ClarityVersion, #[case] epoch: StacksEpochId) {
        test_deser_ser(Value::string_ascii_from_bytes(vec![61, 62, 63, 64]).unwrap());

        // fail because we expect a shorter string
        test_bad_expectation(
            Value::string_ascii_from_bytes(vec![61, 62, 63, 64]).unwrap(),
            TypeSignature::from_string("(string-ascii 3)", version, epoch),
        );
    }

    #[apply(test_clarity_versions)]
    fn test_string_utf8(#[case] version: ClarityVersion, #[case] epoch: StacksEpochId) {
        test_deser_ser(Value::string_utf8_from_bytes(vec![61, 62, 63, 64]).unwrap());
        test_deser_ser(
            Value::string_utf8_from_bytes(vec![61, 62, 63, 240, 159, 164, 151]).unwrap(),
        );

        // fail because we expect a shorter string
        test_bad_expectation(
            Value::string_utf8_from_bytes(vec![61, 62, 63, 64]).unwrap(),
            TypeSignature::from_string("(string-utf8 3)", version, epoch),
        );

        test_bad_expectation(
            Value::string_utf8_from_bytes(vec![61, 62, 63, 240, 159, 164, 151]).unwrap(),
            TypeSignature::from_string("(string-utf8 3)", version, epoch),
        );
    }

    #[test]
    fn test_tuples() {
        let t_1 = Value::from(
            TupleData::from_data(vec![
                ("a".into(), Value::Int(1)),
                ("b".into(), Value::Int(1)),
            ])
            .unwrap(),
        );
        let t_0 = Value::from(
            TupleData::from_data(vec![
                ("b".into(), Value::Int(1)),
                ("a".into(), Value::Int(1)),
            ])
            .unwrap(),
        );
        let t_2 = Value::from(
            TupleData::from_data(vec![
                ("a".into(), Value::Int(1)),
                ("b".into(), Value::Bool(true)),
            ])
            .unwrap(),
        );
        let t_3 = Value::from(TupleData::from_data(vec![("a".into(), Value::Int(1))]).unwrap());
        let t_4 = Value::from(
            TupleData::from_data(vec![
                ("a".into(), Value::Int(1)),
                ("c".into(), Value::Bool(true)),
            ])
            .unwrap(),
        );

        test_deser_ser(t_0.clone());
        test_deser_ser(t_1.clone());
        test_deser_ser(t_2.clone());
        test_deser_ser(t_3.clone());

        test_bad_expectation(t_0.clone(), TypeSignature::BoolType);

        // t_0 and t_1 are actually the same
        assert_eq!(
            Value::try_deserialize_hex(
                &t_1.serialize_to_hex().unwrap(),
                &TypeSignature::type_of(&t_0).unwrap(),
                false
            )
            .unwrap(),
            Value::try_deserialize_hex(
                &t_0.serialize_to_hex().unwrap(),
                &TypeSignature::type_of(&t_0).unwrap(),
                false
            )
            .unwrap()
        );

        // field number not equal to expectations
        assert!(matches!(
            Value::try_deserialize_hex(
                &t_3.serialize_to_hex().unwrap(),
                &TypeSignature::type_of(&t_1).unwrap(),
                false
            )
            .unwrap_err(),
            SerializationError::DeserializeExpected(_)
        ));

        // field type mismatch
        assert!(matches!(
            Value::try_deserialize_hex(
                &t_2.serialize_to_hex().unwrap(),
                &TypeSignature::type_of(&t_1).unwrap(),
                false
            )
            .unwrap_err(),
            SerializationError::DeserializeExpected(_)
        ));

        // field not-present in expected
        assert!(matches!(
            Value::try_deserialize_hex(
                &t_1.serialize_to_hex().unwrap(),
                &TypeSignature::type_of(&t_4).unwrap(),
                false
            )
            .unwrap_err(),
            SerializationError::DeserializeExpected(_)
        ));
    }

    #[apply(test_clarity_versions)]
    fn test_sanitization(#[case] version: ClarityVersion, #[case] epoch: StacksEpochId) {
        let v_1 = Value::list_from(vec![
            TupleData::from_data(vec![("b".into(), Value::Int(2))])
                .unwrap()
                .into(),
            TupleData::from_data(vec![
                ("a".into(), Value::Int(1)),
                ("b".into(), Value::Int(4)),
                ("c".into(), Value::Int(3)),
            ])
            .unwrap()
            .into(),
        ])
        .unwrap();
        let v_1_good = Value::list_from(vec![
            TupleData::from_data(vec![("b".into(), Value::Int(2))])
                .unwrap()
                .into(),
            TupleData::from_data(vec![("b".into(), Value::Int(4))])
                .unwrap()
                .into(),
        ])
        .unwrap();

        let t_1_good = TypeSignature::from_string("(list 5 (tuple (b int)))", version, epoch);
        let t_1_bad_0 =
            TypeSignature::from_string("(list 5 (tuple (b int) (a int)))", version, epoch);
        let t_1_bad_1 = TypeSignature::from_string("(list 5 (tuple (b uint)))", version, epoch);

        let v_2 = TupleData::from_data(vec![
            (
                "list-1".into(),
                Value::list_from(vec![
                    TupleData::from_data(vec![("b".into(), Value::Int(2))])
                        .unwrap()
                        .into(),
                    TupleData::from_data(vec![
                        ("a".into(), Value::Int(1)),
                        ("b".into(), Value::Int(4)),
                        ("c".into(), Value::Int(3)),
                    ])
                    .unwrap()
                    .into(),
                ])
                .unwrap(),
            ),
            (
                "list-2".into(),
                Value::list_from(vec![
                    TupleData::from_data(vec![("c".into(), Value::Int(2))])
                        .unwrap()
                        .into(),
                    TupleData::from_data(vec![
                        ("a".into(), Value::Int(1)),
                        ("b".into(), Value::Int(4)),
                        ("c".into(), Value::Int(3)),
                    ])
                    .unwrap()
                    .into(),
                ])
                .unwrap(),
            ),
        ])
        .unwrap()
        .into();

        let v_2_good = TupleData::from_data(vec![
            (
                "list-1".into(),
                Value::list_from(vec![
                    TupleData::from_data(vec![("b".into(), Value::Int(2))])
                        .unwrap()
                        .into(),
                    TupleData::from_data(vec![("b".into(), Value::Int(4))])
                        .unwrap()
                        .into(),
                ])
                .unwrap(),
            ),
            (
                "list-2".into(),
                Value::list_from(vec![
                    TupleData::from_data(vec![("c".into(), Value::Int(2))])
                        .unwrap()
                        .into(),
                    TupleData::from_data(vec![("c".into(), Value::Int(3))])
                        .unwrap()
                        .into(),
                ])
                .unwrap(),
            ),
        ])
        .unwrap()
        .into();

        let t_2_good = TypeSignature::from_string(
            "(tuple (list-2 (list 2 (tuple (c int)))) (list-1 (list 5 (tuple (b int)))))",
            version,
            epoch,
        );
        let t_2_bad_0 = TypeSignature::from_string(
            "(tuple (list-2 (list 2 (tuple (c int)))) (list-1 (list 5 (tuple (a int)))))",
            version,
            epoch,
        );
        let t_2_bad_1 = TypeSignature::from_string(
            "(tuple (list-2 (list 1 (tuple (c int)))) (list-1 (list 5 (tuple (b int)))))",
            version,
            epoch,
        );

        let v_3 = Value::some(
            TupleData::from_data(vec![
                ("a".into(), Value::Int(1)),
                ("b".into(), Value::Int(4)),
                ("c".into(), Value::Int(3)),
            ])
            .unwrap()
            .into(),
        )
        .unwrap();

        let v_3_good = Value::some(
            TupleData::from_data(vec![
                ("a".into(), Value::Int(1)),
                ("b".into(), Value::Int(4)),
            ])
            .unwrap()
            .into(),
        )
        .unwrap();

        let t_3_good =
            TypeSignature::from_string("(optional (tuple (a int) (b int)))", version, epoch);
        let t_3_bad_0 =
            TypeSignature::from_string("(optional (tuple (a uint) (b int)))", version, epoch);
        let t_3_bad_1 =
            TypeSignature::from_string("(optional (tuple (d int) (b int)))", version, epoch);

        let v_4 = Value::list_from(vec![
            TupleData::from_data(vec![("b".into(), Value::some(Value::Int(2)).unwrap())])
                .unwrap()
                .into(),
            TupleData::from_data(vec![
                ("a".into(), Value::some(Value::Int(1)).unwrap()),
                ("b".into(), Value::none()),
                ("c".into(), Value::some(Value::Int(3)).unwrap()),
            ])
            .unwrap()
            .into(),
        ])
        .unwrap();
        let v_4_good = Value::list_from(vec![
            TupleData::from_data(vec![("b".into(), Value::some(Value::Int(2)).unwrap())])
                .unwrap()
                .into(),
            TupleData::from_data(vec![("b".into(), Value::none())])
                .unwrap()
                .into(),
        ])
        .unwrap();

        let t_4_good =
            TypeSignature::from_string("(list 5 (tuple (b (optional int))))", version, epoch);
        let t_4_bad_0 = TypeSignature::from_string(
            "(list 5 (tuple (b (optional int)) (a (optional int))))",
            version,
            epoch,
        );
        let t_4_bad_1 =
            TypeSignature::from_string("(list 5 (tuple (b (optional uint))))", version, epoch);

        let v_5 = Value::okay(
            Value::list_from(vec![
                TupleData::from_data(vec![("b".into(), Value::some(Value::Int(2)).unwrap())])
                    .unwrap()
                    .into(),
                TupleData::from_data(vec![
                    ("a".into(), Value::some(Value::Int(1)).unwrap()),
                    ("b".into(), Value::none()),
                    ("c".into(), Value::some(Value::Int(3)).unwrap()),
                ])
                .unwrap()
                .into(),
            ])
            .unwrap(),
        )
        .unwrap();
        let v_5_good = Value::okay(
            Value::list_from(vec![
                TupleData::from_data(vec![("b".into(), Value::some(Value::Int(2)).unwrap())])
                    .unwrap()
                    .into(),
                TupleData::from_data(vec![("b".into(), Value::none())])
                    .unwrap()
                    .into(),
            ])
            .unwrap(),
        )
        .unwrap();

        let t_5_good_0 = TypeSignature::from_string(
            "(response (list 5 (tuple (b (optional int)))) int)",
            version,
            epoch,
        );
        let t_5_good_1 = TypeSignature::from_string(
            "(response (list 2 (tuple (b (optional int)))) int)",
            version,
            epoch,
        );
        let t_5_good_2 = TypeSignature::from_string(
            "(response (list 2 (tuple (b (optional int)))) bool)",
            version,
            epoch,
        );
        let t_5_bad_0 = TypeSignature::from_string(
            "(response (list 5 (tuple (b (optional int)) (a (optional int)))) uint)",
            version,
            epoch,
        );
        let t_5_bad_1 = TypeSignature::from_string(
            "(response (list 5 (tuple (b (optional uint)))) int)",
            version,
            epoch,
        );
        let t_5_bad_2 = TypeSignature::from_string(
            "(response int (list 5 (tuple (b (optional int)))))",
            version,
            epoch,
        );
        let t_5_bad_3 = TypeSignature::from_string(
            "(list 5 (tuple (b (optional int)) (a (optional int))))",
            version,
            epoch,
        );

        let v_6 = Value::error(
            Value::list_from(vec![
                TupleData::from_data(vec![("b".into(), Value::some(Value::Int(2)).unwrap())])
                    .unwrap()
                    .into(),
                TupleData::from_data(vec![
                    ("a".into(), Value::some(Value::Int(1)).unwrap()),
                    ("b".into(), Value::none()),
                    ("c".into(), Value::some(Value::Int(3)).unwrap()),
                ])
                .unwrap()
                .into(),
            ])
            .unwrap(),
        )
        .unwrap();
        let v_6_good = Value::error(
            Value::list_from(vec![
                TupleData::from_data(vec![("b".into(), Value::some(Value::Int(2)).unwrap())])
                    .unwrap()
                    .into(),
                TupleData::from_data(vec![("b".into(), Value::none())])
                    .unwrap()
                    .into(),
            ])
            .unwrap(),
        )
        .unwrap();

        let t_6_good_0 = TypeSignature::from_string(
            "(response int (list 5 (tuple (b (optional int)))))",
            version,
            epoch,
        );
        let t_6_good_1 = TypeSignature::from_string(
            "(response int (list 2 (tuple (b (optional int)))))",
            version,
            epoch,
        );
        let t_6_good_2 = TypeSignature::from_string(
            "(response bool (list 2 (tuple (b (optional int)))))",
            version,
            epoch,
        );
        let t_6_bad_0 = TypeSignature::from_string(
            "(response uint (list 5 (tuple (b (optional int)) (a (optional int)))))",
            version,
            epoch,
        );
        let t_6_bad_1 = TypeSignature::from_string(
            "(response int (list 5 (tuple (b (optional uint)))))",
            version,
            epoch,
        );
        let t_6_bad_2 = TypeSignature::from_string(
            "(response (list 5 (tuple (b (optional int)))) int)",
            version,
            epoch,
        );
        let t_6_bad_3 = TypeSignature::from_string(
            "(list 5 (tuple (b (optional int)) (a (optional int))))",
            version,
            epoch,
        );

        let test_cases = [
            (v_1, v_1_good, t_1_good, vec![t_1_bad_0, t_1_bad_1]),
            (v_2, v_2_good, t_2_good, vec![t_2_bad_0, t_2_bad_1]),
            (v_3, v_3_good, t_3_good, vec![t_3_bad_0, t_3_bad_1]),
            (v_4, v_4_good, t_4_good, vec![t_4_bad_0, t_4_bad_1]),
            (
                v_5.clone(),
                v_5_good.clone(),
                t_5_good_0,
                vec![t_5_bad_0, t_5_bad_1, t_5_bad_2, t_5_bad_3],
            ),
            (v_5.clone(), v_5_good.clone(), t_5_good_1, vec![]),
            (v_5, v_5_good, t_5_good_2, vec![]),
            (
                v_6.clone(),
                v_6_good.clone(),
                t_6_good_0,
                vec![t_6_bad_0, t_6_bad_1, t_6_bad_2, t_6_bad_3],
            ),
            (v_6.clone(), v_6_good.clone(), t_6_good_1, vec![]),
            (v_6, v_6_good, t_6_good_2, vec![]),
        ];

        for (input_val, expected_out, good_type, bad_types) in test_cases.iter() {
            eprintln!(
                "Testing {}. Expected sanitization = {}",
                input_val, expected_out
            );
            let serialized = input_val.serialize_to_hex().unwrap();

            let result =
                RollbackWrapper::deserialize_value(&serialized, good_type, &epoch).map(|x| x.value);
            if epoch < StacksEpochId::Epoch24 {
                let error = result.unwrap_err();
                assert!(matches!(error, SerializationError::DeserializeExpected(_)));
            } else {
                let value = result.unwrap();
                assert_eq!(&value, expected_out);
            }

            for bad_type in bad_types.iter() {
                eprintln!("Testing bad type: {}", bad_type);
                let result = RollbackWrapper::deserialize_value(&serialized, bad_type, &epoch);
                let error = result.unwrap_err();
                assert!(matches!(error, SerializationError::DeserializeExpected(_)));
            }

            // now test the value::sanitize routine
            let result = Value::sanitize_value(&epoch, good_type, input_val.clone());
            if epoch < StacksEpochId::Epoch24 {
                let (value, did_sanitize) = result.unwrap();
                assert_eq!(&value, input_val);
                assert!(!did_sanitize, "Should not sanitize before epoch-2.4");
            } else {
                let (value, did_sanitize) = result.unwrap();
                assert_eq!(&value, expected_out);
                assert!(did_sanitize, "Should have sanitized");
            }

            for bad_type in bad_types.iter() {
                eprintln!("Testing bad type: {}", bad_type);
                let result = Value::sanitize_value(&epoch, bad_type, input_val.clone());
                if epoch < StacksEpochId::Epoch24 {
                    let (value, did_sanitize) = result.unwrap();
                    assert_eq!(&value, input_val);
                    assert!(!did_sanitize, "Should not sanitize before epoch-2.4");
                } else {
                    assert!(result.is_none());
                }
            }
        }
    }

    #[test]
    fn test_vectors() {
        let tests = [
            ("1010", Err("Bad type prefix".into())),
            ("0000000000000000000000000000000001", Ok(Value::Int(1))),
            ("00ffffffffffffffffffffffffffffffff", Ok(Value::Int(-1))),
            ("0100000000000000000000000000000001", Ok(Value::UInt(1))),
            ("0200000004deadbeef", Ok(Value::buff_from(vec![0xde, 0xad, 0xbe, 0xef])
                                      .unwrap())),
            ("03", Ok(Value::Bool(true))),
            ("04", Ok(Value::Bool(false))),
            ("050011deadbeef11ababffff11deadbeef11ababffff", Ok(
                StandardPrincipalData(
                    0x00,
                    [0x11, 0xde, 0xad, 0xbe, 0xef, 0x11, 0xab, 0xab, 0xff, 0xff,
                     0x11, 0xde, 0xad, 0xbe, 0xef, 0x11, 0xab, 0xab, 0xff, 0xff]).into())),
            ("060011deadbeef11ababffff11deadbeef11ababffff0461626364", Ok(
                QualifiedContractIdentifier::new(
                    StandardPrincipalData(
                        0x00,
                        [0x11, 0xde, 0xad, 0xbe, 0xef, 0x11, 0xab, 0xab, 0xff, 0xff,
                         0x11, 0xde, 0xad, 0xbe, 0xef, 0x11, 0xab, 0xab, 0xff, 0xff]),
                    "abcd".into()).into())),
            ("0700ffffffffffffffffffffffffffffffff", Ok(Value::okay(Value::Int(-1)).unwrap())),
            ("0800ffffffffffffffffffffffffffffffff", Ok(Value::error(Value::Int(-1)).unwrap())),
            ("09", Ok(Value::none())),
            ("0a00ffffffffffffffffffffffffffffffff", Ok(Value::some(Value::Int(-1)).unwrap())),
            ("0b0000000400000000000000000000000000000000010000000000000000000000000000000002000000000000000000000000000000000300fffffffffffffffffffffffffffffffc",
             Ok(Value::list_from(vec![
                 Value::Int(1), Value::Int(2), Value::Int(3), Value::Int(-4)]).unwrap())),
            ("0c000000020362617a0906666f6f62617203",
             Ok(Value::from(TupleData::from_data(vec![
                 ("baz".into(), Value::none()), ("foobar".into(), Value::Bool(true))]).unwrap())))
        ];

        for (test, expected) in tests.iter() {
            if let Ok(x) = expected {
                assert_eq!(test, &x.serialize_to_hex().unwrap());
            }
            assert_eq!(expected, &Value::try_deserialize_hex_untyped(test));
            assert_eq!(
                expected,
                &Value::try_deserialize_hex_untyped(&format!("0x{}", test))
            );
        }

        // test the serialized_size implementation
        for (test, expected) in tests.iter() {
            if let Ok(value) = expected {
                assert_eq!(
                    value.serialized_size().unwrap(),
                    test.len() as u32 / 2,
                    "serialized_size() should return the byte length of the serialization (half the length of the hex encoding)",
                );
            }
        }
    }

    #[test]
    fn try_deser_large_list() {
        let buff = vec![
            11, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
        ];

        assert_eq!(
            Value::try_deserialize_bytes_untyped(&buff).unwrap_err(),
            SerializationError::DeserializationError("Illegal list type".to_string())
        );
    }

    #[test]
    fn try_deser_large_tuple() {
        let buff = vec![
            12, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
        ];

        assert_eq!(
            Value::try_deserialize_bytes_untyped(&buff).unwrap_err(),
            SerializationError::DeserializationError("Illegal tuple type".to_string())
        );
    }

    #[test]
    fn try_overflow_stack() {
        let input = "08080808080808080808070707080807080808080808080708080808080708080707080707080807080808080808080708080808080708080707080708070807080808080808080708080808080708080708080808080808080807070807080808080808070808070707080807070808070808080808070808070708070807080808080808080707080708070807080708080808080808070808080808070808070808080808080808080707080708080808080807080807070708080707080807080808080807080807070807080708080808080808070708070808080808080708080707070808070708080807080807070708";
        assert_eq!(
            Err(CheckErrors::TypeSignatureTooDeep.into()),
            Value::try_deserialize_hex_untyped(input)
        );
    }

    #[test]
    fn test_principals() {
        let issuer =
            PrincipalData::parse_standard_principal("SM2J6ZY48GV1EZ5V2V5RB9MP66SW86PYKKQVX8X0G")
                .unwrap();
        let standard_p = Value::from(issuer.clone());

        let contract_identifier = QualifiedContractIdentifier::new(issuer, "foo".into());
        let contract_p2 = Value::from(PrincipalData::Contract(contract_identifier));

        test_deser_ser(contract_p2.clone());
        test_deser_ser(standard_p.clone());

        test_bad_expectation(contract_p2, TypeSignature::BoolType);
        test_bad_expectation(standard_p, TypeSignature::BoolType);
    }
}
