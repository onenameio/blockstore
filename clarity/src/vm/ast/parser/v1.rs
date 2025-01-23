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

use lazy_static::lazy_static;
use regex::{Captures, Regex};
use stacks_common::util::hash::hex_bytes;

use crate::vm::ast::errors::{ParseError, ParseErrors, ParseResult};
use crate::vm::ast::stack_depth_checker::AST_CALL_STACK_DEPTH_BUFFER;
use crate::vm::representations::{
    ClarityName, ContractName, PreSymbolicExpression, MAX_STRING_LEN,
};
use crate::vm::types::{PrincipalData, TraitIdentifier, Value};
use crate::vm::MAX_CALL_STACK_DEPTH;

pub const CONTRACT_MIN_NAME_LENGTH: usize = 1;
pub const CONTRACT_MAX_NAME_LENGTH: usize = 40;

pub enum LexItem {
    LeftParen,
    RightParen,
    LeftCurly,
    RightCurly,
    LiteralValue(usize, Value),
    SugaredContractIdentifier(usize, ContractName),
    SugaredFieldIdentifier(usize, ContractName, ClarityName),
    FieldIdentifier(usize, TraitIdentifier),
    TraitReference(usize, ClarityName),
    Variable(String),
    CommaSeparator,
    ColonSeparator,
    Whitespace,
}

#[derive(Debug)]
enum TokenType {
    Whitespace,
    Comma,
    Colon,
    LParens,
    RParens,
    LCurly,
    RCurly,
    StringASCIILiteral,
    StringUTF8Literal,
    HexStringLiteral,
    UIntLiteral,
    IntLiteral,
    Variable,
    TraitReferenceLiteral,
    PrincipalLiteral,
    SugaredContractIdentifierLiteral,
    FullyQualifiedContractIdentifierLiteral,
    SugaredFieldIdentifierLiteral,
    FullyQualifiedFieldIdentifierLiteral,
}

struct LexMatcher {
    matcher: Regex,
    handler: TokenType,
}

#[allow(clippy::enum_variant_names)]
enum LexContext {
    ExpectNothing,
    ExpectClosing,
    ExpectClosingColon,
}

enum ParseContext {
    CollectList,
    CollectTuple,
}

impl LexMatcher {
    fn new(regex_str: &str, handles: TokenType) -> LexMatcher {
        #[allow(clippy::unwrap_used)]
        LexMatcher {
            matcher: Regex::new(&format!("^{}", regex_str)).unwrap(),
            handler: handles,
        }
    }
}

fn get_value_or_err(input: &str, captures: Captures) -> ParseResult<String> {
    let matched = captures
        .name("value")
        .ok_or(ParseError::new(ParseErrors::FailedCapturingInput))?;
    Ok(input[matched.start()..matched.end()].to_string())
}

fn get_lines_at(input: &str) -> Vec<usize> {
    let mut out: Vec<_> = input.match_indices('\n').map(|(ix, _)| ix).collect();
    out.reverse();
    out
}

lazy_static! {
    pub static ref STANDARD_PRINCIPAL_REGEX: String =
        "[0123456789ABCDEFGHJKMNPQRSTVWXYZ]{28,41}".into();
    pub static ref CONTRACT_NAME_REGEX: String = format!(
        r#"([a-zA-Z](([a-zA-Z0-9]|[-_])){{{},{}}})"#,
        CONTRACT_MIN_NAME_LENGTH - 1,
        CONTRACT_MAX_NAME_LENGTH - 1
    );
    pub static ref CONTRACT_PRINCIPAL_REGEX: String = format!(
        r#"{}(\.){}"#,
        *STANDARD_PRINCIPAL_REGEX, *CONTRACT_NAME_REGEX
    );
    pub static ref PRINCIPAL_DATA_REGEX: String = format!(
        "({})|({})",
        *STANDARD_PRINCIPAL_REGEX, *CONTRACT_PRINCIPAL_REGEX
    );
    pub static ref CLARITY_NAME_REGEX: String =
        format!(r#"([[:word:]]|[-!?+<>=/*]){{1,{}}}"#, MAX_STRING_LEN);

    static ref lex_matchers: Vec<LexMatcher> = vec![
        LexMatcher::new(
            r#"u"(?P<value>((\\")|([[ -~]&&[^"]]))*)""#,
            TokenType::StringUTF8Literal,
        ),
        LexMatcher::new(
            r#""(?P<value>((\\")|([[ -~]&&[^"]]))*)""#,
            TokenType::StringASCIILiteral,
        ),
        LexMatcher::new(";;[ -~]*", TokenType::Whitespace), // ;; comments.
        LexMatcher::new("[\n]+", TokenType::Whitespace),
        LexMatcher::new("[ \t]+", TokenType::Whitespace),
        LexMatcher::new("[,]", TokenType::Comma),
        LexMatcher::new("[:]", TokenType::Colon),
        LexMatcher::new("[(]", TokenType::LParens),
        LexMatcher::new("[)]", TokenType::RParens),
        LexMatcher::new("[{]", TokenType::LCurly),
        LexMatcher::new("[}]", TokenType::RCurly),
        LexMatcher::new(
            "<(?P<value>([[:word:]]|[-])+)>",
            TokenType::TraitReferenceLiteral,
        ),
        LexMatcher::new("0x(?P<value>[[:xdigit:]]*)", TokenType::HexStringLiteral),
        LexMatcher::new("u(?P<value>[[:digit:]]+)", TokenType::UIntLiteral),
        LexMatcher::new("(?P<value>-?[[:digit:]]+)", TokenType::IntLiteral),
        LexMatcher::new(
            &format!(
                r#"'(?P<value>{}(\.)([[:alnum:]]|[-]){{1,{}}})"#,
                *CONTRACT_PRINCIPAL_REGEX, MAX_STRING_LEN
            ),
            TokenType::FullyQualifiedFieldIdentifierLiteral,
        ),
        LexMatcher::new(
            &format!(
                r#"(?P<value>(\.){}(\.)([[:alnum:]]|[-]){{1,{}}})"#,
                *CONTRACT_NAME_REGEX, MAX_STRING_LEN
            ),
            TokenType::SugaredFieldIdentifierLiteral,
        ),
        LexMatcher::new(
            &format!(r#"'(?P<value>{})"#, *CONTRACT_PRINCIPAL_REGEX),
            TokenType::FullyQualifiedContractIdentifierLiteral,
        ),
        LexMatcher::new(
            &format!(r#"(?P<value>(\.){})"#, *CONTRACT_NAME_REGEX),
            TokenType::SugaredContractIdentifierLiteral,
        ),
        LexMatcher::new(
            &format!("'(?P<value>{})", *STANDARD_PRINCIPAL_REGEX),
            TokenType::PrincipalLiteral,
        ),
        LexMatcher::new(
            &format!("(?P<value>{})", *CLARITY_NAME_REGEX),
            TokenType::Variable,
        ),
    ];
}

/// Lex the contract, permitting nesting of lists and tuples up to `max_nesting`.
fn inner_lex(input: &str, max_nesting: u64) -> ParseResult<Vec<(LexItem, u32, u32)>> {
    let mut context = LexContext::ExpectNothing;

    let mut line_indices = get_lines_at(input);
    let mut next_line_break = line_indices.pop();
    let mut current_line: u32 = 1;

    let mut result = Vec::new();
    let mut munch_index = 0;
    let mut column_pos: u32 = 1;
    let mut did_match = true;

    let mut nesting_depth = 0;

    while did_match && munch_index < input.len() {
        if let Some(next_line_ix) = next_line_break {
            if munch_index > next_line_ix {
                next_line_break = line_indices.pop();
                column_pos = 1;
                current_line = current_line
                    .checked_add(1)
                    .ok_or(ParseError::new(ParseErrors::ProgramTooLarge))?;
            }
        }

        did_match = false;
        let current_slice = &input[munch_index..];
        for matcher in lex_matchers.iter() {
            if let Some(captures) = matcher.matcher.captures(current_slice) {
                let whole_match = captures.get(0).ok_or(ParseErrors::InterpreterFailure)?;
                assert_eq!(whole_match.start(), 0);
                munch_index += whole_match.end();

                match context {
                    LexContext::ExpectNothing => Ok(()),
                    LexContext::ExpectClosing => {
                        // expect the next lexed item to be something that typically
                        // "closes" an atom -- i.e., whitespace or a right-parens.
                        // this prevents an atom like 1234abc from getting split into "1234" and "abc"
                        match matcher.handler {
                            TokenType::RParens => Ok(()),
                            TokenType::RCurly => Ok(()),
                            TokenType::Whitespace => Ok(()),
                            TokenType::Comma => Ok(()),
                            TokenType::Colon => Ok(()),
                            _ => Err(ParseError::new(ParseErrors::SeparatorExpected(
                                current_slice[..whole_match.end()].to_string(),
                            ))),
                        }
                    }
                    LexContext::ExpectClosingColon => {
                        // handle the expected whitespace after a `:`
                        match matcher.handler {
                            TokenType::RParens => Ok(()),
                            TokenType::RCurly => Ok(()),
                            TokenType::Whitespace => Ok(()),
                            TokenType::Comma => Ok(()),
                            TokenType::Colon => Ok(()),
                            _ => Err(ParseError::new(ParseErrors::SeparatorExpectedAfterColon(
                                current_slice[..whole_match.end()].to_string(),
                            ))),
                        }
                    }
                }?;

                // default to expect a closing
                context = LexContext::ExpectClosing;

                let token = match matcher.handler {
                    TokenType::LParens => {
                        context = LexContext::ExpectNothing;
                        nesting_depth += 1;
                        if nesting_depth > max_nesting {
                            return Err(ParseError::new(
                                ParseErrors::VaryExpressionStackDepthTooDeep,
                            ));
                        }
                        Ok(LexItem::LeftParen)
                    }
                    TokenType::RParens => {
                        // if this underflows, the contract is invalid anyway
                        nesting_depth = nesting_depth.saturating_sub(1);
                        Ok(LexItem::RightParen)
                    }
                    TokenType::Whitespace => {
                        context = LexContext::ExpectNothing;
                        Ok(LexItem::Whitespace)
                    }
                    TokenType::Comma => {
                        context = LexContext::ExpectNothing;
                        Ok(LexItem::CommaSeparator)
                    }
                    TokenType::Colon => {
                        // colon should not be followed directly by an item,
                        //  e.g., {a:b} should not be legal
                        context = LexContext::ExpectClosingColon;
                        Ok(LexItem::ColonSeparator)
                    }
                    TokenType::LCurly => {
                        context = LexContext::ExpectNothing;
                        nesting_depth += 1;
                        if nesting_depth > max_nesting {
                            return Err(ParseError::new(
                                ParseErrors::VaryExpressionStackDepthTooDeep,
                            ));
                        }
                        Ok(LexItem::LeftCurly)
                    }
                    TokenType::RCurly => {
                        // if this underflows, the contract is invalid anyway
                        nesting_depth = nesting_depth.saturating_sub(1);
                        Ok(LexItem::RightCurly)
                    }
                    TokenType::Variable => {
                        let value = get_value_or_err(current_slice, captures)?;
                        if value.contains('#') {
                            Err(ParseError::new(ParseErrors::IllegalVariableName(value)))
                        } else {
                            Ok(LexItem::Variable(value))
                        }
                    }
                    TokenType::UIntLiteral => {
                        let str_value = get_value_or_err(current_slice, captures)?;
                        let value = match str_value.parse::<u128>() {
                            Ok(parsed) => Ok(Value::UInt(parsed)),
                            Err(_e) => Err(ParseError::new(ParseErrors::FailedParsingIntValue(
                                str_value.clone(),
                            ))),
                        }?;
                        Ok(LexItem::LiteralValue(str_value.len(), value))
                    }
                    TokenType::IntLiteral => {
                        let str_value = get_value_or_err(current_slice, captures)?;
                        let value = match str_value.parse::<i128>() {
                            Ok(parsed) => Ok(Value::Int(parsed)),
                            Err(_e) => Err(ParseError::new(ParseErrors::FailedParsingIntValue(
                                str_value.clone(),
                            ))),
                        }?;
                        Ok(LexItem::LiteralValue(str_value.len(), value))
                    }
                    TokenType::FullyQualifiedContractIdentifierLiteral => {
                        let str_value = get_value_or_err(current_slice, captures)?;
                        let value =
                            match PrincipalData::parse_qualified_contract_principal(&str_value) {
                                Ok(parsed) => Ok(Value::Principal(parsed)),
                                Err(_e) => Err(ParseError::new(
                                    ParseErrors::FailedParsingPrincipal(str_value.clone()),
                                )),
                            }?;
                        Ok(LexItem::LiteralValue(str_value.len(), value))
                    }
                    TokenType::SugaredContractIdentifierLiteral => {
                        let str_value = get_value_or_err(current_slice, captures)?;
                        let value = match str_value[1..].to_string().try_into() {
                            Ok(parsed) => Ok(parsed),
                            Err(_e) => Err(ParseError::new(ParseErrors::FailedParsingPrincipal(
                                str_value.clone(),
                            ))),
                        }?;
                        Ok(LexItem::SugaredContractIdentifier(str_value.len(), value))
                    }
                    TokenType::FullyQualifiedFieldIdentifierLiteral => {
                        let str_value = get_value_or_err(current_slice, captures)?;
                        let value = match TraitIdentifier::parse_fully_qualified(&str_value) {
                            Ok(parsed) => Ok(parsed),
                            Err(_e) => Err(ParseError::new(ParseErrors::FailedParsingField(
                                str_value.clone(),
                            ))),
                        }?;
                        Ok(LexItem::FieldIdentifier(str_value.len(), value))
                    }
                    TokenType::SugaredFieldIdentifierLiteral => {
                        let str_value = get_value_or_err(current_slice, captures)?;
                        let (contract_name, field_name) =
                            match TraitIdentifier::parse_sugared_syntax(&str_value) {
                                Ok((contract_name, field_name)) => Ok((contract_name, field_name)),
                                Err(_e) => Err(ParseError::new(ParseErrors::FailedParsingField(
                                    str_value.clone(),
                                ))),
                            }?;
                        Ok(LexItem::SugaredFieldIdentifier(
                            str_value.len(),
                            contract_name,
                            field_name,
                        ))
                    }
                    TokenType::PrincipalLiteral => {
                        let str_value = get_value_or_err(current_slice, captures)?;
                        let value = match PrincipalData::parse_standard_principal(&str_value) {
                            Ok(parsed) => Ok(Value::Principal(PrincipalData::Standard(parsed))),
                            Err(_e) => Err(ParseError::new(ParseErrors::FailedParsingPrincipal(
                                str_value.clone(),
                            ))),
                        }?;
                        Ok(LexItem::LiteralValue(str_value.len(), value))
                    }
                    TokenType::TraitReferenceLiteral => {
                        let str_value = get_value_or_err(current_slice, captures)?;
                        let data = str_value.clone().try_into().map_err(|_| {
                            ParseError::new(ParseErrors::IllegalVariableName(str_value.to_string()))
                        })?;
                        Ok(LexItem::TraitReference(str_value.len(), data))
                    }
                    TokenType::HexStringLiteral => {
                        let str_value = get_value_or_err(current_slice, captures)?;
                        let byte_vec = hex_bytes(&str_value).map_err(|x| {
                            ParseError::new(ParseErrors::FailedParsingHexValue(
                                str_value.clone(),
                                x.to_string(),
                            ))
                        })?;
                        let value = match Value::buff_from(byte_vec) {
                            Ok(parsed) => Ok(parsed),
                            Err(_e) => Err(ParseError::new(ParseErrors::FailedParsingBuffer(
                                str_value.clone(),
                            ))),
                        }?;
                        Ok(LexItem::LiteralValue(str_value.len(), value))
                    }
                    TokenType::StringASCIILiteral => {
                        let str_value = get_value_or_err(current_slice, captures)?;
                        let str_value_len = str_value.len();
                        let unescaped_str = unescape_ascii_chars(str_value, false)?;
                        let byte_vec = unescaped_str.as_bytes().to_vec();

                        let value = match Value::string_ascii_from_bytes(byte_vec) {
                            Ok(parsed) => Ok(parsed),
                            Err(_e) => Err(ParseError::new(ParseErrors::InvalidCharactersDetected)),
                        }?;
                        Ok(LexItem::LiteralValue(str_value_len, value))
                    }
                    TokenType::StringUTF8Literal => {
                        let str_value = get_value_or_err(current_slice, captures)?;
                        let str_value_len = str_value.len();
                        let unescaped_str = unescape_ascii_chars(str_value, true)?;

                        let value = match Value::string_utf8_from_string_utf8_literal(unescaped_str)
                        {
                            Ok(parsed) => Ok(parsed),
                            Err(_e) => Err(ParseError::new(ParseErrors::InvalidCharactersDetected)),
                        }?;
                        Ok(LexItem::LiteralValue(str_value_len, value))
                    }
                }?;

                result.push((token, current_line, column_pos));
                column_pos += whole_match.end() as u32;
                did_match = true;
                break;
            }
        }
    }

    if munch_index == input.len() {
        Ok(result)
    } else {
        Err(ParseError::new(ParseErrors::FailedParsingRemainder(
            input[munch_index..].to_string(),
        )))
    }
}

pub fn lex(input: &str) -> ParseResult<Vec<(LexItem, u32, u32)>> {
    inner_lex(
        input,
        AST_CALL_STACK_DEPTH_BUFFER + (MAX_CALL_STACK_DEPTH as u64) + 1,
    )
}

fn unescape_ascii_chars(escaped_str: String, allow_unicode_escape: bool) -> ParseResult<String> {
    let mut unescaped_str = String::new();
    let mut chars = escaped_str.chars();
    while let Some(char) = chars.next() {
        if char == '\\' {
            if let Some(next) = chars.next() {
                match next {
                    // ASCII escapes based on Rust list (https://doc.rust-lang.org/reference/tokens.html#ascii-escapes)
                    '\\' => unescaped_str.push('\\'),
                    '\"' => unescaped_str.push('\"'),
                    'n' => unescaped_str.push('\n'),
                    't' => unescaped_str.push('\t'),
                    'r' => unescaped_str.push('\r'),
                    '0' => unescaped_str.push('\0'),
                    'u' if allow_unicode_escape => unescaped_str.push_str("\\u"),
                    _ => return Err(ParseError::new(ParseErrors::InvalidEscaping)),
                }
            } else {
                return Err(ParseError::new(ParseErrors::InvalidEscaping));
            }
        } else {
            unescaped_str.push(char);
        }
    }
    Ok(unescaped_str)
}

enum ParseStackItem {
    Expression(PreSymbolicExpression),
    Colon,
    Comma,
}

fn handle_expression(
    parse_stack: &mut [(Vec<ParseStackItem>, u32, u32, ParseContext)],
    outputs: &mut Vec<PreSymbolicExpression>,
    expr: PreSymbolicExpression,
) {
    match parse_stack.last_mut() {
        // no open lists on stack, add current to outputs.
        None => outputs.push(expr),
        // there's an open list or tuple on the stack.
        Some((ref mut list, _, _, _)) => list.push(ParseStackItem::Expression(expr)),
    }
}

// TODO: add tests from mutation testing results #4828
#[cfg_attr(test, mutants::skip)]
pub fn parse_lexed(input: Vec<(LexItem, u32, u32)>) -> ParseResult<Vec<PreSymbolicExpression>> {
    let mut parse_stack = Vec::new();

    let mut output_list = Vec::new();

    for (item, line_pos, column_pos) in input.into_iter() {
        match item {
            LexItem::LeftParen => {
                // start new list.
                let new_list = Vec::new();
                parse_stack.push((new_list, line_pos, column_pos, ParseContext::CollectList));
            }
            LexItem::RightParen => {
                // end current list.
                if let Some((list, start_line, start_column, parse_context)) = parse_stack.pop() {
                    match parse_context {
                        ParseContext::CollectList => {
                            let checked_list: ParseResult<Vec<PreSymbolicExpression>> = list
                                .into_iter()
                                .map(|i| match i {
                                    ParseStackItem::Expression(e) => Ok(e),
                                    ParseStackItem::Colon => {
                                        Err(ParseError::new(ParseErrors::ColonSeparatorUnexpected))
                                    }
                                    ParseStackItem::Comma => {
                                        Err(ParseError::new(ParseErrors::CommaSeparatorUnexpected))
                                    }
                                })
                                .collect();
                            let checked_list = checked_list?;
                            let mut pre_expr = PreSymbolicExpression::list(checked_list);
                            pre_expr.set_span(start_line, start_column, line_pos, column_pos);
                            handle_expression(&mut parse_stack, &mut output_list, pre_expr);
                        }
                        ParseContext::CollectTuple => {
                            let mut error =
                                ParseError::new(ParseErrors::ClosingTupleLiteralExpected);
                            error.diagnostic.add_span(
                                start_line,
                                start_column,
                                line_pos,
                                column_pos,
                            );
                            return Err(error);
                        }
                    }
                } else {
                    debug!(
                        "Closing parenthesis expected ({}, {})",
                        line_pos, column_pos
                    );
                    return Err(ParseError::new(ParseErrors::ClosingParenthesisUnexpected));
                }
            }
            LexItem::LeftCurly => {
                let new_list = Vec::new();
                parse_stack.push((new_list, line_pos, column_pos, ParseContext::CollectTuple));
            }
            LexItem::RightCurly => {
                if let Some((tuple_list, start_line, start_column, parse_context)) =
                    parse_stack.pop()
                {
                    match parse_context {
                        ParseContext::CollectTuple => {
                            let mut checked_list = Vec::new();
                            for (index, item) in tuple_list.into_iter().enumerate() {
                                // check that tuple items are (expr, colon, expr, comma)
                                match index % 4 {
                                    0 | 2 => {
                                        if let ParseStackItem::Expression(e) = item {
                                            checked_list.push(e);
                                            Ok(())
                                        } else {
                                            Err(ParseErrors::TupleItemExpected(index))
                                        }
                                    }
                                    1 => {
                                        if let ParseStackItem::Colon = item {
                                            Ok(())
                                        } else {
                                            Err(ParseErrors::TupleColonExpected(index))
                                        }
                                    }
                                    3 => {
                                        if let ParseStackItem::Comma = item {
                                            Ok(())
                                        } else {
                                            Err(ParseErrors::TupleCommaExpected(index))
                                        }
                                    }
                                    _ => unreachable!("More than four modulos of four."),
                                }?;
                            }
                            let mut pre_expr = PreSymbolicExpression::tuple(checked_list);
                            pre_expr.set_span(start_line, start_column, line_pos, column_pos);
                            handle_expression(&mut parse_stack, &mut output_list, pre_expr);
                        }
                        ParseContext::CollectList => {
                            let mut error =
                                ParseError::new(ParseErrors::ClosingParenthesisExpected);
                            error.diagnostic.add_span(
                                start_line,
                                start_column,
                                line_pos,
                                column_pos,
                            );
                            return Err(error);
                        }
                    }
                } else {
                    debug!(
                        "Closing tuple literal unexpected ({}, {})",
                        line_pos, column_pos
                    );
                    return Err(ParseError::new(ParseErrors::ClosingTupleLiteralUnexpected));
                }
            }
            LexItem::Variable(value) => {
                let end_column = column_pos + (value.len() as u32) - 1;
                let value = value.clone().try_into().map_err(|_| {
                    ParseError::new(ParseErrors::IllegalVariableName(value.to_string()))
                })?;
                let mut pre_expr = PreSymbolicExpression::atom(value);
                pre_expr.set_span(line_pos, column_pos, line_pos, end_column);
                handle_expression(&mut parse_stack, &mut output_list, pre_expr);
            }
            LexItem::LiteralValue(length, value) => {
                let mut end_column = column_pos + (length as u32);
                // Avoid underflows on cases like empty strings
                if length > 0 {
                    end_column -= 1;
                }
                let mut pre_expr = PreSymbolicExpression::atom_value(value);
                pre_expr.set_span(line_pos, column_pos, line_pos, end_column);
                handle_expression(&mut parse_stack, &mut output_list, pre_expr);
            }
            LexItem::SugaredContractIdentifier(length, value) => {
                let mut end_column = column_pos + (length as u32);
                // Avoid underflows on cases like empty strings
                if length > 0 {
                    end_column -= 1;
                }
                let mut pre_expr = PreSymbolicExpression::sugared_contract_identifier(value);
                pre_expr.set_span(line_pos, column_pos, line_pos, end_column);
                handle_expression(&mut parse_stack, &mut output_list, pre_expr);
            }
            LexItem::SugaredFieldIdentifier(length, contract_name, name) => {
                let mut end_column = column_pos + (length as u32);
                // Avoid underflows on cases like empty strings
                if length > 0 {
                    end_column -= 1;
                }
                let mut pre_expr =
                    PreSymbolicExpression::sugared_field_identifier(contract_name, name);
                pre_expr.set_span(line_pos, column_pos, line_pos, end_column);
                handle_expression(&mut parse_stack, &mut output_list, pre_expr);
            }
            LexItem::FieldIdentifier(length, trait_identifier) => {
                let mut end_column = column_pos + (length as u32);
                // Avoid underflows on cases like empty strings
                if length > 0 {
                    end_column -= 1;
                }
                let mut pre_expr = PreSymbolicExpression::field_identifier(trait_identifier);
                pre_expr.set_span(line_pos, column_pos, line_pos, end_column);
                handle_expression(&mut parse_stack, &mut output_list, pre_expr);
            }
            LexItem::TraitReference(_length, value) => {
                let end_column = column_pos + (value.len() as u32) - 1;
                let mut pre_expr = PreSymbolicExpression::trait_reference(value);
                pre_expr.set_span(line_pos, column_pos, line_pos, end_column);
                handle_expression(&mut parse_stack, &mut output_list, pre_expr);
            }
            LexItem::ColonSeparator => {
                match parse_stack.last_mut() {
                    None => return Err(ParseError::new(ParseErrors::ColonSeparatorUnexpected)),
                    Some((ref mut list, ..)) => {
                        list.push(ParseStackItem::Colon);
                    }
                };
            }
            LexItem::CommaSeparator => {
                match parse_stack.last_mut() {
                    None => return Err(ParseError::new(ParseErrors::CommaSeparatorUnexpected)),
                    Some((ref mut list, ..)) => {
                        list.push(ParseStackItem::Comma);
                    }
                };
            }
            LexItem::Whitespace => (),
        };
    }

    // check unfinished stack:
    if !parse_stack.is_empty() {
        let mut error = ParseError::new(ParseErrors::ClosingParenthesisExpected);
        if let Some((_list, start_line, start_column, _parse_context)) = parse_stack.pop() {
            error.diagnostic.add_span(start_line, start_column, 0, 0);
            debug!(
                "Unfinished stack: {} items remaining starting at ({}, {})",
                parse_stack.len() + 1,
                start_line,
                start_column
            );
        }
        Err(error)
    } else {
        Ok(output_list)
    }
}

pub fn parse(input: &str) -> ParseResult<Vec<PreSymbolicExpression>> {
    let lexed = inner_lex(
        input,
        AST_CALL_STACK_DEPTH_BUFFER + (MAX_CALL_STACK_DEPTH as u64) + 1,
    )?;
    parse_lexed(lexed)
}

pub fn parse_no_stack_limit(input: &str) -> ParseResult<Vec<PreSymbolicExpression>> {
    let lexed = inner_lex(input, u64::MAX)?;
    parse_lexed(lexed)
}

#[cfg(test)]
mod test {
    use crate::vm::ast::errors::ParseErrors;
    use crate::vm::ast::stack_depth_checker::AST_CALL_STACK_DEPTH_BUFFER;
    use crate::vm::representations::{PreSymbolicExpression, PreSymbolicExpressionType};
    use crate::vm::types::{CharType, PrincipalData, SequenceData, Value};
    use crate::vm::{ast, MAX_CALL_STACK_DEPTH};

    fn make_atom(
        x: &str,
        start_line: u32,
        start_column: u32,
        end_line: u32,
        end_column: u32,
    ) -> PreSymbolicExpression {
        let mut e = PreSymbolicExpression::atom(x.into());
        e.set_span(start_line, start_column, end_line, end_column);
        e
    }

    fn make_atom_value(
        x: Value,
        start_line: u32,
        start_column: u32,
        end_line: u32,
        end_column: u32,
    ) -> PreSymbolicExpression {
        let mut e = PreSymbolicExpression::atom_value(x);
        e.set_span(start_line, start_column, end_line, end_column);
        e
    }

    fn make_list(
        start_line: u32,
        start_column: u32,
        end_line: u32,
        end_column: u32,
        x: Vec<PreSymbolicExpression>,
    ) -> PreSymbolicExpression {
        let mut e = PreSymbolicExpression::list(x);
        e.set_span(start_line, start_column, end_line, end_column);
        e
    }

    fn make_tuple(
        start_line: u32,
        start_column: u32,
        end_line: u32,
        end_column: u32,
        x: Vec<PreSymbolicExpression>,
    ) -> PreSymbolicExpression {
        let mut e = PreSymbolicExpression::tuple(x);
        e.set_span(start_line, start_column, end_line, end_column);
        e
    }

    #[test]
    fn test_parse_let_expression() {
        // This test includes some assertions ont the spans of each atom / atom_value / list, which makes indentation important.
        let input = r#"z (let ((x 1) (y 2))
    (+ x ;; "comments section?"
        ;; this is also a comment!
        (let ((x 3)) ;; more commentary
        (+ x y))
        x)) x y
        ;; this is 'quoted comment!"#;
        let program = vec![
            make_atom("z", 1, 1, 1, 1),
            make_list(
                1,
                3,
                6,
                11,
                vec![
                    make_atom("let", 1, 4, 1, 6),
                    make_list(
                        1,
                        8,
                        1,
                        20,
                        vec![
                            make_list(
                                1,
                                9,
                                1,
                                13,
                                vec![
                                    make_atom("x", 1, 10, 1, 10),
                                    make_atom_value(Value::Int(1), 1, 12, 1, 12),
                                ],
                            ),
                            make_list(
                                1,
                                15,
                                1,
                                19,
                                vec![
                                    make_atom("y", 1, 16, 1, 16),
                                    make_atom_value(Value::Int(2), 1, 18, 1, 18),
                                ],
                            ),
                        ],
                    ),
                    make_list(
                        2,
                        5,
                        6,
                        10,
                        vec![
                            make_atom("+", 2, 6, 2, 6),
                            make_atom("x", 2, 8, 2, 8),
                            make_list(
                                4,
                                9,
                                5,
                                16,
                                vec![
                                    make_atom("let", 4, 10, 4, 12),
                                    make_list(
                                        4,
                                        14,
                                        4,
                                        20,
                                        vec![make_list(
                                            4,
                                            15,
                                            4,
                                            19,
                                            vec![
                                                make_atom("x", 4, 16, 4, 16),
                                                make_atom_value(Value::Int(3), 4, 18, 4, 18),
                                            ],
                                        )],
                                    ),
                                    make_list(
                                        5,
                                        9,
                                        5,
                                        15,
                                        vec![
                                            make_atom("+", 5, 10, 5, 10),
                                            make_atom("x", 5, 12, 5, 12),
                                            make_atom("y", 5, 14, 5, 14),
                                        ],
                                    ),
                                ],
                            ),
                            make_atom("x", 6, 9, 6, 9),
                        ],
                    ),
                ],
            ),
            make_atom("x", 6, 13, 6, 13),
            make_atom("y", 6, 15, 6, 15),
        ];

        let parsed = ast::parser::v1::parse(input);
        assert_eq!(
            Ok(program),
            parsed,
            "Should match expected symbolic expression"
        );

        let input = "        -1234
        (- 12 34)";
        let program = vec![
            make_atom_value(Value::Int(-1234), 1, 9, 1, 13),
            make_list(
                2,
                9,
                2,
                17,
                vec![
                    make_atom("-", 2, 10, 2, 10),
                    make_atom_value(Value::Int(12), 2, 12, 2, 13),
                    make_atom_value(Value::Int(34), 2, 15, 2, 16),
                ],
            ),
        ];

        let parsed = ast::parser::v1::parse(input);
        assert_eq!(
            Ok(program),
            parsed,
            "Should match expected symbolic expression"
        );
    }

    #[test]
    fn test_parse_tuple_literal() {
        let input = "{id: 1337 }";
        let program = vec![make_tuple(
            1,
            1,
            1,
            11,
            vec![
                make_atom("id", 1, 2, 1, 3),
                make_atom_value(Value::Int(1337), 1, 6, 1, 9),
            ],
        )];
        let parsed = ast::parser::v1::parse(input);
        assert_eq!(Ok(program), parsed, "Should match expected tuple literal");
    }

    #[test]
    fn test_parse_contract_principals() {
        let input = "'SZ2J6ZY48GV1EZ5V2V5RB9MP66SW86PYKKQ9H6DPR.contract-a";
        let parsed = ast::parser::v1::parse(input).unwrap();

        let x1 = &parsed[0];
        assert!(match x1.match_atom_value() {
            Some(Value::Principal(PrincipalData::Contract(identifier))) => {
                format!("{}", PrincipalData::Standard(identifier.issuer.clone()))
                    == "SZ2J6ZY48GV1EZ5V2V5RB9MP66SW86PYKKQ9H6DPR"
                    && identifier.name == "contract-a".into()
            }
            _ => false,
        });

        let input = "'SZ2J6ZY48GV1EZ5V2V5RB9MP66SW86PYKKQ9H6DPR.a";
        let parsed = ast::parser::v1::parse(input).unwrap();

        let x1 = &parsed[0];
        assert!(match x1.match_atom_value() {
            Some(Value::Principal(PrincipalData::Contract(identifier))) => {
                format!("{}", PrincipalData::Standard(identifier.issuer.clone()))
                    == "SZ2J6ZY48GV1EZ5V2V5RB9MP66SW86PYKKQ9H6DPR"
                    && identifier.name == "a".into()
            }
            _ => false,
        });
    }

    #[test]
    fn test_parse_generics() {
        let input = "<a>";
        let parsed = ast::parser::v1::parse(input).unwrap();

        let x1 = &parsed[0];
        assert!(match x1.match_trait_reference() {
            Some(trait_name) => *trait_name == "a".into(),
            _ => false,
        });
    }

    #[test]
    fn test_parse_field_identifiers() {
        use crate::vm::types::PrincipalData;
        let input = "'SZ2J6ZY48GV1EZ5V2V5RB9MP66SW86PYKKQ9H6DPR.my-contract.my-trait";
        let parsed = ast::parser::v1::parse(input).unwrap();

        let x1 = &parsed[0];
        assert!(match x1.match_field_identifier() {
            Some(data) => {
                format!(
                    "{}",
                    PrincipalData::Standard(data.contract_identifier.issuer.clone())
                ) == "SZ2J6ZY48GV1EZ5V2V5RB9MP66SW86PYKKQ9H6DPR"
                    && data.contract_identifier.name == "my-contract".into()
                    && data.name == "my-trait".into()
            }
            _ => false,
        });
    }

    #[test]
    fn test_parse_sugared_field_identifiers() {
        let input = ".my-contract.my-trait";
        let parsed = ast::parser::v1::parse(input).unwrap();

        let x1 = &parsed[0];
        assert!(match &x1.pre_expr {
            PreSymbolicExpressionType::SugaredFieldIdentifier(contract_name, field_name) => {
                *contract_name == "my-contract".into() && *field_name == "my-trait".into()
            }
            _ => false,
        });
    }

    #[test]
    fn test_parse_failures() {
        let too_much_closure = "(let ((x 1) (y 2))))";
        let not_enough_closure = "(let ((x 1) (y 2))";
        let middle_hash = "(let ((x 1) (y#not 2)) x)";
        let unicode = "(let ((x🎶 1)) (eq x🎶 1))";
        let split_tokens = "(let ((023ab13 1)))";
        let name_with_dot = "(let ((ab.de 1)))";
        let wrong_tuple_literal_close = "{id 1337)";
        let wrong_list_close = "(13 37}";
        let extra_tuple_literal_close = "{id: 37}}";
        let unexpected_comma = "(let ((a 1), (b 2)) b)";
        let shorthand_tuple = "{ a, b }";
        let shorthand_tuple_dangling_comma = "{ a: b, b: ,}";
        let decorative_colon_on_value = "{ a: b: }";
        let tuple_literal_colon_after_comma = "{ a: b, : b a}";
        let tuple_comma_no_space = "{ a: b,c: 3 }"; // legal
        let tuple_colon_no_space = "{ a:b }";
        let empty_tuple_literal_comma = "{,}";
        let empty_tuple_literal_colon = "{:}";
        let legacy_boolean_literals = "(and 'true 'false)";
        let function_with_CR = "(define (foo (x y)) \n (+ 1 2 3) \r (- 1 2 3))";
        let function_with_CRLF = "(define (foo (x y)) \n (+ 1 2 3) \n\r (- 1 2 3))";
        let function_with_NEL = "(define (foo (x y)) \u{0085} (+ 1 2 3) \u{0085} (- 1 2 3))";
        let function_with_LS = "(define (foo (x y)) \u{2028} (+ 1 2 3) \u{2028} (- 1 2 3))";
        let function_with_PS = "(define (foo (x y)) \u{2029} (+ 1 2 3) \u{2029} (- 1 2 3))";
        let function_with_LF = "(define (foo (x y)) \n (+ 1 2 3) \n (- 1 2 3))";
        let string_with_invalid_escape = r#"
        "hello\eworld"
        "#;
        let ascii_string_with_unicode_escape = r#"
        "hello\u{1F436}world"
        "#;
        let string_with_valid_escape = r#"
        "hello\nworld"
        "#;
        let string_with_valid_double_escape = r#"
        "hello\\eworld"
        "#;
        let string_with_multiple_slashes = r#"
        "hello\\\"world"
        "#;
        let stack_limit =
            (AST_CALL_STACK_DEPTH_BUFFER + (MAX_CALL_STACK_DEPTH as u64) + 1) as usize;
        let exceeds_stack_depth_tuple = format!(
            "{}u1 {}",
            "{ a : ".repeat(stack_limit + 1),
            "} ".repeat(stack_limit + 1)
        );
        let exceeds_stack_depth_list = format!(
            "{}u1 {}",
            "(list ".repeat(stack_limit + 1),
            ")".repeat(stack_limit + 1)
        );

        assert!(matches!(
            ast::parser::v1::parse(split_tokens).unwrap_err().err,
            ParseErrors::SeparatorExpected(_)
        ));

        assert!(matches!(
            ast::parser::v1::parse(too_much_closure).unwrap_err().err,
            ParseErrors::ClosingParenthesisUnexpected
        ));

        assert!(matches!(
            ast::parser::v1::parse(not_enough_closure).unwrap_err().err,
            ParseErrors::ClosingParenthesisExpected
        ));

        assert!(matches!(
            ast::parser::v1::parse(middle_hash).unwrap_err().err,
            ParseErrors::FailedParsingRemainder(_)
        ));

        assert!(matches!(
            ast::parser::v1::parse(unicode).unwrap_err().err,
            ParseErrors::FailedParsingRemainder(_)
        ));

        assert!(matches!(
            ast::parser::v1::parse(name_with_dot).unwrap_err().err,
            ParseErrors::SeparatorExpected(_)
        ));

        assert!(matches!(
            ast::parser::v1::parse(wrong_tuple_literal_close)
                .unwrap_err()
                .err,
            ParseErrors::ClosingTupleLiteralExpected
        ));

        assert!(matches!(
            ast::parser::v1::parse(wrong_list_close).unwrap_err().err,
            ParseErrors::ClosingParenthesisExpected
        ));

        assert!(matches!(
            ast::parser::v1::parse(extra_tuple_literal_close)
                .unwrap_err()
                .err,
            ParseErrors::ClosingTupleLiteralUnexpected
        ));

        assert!(matches!(
            ast::parser::v1::parse(unexpected_comma).unwrap_err().err,
            ParseErrors::CommaSeparatorUnexpected
        ));

        // { a: b,c: 3 } is legal
        ast::parser::v1::parse(tuple_comma_no_space).unwrap();

        assert!(matches!(
            ast::parser::v1::parse(tuple_colon_no_space)
                .unwrap_err()
                .err,
            ParseErrors::SeparatorExpectedAfterColon(_)
        ));

        assert!(matches!(
            ast::parser::v1::parse(shorthand_tuple).unwrap_err().err,
            ParseErrors::TupleColonExpected(_)
        ));

        assert!(matches!(
            ast::parser::v1::parse(shorthand_tuple_dangling_comma)
                .unwrap_err()
                .err,
            ParseErrors::TupleItemExpected(_)
        ));

        assert!(matches!(
            ast::parser::v1::parse(decorative_colon_on_value)
                .unwrap_err()
                .err,
            ParseErrors::TupleCommaExpected(_)
        ));

        assert!(matches!(
            ast::parser::v1::parse(tuple_literal_colon_after_comma)
                .unwrap_err()
                .err,
            ParseErrors::TupleItemExpected(_)
        ));

        assert!(matches!(
            ast::parser::v1::parse(empty_tuple_literal_comma)
                .unwrap_err()
                .err,
            ParseErrors::TupleItemExpected(_)
        ));

        assert!(matches!(
            ast::parser::v1::parse(empty_tuple_literal_colon)
                .unwrap_err()
                .err,
            ParseErrors::TupleItemExpected(_)
        ));

        assert!(matches!(
            ast::parser::v1::parse(legacy_boolean_literals)
                .unwrap_err()
                .err,
            ParseErrors::FailedParsingRemainder(_)
        ));

        assert!(matches!(
            ast::parser::v1::parse(function_with_CR).unwrap_err().err,
            ParseErrors::FailedParsingRemainder(_)
        ));
        assert!(matches!(
            ast::parser::v1::parse(function_with_CRLF).unwrap_err().err,
            ParseErrors::FailedParsingRemainder(_)
        ));
        assert!(matches!(
            ast::parser::v1::parse(function_with_NEL).unwrap_err().err,
            ParseErrors::FailedParsingRemainder(_)
        ));
        assert!(matches!(
            ast::parser::v1::parse(function_with_LS).unwrap_err().err,
            ParseErrors::FailedParsingRemainder(_)
        ));
        assert!(matches!(
            ast::parser::v1::parse(function_with_PS).unwrap_err().err,
            ParseErrors::FailedParsingRemainder(_)
        ));

        ast::parser::v1::parse(function_with_LF).unwrap();

        assert!(matches!(
            ast::parser::v1::parse(string_with_invalid_escape)
                .unwrap_err()
                .err,
            ParseErrors::InvalidEscaping
        ));

        assert!(matches!(
            ast::parser::v1::parse(ascii_string_with_unicode_escape)
                .unwrap_err()
                .err,
            ParseErrors::InvalidEscaping
        ));

        assert!(
            matches!(ast::parser::v1::parse(string_with_valid_escape).unwrap()[0].pre_expr, PreSymbolicExpressionType::AtomValue(Value::Sequence(SequenceData::String(
                                     CharType::ASCII(ref v),
                                 ))) if v.data.len() == 11)
        );

        assert!(
            matches!(ast::parser::v1::parse(string_with_valid_double_escape).unwrap()[0].pre_expr,
                PreSymbolicExpressionType::AtomValue(Value::Sequence(SequenceData::String(
                    CharType::ASCII(ref v),
                ))) if v.data.len() == 12)
        );

        assert!(
            matches!(ast::parser::v1::parse(string_with_multiple_slashes).unwrap()[0].pre_expr,
                PreSymbolicExpressionType::AtomValue(Value::Sequence(SequenceData::String(
                    CharType::ASCII(ref v),
                ))) if v.data.len() == 12)
        );

        assert!(matches!(
            ast::parser::v1::parse(&exceeds_stack_depth_tuple)
                .unwrap_err()
                .err,
            ParseErrors::VaryExpressionStackDepthTooDeep
        ));

        assert!(matches!(
            ast::parser::v1::parse(&exceeds_stack_depth_list)
                .unwrap_err()
                .err,
            ParseErrors::VaryExpressionStackDepthTooDeep
        ));
    }

    #[test]
    fn test_long_contract_name() {
        let long_contract_name = "(define-private (transfer (id uint) (receiver principal)) (contract-call? 'SP3D6PV2ACBPEKYJTCMH7HEN02KP87QSP8KTEH335.megapont-robot-expansion-nftSPNWZ5V2TPWGQGVDR6T7B6RQ4XMGZ4PXTEE0VQ0S.guests-hosted-stacks-parrots transfer id tx-sender receiver))";
        assert!(matches!(
            ast::parser::v1::parse(long_contract_name).unwrap_err().err,
            ParseErrors::SeparatorExpected(_)
        ));
    }
}
