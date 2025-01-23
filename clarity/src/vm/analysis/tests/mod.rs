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

use crate::vm::analysis::mem_type_check as mem_run_analysis;
use crate::vm::analysis::type_checker::v2_1::tests::mem_type_check;
use crate::vm::ClarityVersion;

#[test]
fn test_list_types_must_match() {
    let snippet = "(list 1 true)";
    let err = mem_type_check(snippet).unwrap_err();
    assert!(
        format!("{}", err.diagnostic).contains("expecting expression of type 'int', found 'bool'")
    );
}

#[test]
fn test_type_error() {
    let snippet = "(+ true 1)";
    let err = mem_type_check(snippet).unwrap_err();
    println!("{}", err.diagnostic);
    assert!(format!("{}", err.diagnostic)
        .contains("expecting expression of type 'int' or 'uint', found 'bool'"));

    let snippet = "(+ 1 true)";
    let err = mem_type_check(snippet).unwrap_err();
    println!("{}", err.diagnostic);
    assert!(
        format!("{}", err.diagnostic).contains("expecting expression of type 'int', found 'bool'")
    );
}

#[test]
fn test_union_type_error() {
    let snippet = "(hash160 true)";
    let err = mem_type_check(snippet).unwrap_err();
    assert!(format!("{}", err.diagnostic)
        .contains("expecting expression of type '(buff 1048576)', 'uint' or 'int', found 'bool'"));
}

#[test]
fn test_expected_optional_type() {
    let snippet = "(is-none 1)";
    let err = mem_type_check(snippet).unwrap_err();
    assert!(format!("{}", err.diagnostic)
        .contains("expecting expression of type 'optional', found 'int'"));
}

#[test]
fn test_expected_response_type() {
    let snippet = "(is-ok 1)";
    let err = mem_type_check(snippet).unwrap_err();
    assert!(format!("{}", err.diagnostic)
        .contains("expecting expression of type 'response', found 'int'"));
}

#[test]
fn test_could_not_determine_response_ok_type() {
    let snippet = "(unwrap! (err \"error\") 0)";
    let err = mem_type_check(snippet).unwrap_err();
    assert!(format!("{}", err.diagnostic)
        .contains("attempted to obtain 'ok' value from response, but 'ok' type is indeterminate"));
}

#[test]
fn test_could_not_determine_response_err_type() {
    let snippet = "(unwrap-err! (ok 1) 0)";
    let err = mem_type_check(snippet).unwrap_err();
    assert!(format!("{}", err.diagnostic).contains(
        "attempted to obtain 'err' value from response, but 'err' type is indeterminate"
    ));
}

#[test]
fn test_bad_tuple_field_name() {
    let snippet = "(get 1 (tuple (value 100)))";
    let err = mem_type_check(snippet).unwrap_err();
    assert!(format!("{}", err.diagnostic).contains("invalid tuple field name"));
}

#[test]
fn test_bad_function_name_2() {
    // outside of the legal "implicit" tuple structures,
    //    things that look like ((value 100)) are evaluated as
    //    _function applications_, so this should error, since (value 100) isn't a function.
    let snippet = "(get 1 ((value 100)))";
    let err = mem_type_check(snippet).unwrap_err();
    println!("{}", err.diagnostic);
    assert!(format!("{}", err.diagnostic).contains("expecting expression of type function"));
}

#[test]
fn test_expected_tuple() {
    let snippet = "(get value 1)";
    let err = mem_type_check(snippet).unwrap_err();
    assert!(format!("{}", err.diagnostic).contains("expecting tuple, found 'int'"));
}

#[test]
fn test_no_such_tuple_field() {
    let snippet = "(get val (tuple (value 100)))";
    let err = mem_type_check(snippet).unwrap_err();
    assert!(format!("{}", err.diagnostic)
        .contains("cannot find field 'val' in tuple '(tuple (value int))'"));
}

#[test]
fn test_bad_tuple_construction() {
    let snippet = "(tuple (key 1) (key 2))";
    let err = mem_type_check(snippet).unwrap_err();
    assert!(format!("{}", err.diagnostic).contains("invalid tuple syntax, expecting list of pair"));
}

#[test]
fn test_tuple_expects_pairs() {
    let snippet = "(tuple (key 1) (key-with-missing-value))";
    let err = mem_type_check(snippet).unwrap_err();
    assert!(format!("{}", err.diagnostic).contains("invalid tuple syntax, expecting pair"));
}

#[test]
fn test_no_such_variable() {
    let snippet = "(var-get unicorn)";
    let err = mem_type_check(snippet).unwrap_err();
    assert!(
        format!("{}", err.diagnostic).contains("use of unresolved persisted variable 'unicorn'")
    );
}

#[test]
fn test_bad_map_name() {
    let snippet = "(define-map 1 { key: int } { value: int })";
    let err = mem_type_check(snippet).unwrap_err();
    assert!(format!("{}", err.diagnostic).contains("expected a name argument"));
}

#[test]
fn test_no_such_map() {
    let snippet = "(map-get? unicorn { key: 1 })";
    let err = mem_type_check(snippet).unwrap_err();
    assert!(format!("{}", err.diagnostic).contains("use of unresolved map 'unicorn'"));
}

#[test]
fn test_define_function_bad_signature() {
    let snippet = "(define-public test (ok 1))";
    let err = mem_type_check(snippet).unwrap_err();
    assert!(format!("{}", err.diagnostic).contains("invalid function definition"));
}

#[test]
fn test_bad_function_name() {
    let snippet = "(define-public (1) (ok 1))";
    let err = mem_type_check(snippet).unwrap_err();
    assert!(format!("{}", err.diagnostic).contains("invalid function name"));
}

#[test]
fn test_public_function_must_return_response() {
    let snippet = "(define-public (fn) 1)";
    let err = mem_type_check(snippet).unwrap_err();
    assert!(format!("{}", err.diagnostic)
        .contains("public functions must return an expression of type 'response', found 'int'"));
}

#[test]
fn test_define_variable_bad_signature() {
    let snippet = "(define-data-var 1 int 0)";
    let err = mem_type_check(snippet).unwrap_err();
    assert!(format!("{}", err.diagnostic).contains("expected a name argument"));
}

#[test]
fn test_return_types_must_match() {
    let snippet = "(define-private (mismatched) (begin (unwrap! (ok 1) false) 1))";
    let err = mem_type_check(snippet).unwrap_err();
    assert!(format!("{}", err.diagnostic)
        .contains("detected two execution paths, returning two different expression types"));
}

#[test]
fn test_contract_call_expect_name() {
    let snippet = "(contract-call? 1 fn)";
    let err = mem_type_check(snippet).unwrap_err();
    assert!(format!("{}", err.diagnostic).contains("missing contract name for call"));
}

#[test]
fn test_no_such_block_info_property() {
    let snippet = "(get-block-info? unicorn 1)";
    let err =
        mem_run_analysis(snippet, ClarityVersion::Clarity2, StacksEpochId::latest()).unwrap_err();
    assert!(format!("{}", err.diagnostic).contains("use of block unknown property 'unicorn'"));
}

#[test]
fn test_no_such_stacks_block_info_property() {
    let snippet = "(get-stacks-block-info? unicorn 1)";
    let err =
        mem_run_analysis(snippet, ClarityVersion::Clarity3, StacksEpochId::latest()).unwrap_err();
    assert!(
        format!("{}", err.diagnostic).contains("use of unknown stacks block property 'unicorn'")
    );
}

#[test]
fn test_no_such_tenure_info_property() {
    let snippet = "(get-tenure-info? unicorn 1)";
    let err =
        mem_run_analysis(snippet, ClarityVersion::Clarity3, StacksEpochId::latest()).unwrap_err();
    assert!(format!("{}", err.diagnostic).contains("use of unknown tenure property 'unicorn'"));
}

#[test]
fn test_get_block_info_expect_property_name() {
    let snippet = "(get-block-info? 0 1)";
    let err =
        mem_run_analysis(snippet, ClarityVersion::Clarity2, StacksEpochId::latest()).unwrap_err();
    assert!(format!("{}", err.diagnostic)
        .contains("missing property name for block info introspection"));
}

#[test]
fn test_get_stacks_block_info_expect_property_name() {
    let snippet = "(get-stacks-block-info? 0 1)";
    let err =
        mem_run_analysis(snippet, ClarityVersion::Clarity3, StacksEpochId::latest()).unwrap_err();
    assert!(format!("{}", err.diagnostic)
        .contains("missing property name for stacks block info introspection"));
}

#[test]
fn test_get_tenure_info_expect_property_name() {
    let snippet = "(get-tenure-info? 0 1)";
    let err =
        mem_run_analysis(snippet, ClarityVersion::Clarity3, StacksEpochId::latest()).unwrap_err();
    assert!(format!("{}", err.diagnostic)
        .contains("missing property name for tenure info introspection"));
}

#[test]
fn test_no_such_block_info_height() {
    let snippet = "(get-block-info? time 1)";
    let err =
        mem_run_analysis(snippet, ClarityVersion::Clarity2, StacksEpochId::latest()).unwrap_err();
    println!("{}", err.diagnostic);
    assert!(
        format!("{}", err.diagnostic).contains("expecting expression of type 'uint', found 'int'")
    );
}

#[test]
fn test_no_such_stacks_block_info_height() {
    let snippet = "(get-stacks-block-info? time 1)";
    let err =
        mem_run_analysis(snippet, ClarityVersion::Clarity3, StacksEpochId::latest()).unwrap_err();
    assert!(
        format!("{}", err.diagnostic).contains("expecting expression of type 'uint', found 'int'")
    );
}

#[test]
fn test_no_such_tenure_info_height() {
    let snippet = "(get-tenure-info? time 1)";
    let err =
        mem_run_analysis(snippet, ClarityVersion::Clarity3, StacksEpochId::latest()).unwrap_err();
    assert!(
        format!("{}", err.diagnostic).contains("expecting expression of type 'uint', found 'int'")
    );
}

#[test]
fn test_name_already_used() {
    let snippet = "(define-constant var1 true) (define-constant var1 1)";
    let err = mem_type_check(snippet).unwrap_err();
    assert!(format!("{}", err.diagnostic).contains("'var1' conflicts with previous value"));
}

#[test]
fn test_non_function_application() {
    let snippet = "(filter 1 (1 2 3 4))";
    let err = mem_type_check(snippet).unwrap_err();
    assert!(format!("{}", err.diagnostic).contains("expecting expression of type function"));
}

#[test]
fn test_expected_list_or_buff() {
    let snippet = "(filter not 4)";
    let err = mem_type_check(snippet).unwrap_err();
    assert!(format!("{}", err.diagnostic)
        .contains("expecting expression of type 'list', 'buff', 'string-ascii' or 'string-utf8'"));
}

#[test]
fn test_bad_let_syntax() {
    let snippet = "(let 1 (true))";
    let err = mem_type_check(snippet).unwrap_err();
    assert!(format!("{}", err.diagnostic).contains("invalid syntax of 'let'"));
}

#[test]
fn test_bad_syntax_binding() {
    let snippet = "(let (t ((0))) t)";
    let err = mem_type_check(snippet).unwrap_err();
    assert!(format!("{}", err.diagnostic).contains("invalid syntax binding"));
}

#[test]
fn test_unbound_variable() {
    let snippet = "(+ 1 unicorn)";
    let err = mem_type_check(snippet).unwrap_err();
    eprintln!("{}", err.diagnostic);
    assert!(format!("{}", err.diagnostic).contains("use of unresolved variable 'unicorn'"));
}

#[test]
fn test_variadic_needs_one_argument() {
    let snippet = "(begin)";
    let err = mem_type_check(snippet).unwrap_err();
    assert!(format!("{}", err.diagnostic).contains(""));
}

#[test]
fn test_incorrect_argument_count() {
    let snippet = "(define-map my-map { val: int })";
    let err = mem_type_check(snippet).unwrap_err();
    assert!(format!("{}", err.diagnostic).contains("expecting 3 arguments, got 2"));
}

#[test]
fn test_if_arms_must_match() {
    let snippet = "(if true true 1)";
    let err = mem_type_check(snippet).unwrap_err();
    assert!(format!("{}", err.diagnostic).contains(
        "expression types returned by the arms of 'if' must match (got 'bool' and 'int')"
    ));
}

#[test]
fn test_default_types_must_match() {
    let snippet = "(default-to 1 (some true))";
    let err = mem_type_check(snippet).unwrap_err();
    assert!(format!("{}", err.diagnostic)
        .contains("expression types passed in 'default-to' must match (got 'int' and 'bool')"));
}

#[test]
fn test_write_attempt_in_readonly() {
    let snippet = "(define-data-var x int 0) (define-read-only (fn) (var-set x 1))";
    let err = mem_type_check(snippet).unwrap_err();
    assert!(format!("{}", err.diagnostic)
        .contains("expecting read-only statements, detected a writing operation"));
}
