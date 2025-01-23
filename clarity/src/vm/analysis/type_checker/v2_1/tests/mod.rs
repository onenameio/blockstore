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

#[cfg(test)]
use rstest::rstest;
#[cfg(test)]
use rstest_reuse::{self, *};
use stacks_common::types::StacksEpochId;

use super::CheckResult;
use crate::vm::analysis::errors::CheckErrors;
use crate::vm::analysis::mem_type_check as mem_run_analysis;
use crate::vm::analysis::type_checker::v2_1::TypeResult;
use crate::vm::analysis::types::ContractAnalysis;
use crate::vm::ast::build_ast;
use crate::vm::ast::errors::ParseErrors;
use crate::vm::tests::test_clarity_versions;
use crate::vm::types::signatures::TypeSignature::OptionalType;
use crate::vm::types::signatures::{ListTypeData, StringUTF8Length};
use crate::vm::types::SequenceSubtype::*;
use crate::vm::types::StringSubtype::*;
use crate::vm::types::TypeSignature::{BoolType, IntType, PrincipalType, SequenceType, UIntType};
use crate::vm::types::{
    BufferLength, FixedFunction, FunctionType, QualifiedContractIdentifier, TraitIdentifier,
    TypeSignature, BUFF_1, BUFF_20, BUFF_21, BUFF_32, BUFF_64,
};
use crate::vm::{execute_v2, ClarityName, ClarityVersion};

mod assets;
pub mod contracts;

/// Backwards-compatibility shim for type_checker tests. Runs at latest Clarity version.
pub fn mem_type_check(exp: &str) -> CheckResult<(Option<TypeSignature>, ContractAnalysis)> {
    mem_run_analysis(
        exp,
        crate::vm::ClarityVersion::latest(),
        StacksEpochId::Epoch21,
    )
}

/// NOTE: runs at latest Clarity version
fn type_check_helper(exp: &str) -> TypeResult {
    mem_type_check(exp).map(|(type_sig_opt, _)| type_sig_opt.unwrap())
}

fn type_check_helper_version(exp: &str, version: ClarityVersion) -> TypeResult {
    mem_run_analysis(exp, version, StacksEpochId::latest())
        .map(|(type_sig_opt, _)| type_sig_opt.unwrap())
}

fn type_check_helper_v1(exp: &str) -> TypeResult {
    type_check_helper_version(exp, ClarityVersion::Clarity1)
}

fn buff_type(size: u32) -> TypeSignature {
    TypeSignature::SequenceType(BufferType(size.try_into().unwrap()))
}

fn ascii_type(size: u32) -> TypeSignature {
    TypeSignature::SequenceType(StringType(ASCII(size.try_into().unwrap())))
}

#[test]
fn test_from_consensus_buff() {
    let good = [
        ("(from-consensus-buff? int 0x00)", "(optional int)"),
        (
            "(from-consensus-buff? { a: uint, b: principal } 0x00)",
            "(optional (tuple (a uint) (b principal)))",
        ),
    ];

    let bad = [
        (
            "(from-consensus-buff?)",
            CheckErrors::IncorrectArgumentCount(2, 0),
        ),
        (
            "(from-consensus-buff? 0x00 0x00 0x00)",
            CheckErrors::IncorrectArgumentCount(2, 3),
        ),
        (
            "(from-consensus-buff? 0x00 0x00)",
            CheckErrors::InvalidTypeDescription,
        ),
        (
            "(from-consensus-buff? int u6)",
            CheckErrors::TypeError(
                TypeSignature::max_buffer().unwrap(),
                TypeSignature::UIntType,
            ),
        ),
        (
            "(from-consensus-buff? (buff 1048576) 0x00)",
            CheckErrors::ValueTooLarge,
        ),
    ];

    for (good_test, expected) in good.iter() {
        let type_result = type_check_helper(good_test).unwrap();
        assert_eq!(expected, &type_result.to_string());

        assert!(
            type_result
                .admits(
                    &StacksEpochId::Epoch21,
                    &execute_v2(good_test).unwrap().unwrap()
                )
                .unwrap(),
            "The analyzed type must admit the evaluated type"
        );
    }

    for (bad_test, expected) in bad.iter() {
        assert_eq!(expected, &type_check_helper(bad_test).unwrap_err().err);
    }
}

#[test]
fn test_to_consensus_buff() {
    let good = [
        (
            "(to-consensus-buff? (if true (some u1) (some u2)))",
            "(optional (buff 18))",
        ),
        (
            "(to-consensus-buff? (if true (ok u1) (ok u2)))",
            "(optional (buff 18))",
        ),
        (
            "(to-consensus-buff? (if true (ok 1) (err u2)))",
            "(optional (buff 18))",
        ),
        (
            "(to-consensus-buff? (if true (ok 1) (err true)))",
            "(optional (buff 18))",
        ),
        (
            "(to-consensus-buff? (if true (ok false) (err true)))",
            "(optional (buff 2))",
        ),
        (
            "(to-consensus-buff? (if true (err u1) (err u2)))",
            "(optional (buff 18))",
        ),
        ("(to-consensus-buff? none)", "(optional (buff 1))"),
        ("(to-consensus-buff? 0x00)", "(optional (buff 6))"),
        ("(to-consensus-buff? \"a\")", "(optional (buff 6))"),
        ("(to-consensus-buff? u\"ab\")", "(optional (buff 13))"),
        ("(to-consensus-buff? 'STB44HYPYAT2BB2QE513NSP81HTMYWBJP02HPGK6)", "(optional (buff 151))"),
        ("(to-consensus-buff? 'STB44HYPYAT2BB2QE513NSP81HTMYWBJP02HPGK6.abcdeabcdeabcdeabcdeabcdeabcdeabcdeabcde)", "(optional (buff 151))"),
        ("(to-consensus-buff? true)", "(optional (buff 1))"),
        ("(to-consensus-buff? -1)", "(optional (buff 17))"),
        ("(to-consensus-buff? u1)", "(optional (buff 17))"),
        ("(to-consensus-buff? (list 1 2 3 4))", "(optional (buff 73))"),
        (
            "(to-consensus-buff? { apple: u1, orange: 2, blue: true })",
            "(optional (buff 58))",
        ),
        (
            "(define-private (my-func (x (buff 1048566)))
           (to-consensus-buff? x))
          (my-func 0x001122334455)
         ",
            "(optional (buff 1048571))",
        ),
    ];

    let bad = [
        (
            "(to-consensus-buff?)",
            CheckErrors::IncorrectArgumentCount(1, 0),
        ),
        (
            "(to-consensus-buff? 0x00 0x00)",
            CheckErrors::IncorrectArgumentCount(1, 2),
        ),
        (
            "(define-private (my-func (x (buff 1048576)))
           (to-consensus-buff? x))",
            CheckErrors::ValueTooLarge,
        ),
        (
            "(define-private (my-func (x (buff 1048570)))
           (to-consensus-buff? x))",
            CheckErrors::ValueTooLarge,
        ),
        (
            "(define-private (my-func (x (buff 1048567)))
           (to-consensus-buff? x))",
            CheckErrors::ValueTooLarge,
        ),
    ];

    for (good_test, expected) in good.iter() {
        let type_result = type_check_helper(good_test).unwrap();
        assert_eq!(expected, &type_result.to_string());

        assert!(
            type_result
                .admits(
                    &StacksEpochId::Epoch21,
                    &execute_v2(good_test).unwrap().unwrap()
                )
                .unwrap(),
            "The analyzed type must admit the evaluated type"
        );
    }

    for (bad_test, expected) in bad.iter() {
        assert_eq!(expected, &type_check_helper(bad_test).unwrap_err().err);
    }
}

#[test]
fn test_get_block_info() {
    let good = [
        "(get-block-info? time u1)",
        "(get-block-info? time (* u2 u3))",
        "(get-block-info? vrf-seed u1)",
        "(get-block-info? header-hash u1)",
        "(get-block-info? burnchain-header-hash u1)",
        "(get-block-info? miner-address u1)",
    ];

    let good_v210 = [
        "(get-block-info? miner-spend-winner u1)",
        "(get-block-info? miner-spend-total u1)",
        "(get-block-info? block-reward u1)",
    ];

    let expected = [
        "(optional uint)",
        "(optional uint)",
        "(optional (buff 32))",
        "(optional (buff 32))",
        "(optional (buff 32))",
        "(optional principal)",
    ];

    let expected_v210 = ["(optional uint)", "(optional uint)", "(optional uint)"];

    let bad = [
        "(get-block-info? none u1)",
        "(get-block-info? time true)",
        "(get-block-info? time 1)",
        "(get-block-info? time)",
    ];
    let bad_expected = [
        CheckErrors::NoSuchBlockInfoProperty("none".to_string()),
        CheckErrors::TypeError(UIntType, BoolType),
        CheckErrors::TypeError(UIntType, IntType),
        CheckErrors::RequiresAtLeastArguments(2, 1),
    ];

    for (good_test, expected) in good.iter().zip(expected.iter()) {
        assert_eq!(
            expected,
            &format!(
                "{}",
                type_check_helper_version(good_test, ClarityVersion::Clarity2).unwrap()
            )
        );
    }
    for (good_test_v210, expected_v210) in good_v210.iter().zip(expected_v210.iter()) {
        assert_eq!(
            expected_v210,
            &format!(
                "{}",
                type_check_helper_version(good_test_v210, ClarityVersion::Clarity2).unwrap()
            )
        );
    }

    for (bad_test, expected) in bad.iter().zip(bad_expected.iter()) {
        assert_eq!(
            expected,
            &type_check_helper_version(bad_test, ClarityVersion::Clarity2)
                .unwrap_err()
                .err
        );
    }

    for good_test in good_v210.iter() {
        if let CheckErrors::NoSuchBlockInfoProperty(_) =
            type_check_helper_v1(good_test).unwrap_err().err
        {
        } else {
            panic!("Failed to get a typecheck error when using a v2 property in a v1 context");
        }
    }
}

#[test]
fn test_get_burn_block_info() {
    let good = ["(get-burn-block-info? header-hash u0)"];
    let expected = ["(optional (buff 32))"];

    let bad = [
        "(get-burn-block-info? none u1)",
        "(get-burn-block-info?)",
        "(get-burn-block-info? header-hash)",
        r#"(get-burn-block-info? header-hash "a")"#,
    ];
    let bad_expected = [
        CheckErrors::NoSuchBlockInfoProperty("none".to_string()),
        CheckErrors::IncorrectArgumentCount(2, 0),
        CheckErrors::IncorrectArgumentCount(2, 1),
        CheckErrors::TypeError(
            UIntType,
            SequenceType(StringType(ASCII(
                BufferLength::try_from(1u32).expect("BufferLength::try_from failed"),
            ))),
        ),
    ];

    for (good_test, expected) in good.iter().zip(expected.iter()) {
        assert_eq!(
            expected,
            &format!("{}", type_check_helper(good_test).unwrap())
        );
    }

    for (bad_test, expected) in bad.iter().zip(bad_expected.iter()) {
        assert_eq!(expected, &type_check_helper(bad_test).unwrap_err().err);
    }
}

#[apply(test_clarity_versions)]
fn test_define_trait(#[case] version: ClarityVersion, #[case] epoch: StacksEpochId) {
    let good = [
        "(define-trait trait-1 ((get-1 (uint) (response uint uint))))",
        "(define-trait trait-1 ((get-1 () (response uint (buff 32)))))",
        "(define-trait trait-1 ((get-1 () (response (buff 32) (buff 32)))))",
    ];

    for good_test in good.iter() {
        mem_type_check(good_test).unwrap();
    }

    let bad = [
        "(define-trait trait-1 ((get-1 uint)))",
        "(define-trait trait-1 ((get-1 uint uint)))",
        "(define-trait trait-1 ((get-1 (uint) (uint))))",
        "(define-trait trait-1 ((get-1 (response uint uint))))",
        "(define-trait trait-1)",
        "(define-trait)",
    ];
    let bad_expected = [
        CheckErrors::InvalidTypeDescription,
        CheckErrors::DefineTraitBadSignature,
        CheckErrors::DefineTraitBadSignature,
        CheckErrors::InvalidTypeDescription,
    ];

    for (bad_test, expected) in bad.iter().zip(bad_expected.iter()) {
        assert_eq!(expected, &type_check_helper(bad_test).unwrap_err().err);
    }

    let bad = ["(define-trait trait-1)", "(define-trait)"];
    let bad_expected = [
        ParseErrors::DefineTraitBadSignature,
        ParseErrors::DefineTraitBadSignature,
    ];

    let contract_identifier = QualifiedContractIdentifier::transient();
    for (bad_test, expected) in bad.iter().zip(bad_expected.iter()) {
        let res = build_ast(&contract_identifier, bad_test, &mut (), version, epoch).unwrap_err();
        assert_eq!(expected, &res.err);
    }
}

#[apply(test_clarity_versions)]
fn test_use_trait(#[case] version: ClarityVersion, #[case] epoch: StacksEpochId) {
    let bad = [
        "(use-trait trait-1 ((get-1 (uint) (response uint uint))))",
        "(use-trait trait-1 ((get-1 uint)))",
        "(use-trait trait-1)",
        "(use-trait)",
    ];
    let bad_expected = [
        ParseErrors::ImportTraitBadSignature,
        ParseErrors::ImportTraitBadSignature,
        ParseErrors::ImportTraitBadSignature,
        ParseErrors::ImportTraitBadSignature,
    ];

    let contract_identifier = QualifiedContractIdentifier::transient();
    for (bad_test, expected) in bad.iter().zip(bad_expected.iter()) {
        let res = build_ast(&contract_identifier, bad_test, &mut (), version, epoch).unwrap_err();
        assert_eq!(expected, &res.err);
    }
}

#[apply(test_clarity_versions)]
fn test_impl_trait(#[case] version: ClarityVersion, #[case] epoch: StacksEpochId) {
    let bad = ["(impl-trait trait-1)", "(impl-trait)"];
    let bad_expected = [
        ParseErrors::ImplTraitBadSignature,
        ParseErrors::ImplTraitBadSignature,
    ];

    let contract_identifier = QualifiedContractIdentifier::transient();
    for (bad_test, expected) in bad.iter().zip(bad_expected.iter()) {
        let res = build_ast(&contract_identifier, bad_test, &mut (), version, epoch).unwrap_err();
        assert_eq!(expected, &res.err);
    }
}

#[test]
fn test_stx_ops() {
    let good = [
        "(stx-burn? u10 'SM2J6ZY48GV1EZ5V2V5RB9MP66SW86PYKKQVX8X0G)",
        r#"(stx-transfer? u10 tx-sender 'SM2J6ZY48GV1EZ5V2V5RB9MP66SW86PYKKQVX8X0G)"#,
        r#"(stx-transfer-memo? u10 tx-sender 'SM2J6ZY48GV1EZ5V2V5RB9MP66SW86PYKKQVX8X0G 0x0102)"#,
        "(stx-get-balance 'SM2J6ZY48GV1EZ5V2V5RB9MP66SW86PYKKQVX8X0G)",
    ];
    let expected = [
        "(response bool uint)",
        "(response bool uint)",
        "(response bool uint)",
        "uint",
    ];

    let bad = [
        r#"(stx-transfer? u4 'SZ2J6ZY48GV1EZ5V2V5RB9MP66SW86PYKKQ9H6DPR 0x7759)"#,
        r#"(stx-transfer? 4 'SZ2J6ZY48GV1EZ5V2V5RB9MP66SW86PYKKQ9H6DPR 'SZ2J6ZY48GV1EZ5V2V5RB9MP66SW86PYKKQ9H6DPR)"#,
        r#"(stx-transfer? 4 'SZ2J6ZY48GV1EZ5V2V5RB9MP66SW86PYKKQ9H6DPR 'SZ2J6ZY48GV1EZ5V2V5RB9MP66SW86PYKKQ9H6DPR true 0x00)"#,
        r#"(stx-transfer? u4 u3  'SZ2J6ZY48GV1EZ5V2V5RB9MP66SW86PYKKQ9H6DPR)"#,
        r#"(stx-transfer? u4 'SZ2J6ZY48GV1EZ5V2V5RB9MP66SW86PYKKQ9H6DPR true)"#,
        r#"(stx-transfer? u10 tx-sponsor? 'SM2J6ZY48GV1EZ5V2V5RB9MP66SW86PYKKQVX8X0G)"#,
        r#"(stx-transfer? u10 tx-sender 'SM2J6ZY48GV1EZ5V2V5RB9MP66SW86PYKKQVX8X0G 0x0102)"#,  // valid arguments for stx-transfer-memo
        r#"(stx-transfer-memo? u4 'SZ2J6ZY48GV1EZ5V2V5RB9MP66SW86PYKKQ9H6DPR 0x7759 0x0102)"#,
        r#"(stx-transfer-memo? 4 'SZ2J6ZY48GV1EZ5V2V5RB9MP66SW86PYKKQ9H6DPR 'SZ2J6ZY48GV1EZ5V2V5RB9MP66SW86PYKKQ9H6DPR 0x0102)"#,
        r#"(stx-transfer-memo? 4 'SZ2J6ZY48GV1EZ5V2V5RB9MP66SW86PYKKQ9H6DPR 'SZ2J6ZY48GV1EZ5V2V5RB9MP66SW86PYKKQ9H6DPR true 0x00) 0x0102"#,
        r#"(stx-transfer-memo? u4 u3  'SZ2J6ZY48GV1EZ5V2V5RB9MP66SW86PYKKQ9H6DPR 0x0102)"#,
        r#"(stx-transfer-memo? u4 'SZ2J6ZY48GV1EZ5V2V5RB9MP66SW86PYKKQ9H6DPR true 0x0102)"#,
        r#"(stx-transfer-memo? u10 tx-sponsor? 'SM2J6ZY48GV1EZ5V2V5RB9MP66SW86PYKKQVX8X0G 0x0102)"#,
        r#"(stx-transfer-memo? u10 tx-sender 'SM2J6ZY48GV1EZ5V2V5RB9MP66SW86PYKKQVX8X0G)"#,  // valid arguments for stx-transfer
        "(stx-burn? u4)",
        "(stx-burn? 4 'SZ2J6ZY48GV1EZ5V2V5RB9MP66SW86PYKKQ9H6DPR)",
        "(stx-burn? u4 true)",
        "(stx-burn? u4 'SZ2J6ZY48GV1EZ5V2V5RB9MP66SW86PYKKQ9H6DPR 'SZ2J6ZY48GV1EZ5V2V5RB9MP66SW86PYKKQ9H6DPR)",
        "(stx-get-balance true)",
        "(stx-get-balance 'SZ2J6ZY48GV1EZ5V2V5RB9MP66SW86PYKKQ9H6DPR 'SZ2J6ZY48GV1EZ5V2V5RB9MP66SW86PYKKQ9H6DPR)"
    ];
    let bad_expected = [
        CheckErrors::TypeError(
            PrincipalType,
            SequenceType(BufferType(BufferLength::try_from(2_u32).unwrap())),
        ),
        CheckErrors::TypeError(UIntType, IntType),
        CheckErrors::IncorrectArgumentCount(3, 5),
        CheckErrors::TypeError(PrincipalType, UIntType),
        CheckErrors::TypeError(PrincipalType, BoolType),
        CheckErrors::TypeError(PrincipalType, OptionalType(Box::from(PrincipalType))),
        CheckErrors::IncorrectArgumentCount(3, 4),
        CheckErrors::TypeError(
            PrincipalType,
            SequenceType(BufferType(BufferLength::try_from(2_u32).unwrap())),
        ),
        CheckErrors::TypeError(UIntType, IntType),
        CheckErrors::IncorrectArgumentCount(4, 5),
        CheckErrors::TypeError(PrincipalType, UIntType),
        CheckErrors::TypeError(PrincipalType, BoolType),
        CheckErrors::TypeError(PrincipalType, OptionalType(Box::from(PrincipalType))),
        CheckErrors::IncorrectArgumentCount(4, 3),
        CheckErrors::IncorrectArgumentCount(2, 1),
        CheckErrors::TypeError(UIntType, IntType),
        CheckErrors::TypeError(PrincipalType, BoolType),
        CheckErrors::IncorrectArgumentCount(2, 3),
        CheckErrors::TypeError(PrincipalType, BoolType),
        CheckErrors::IncorrectArgumentCount(1, 2),
    ];

    for (good_test, expected) in good.iter().zip(expected.iter()) {
        assert_eq!(
            expected,
            &format!("{}", type_check_helper(good_test).unwrap())
        );
    }

    for (bad_test, expected) in bad.iter().zip(bad_expected.iter()) {
        assert_eq!(expected, &type_check_helper(bad_test).unwrap_err().err);
    }
}

#[test]
fn test_tx_sponsor() {
    let good = [
        "(if (is-some tx-sponsor?) (ok true) (err 4))",
        "(if (is-none tx-sponsor?) (ok true) (err 4))",
        "(match tx-sponsor? sponsor (ok 3) (err u5))",
    ];
    let expected = [
        "(response bool int)",
        "(response bool int)",
        "(response int uint)",
    ];

    let bad = ["(stx-transfer? u10 tx-sponsor? 'SM2J6ZY48GV1EZ5V2V5RB9MP66SW86PYKKQVX8X0G)"];
    let bad_expected = [CheckErrors::TypeError(
        PrincipalType,
        OptionalType(Box::from(PrincipalType)),
    )];

    for (good_test, expected) in good.iter().zip(expected.iter()) {
        assert_eq!(
            expected,
            &format!("{}", type_check_helper(good_test).unwrap())
        );
    }

    for (bad_test, expected) in bad.iter().zip(bad_expected.iter()) {
        assert_eq!(expected, &type_check_helper(bad_test).unwrap_err().err);
    }
}

#[apply(test_clarity_versions)]
fn test_destructuring_opts(#[case] version: ClarityVersion, #[case] epoch: StacksEpochId) {
    let good = [
        "(unwrap! (some 1) 2)",
        "(unwrap-err! (err 1) 2)",
        "(unwrap! (ok 3) 2)",
        "(unwrap-panic (ok 3))",
        "(unwrap-panic (some 3))",
        "(unwrap-err-panic (err 3))",
        "(match (some 1) inner-value (+ 1 inner-value) (/ 1 0))",
        "(define-private (foo) (if (> 1 0) (ok 1) (err 8)))
         (match (foo) ok-val (+ 1 ok-val) err-val (/ err-val 0))",
        "(define-private (t1 (x uint)) (if (> x u1) (ok x) (err false)))
         (define-private (t2 (x uint))
           (if (> x u4)
               (err true)
               (ok (+ u2 (try! (t1 x))))))
         (t2 u3)",
        "(define-private (t1 (x uint)) (if (> x u1) (ok x) (err false)))
         (define-private (t2 (x uint))
           (if (> x u4)
               (err true)
               (ok (> u2 (try! (t1 x))))))
         (t2 u3)",
        "(define-private (t1 (x uint)) (if (> x u1) (some x) none))
         (define-private (t2 (x uint))
           (if (> x u4)
               (some false)
               (some (> u2 (try! (t1 x))))))
         (t2 u3)",
    ];

    let expected = [
        "int",
        "int",
        "int",
        "int",
        "int",
        "int",
        "int",
        "int",
        "(response uint bool)",
        "(response bool bool)",
        "(optional bool)",
    ];

    assert_eq!(expected.len(), good.len());

    let bad = [
        (
            "(unwrap-err! (some 2) 2)",
            CheckErrors::ExpectedResponseType(TypeSignature::from_string(
                "(optional int)",
                version,
                epoch,
            )),
        ),
        (
            "(unwrap! (err 3) 2)",
            CheckErrors::CouldNotDetermineResponseOkType,
        ),
        (
            "(unwrap-err-panic (ok 3))",
            CheckErrors::CouldNotDetermineResponseErrType,
        ),
        (
            "(unwrap-panic none)",
            CheckErrors::CouldNotDetermineResponseOkType,
        ),
        (
            "(define-private (foo) (if (> 1 0) none none)) (unwrap-panic (foo))",
            CheckErrors::CouldNotDetermineResponseOkType,
        ),
        (
            "(unwrap-panic (err 3))",
            CheckErrors::CouldNotDetermineResponseOkType,
        ),
        (
            "(match none inner-value (/ 1 0) (+ 1 8))",
            CheckErrors::CouldNotDetermineMatchTypes,
        ),
        (
            "(match (ok 1) ok-val (/ ok-val 0) err-val (+ err-val 7))",
            CheckErrors::CouldNotDetermineMatchTypes,
        ),
        (
            "(match (err 1) ok-val (/ ok-val 0) err-val (+ err-val 7))",
            CheckErrors::CouldNotDetermineMatchTypes,
        ),
        (
            "(define-private (foo) (if (> 1 0) (ok 1) (err u8)))
         (match (foo) ok-val (+ 1 ok-val) err-val (/ err-val u0))",
            CheckErrors::MatchArmsMustMatch(TypeSignature::IntType, TypeSignature::UIntType),
        ),
        (
            "(match (some 1) inner-value (+ 1 inner-value) (> 1 28))",
            CheckErrors::MatchArmsMustMatch(TypeSignature::IntType, TypeSignature::BoolType),
        ),
        (
            "(match (some 1) inner-value (+ 1 inner-value))",
            CheckErrors::BadMatchOptionSyntax(Box::new(CheckErrors::IncorrectArgumentCount(4, 3))),
        ),
        (
            "(match (ok 1) inner-value (+ 1 inner-value))",
            CheckErrors::BadMatchResponseSyntax(Box::new(CheckErrors::IncorrectArgumentCount(
                5, 3,
            ))),
        ),
        (
            "(match (ok 1) 1 (+ 1 1) err-val (+ 2 err-val))",
            CheckErrors::BadMatchResponseSyntax(Box::new(CheckErrors::ExpectedName)),
        ),
        (
            "(match (ok 1) ok-val (+ 1 1) (+ 3 4) (+ 2 err-val))",
            CheckErrors::BadMatchResponseSyntax(Box::new(CheckErrors::ExpectedName)),
        ),
        (
            "(match (some 1) 2 (+ 1 1) (+ 3 4))",
            CheckErrors::BadMatchOptionSyntax(Box::new(CheckErrors::ExpectedName)),
        ),
        ("(match)", CheckErrors::RequiresAtLeastArguments(1, 0)),
        (
            "(match 1 ok-val (/ ok-val 0) err-val (+ err-val 7))",
            CheckErrors::BadMatchInput(TypeSignature::from_string("int", version, epoch)),
        ),
        (
            "(default-to 3 5)",
            CheckErrors::ExpectedOptionalType(TypeSignature::IntType),
        ),
        (
            "(define-private (foo (x int))
           (match (some 3)
             x (+ x 2)
             5))",
            CheckErrors::NameAlreadyUsed("x".to_string()),
        ),
        (
            "(define-private (t1 (x uint)) (if (> x u1) (ok x) (err false)))
         (define-private (t2 (x uint))
           (if (> x u4)
               (err u3)
               (ok (+ u2 (try! (t1 x))))))",
            CheckErrors::ReturnTypesMustMatch(
                TypeSignature::new_response(TypeSignature::NoType, TypeSignature::BoolType)
                    .unwrap(),
                TypeSignature::new_response(TypeSignature::UIntType, TypeSignature::UIntType)
                    .unwrap(),
            ),
        ),
        (
            "(define-private (t1 (x uint)) (if (> x u1) (ok x) (err false)))
         (define-private (t2 (x uint))
           (> u2 (try! (t1 x))))",
            CheckErrors::ReturnTypesMustMatch(
                TypeSignature::new_response(TypeSignature::NoType, TypeSignature::BoolType)
                    .unwrap(),
                TypeSignature::BoolType,
            ),
        ),
        (
            "(try! (ok 3))",
            CheckErrors::CouldNotDetermineResponseErrType,
        ),
        ("(try! none)", CheckErrors::CouldNotDetermineResponseOkType),
        (
            "(try! (err 3))",
            CheckErrors::CouldNotDetermineResponseOkType,
        ),
        (
            "(try! 3)",
            CheckErrors::ExpectedOptionalOrResponseType(TypeSignature::IntType),
        ),
        ("(try! (ok 3) 4)", CheckErrors::IncorrectArgumentCount(1, 2)),
    ];

    for (good_test, expected) in good.iter().zip(expected.iter()) {
        assert_eq!(
            expected,
            &format!("{}", type_check_helper(good_test).unwrap())
        );
    }

    for (bad_test, expected) in bad.iter() {
        assert_eq!(expected, &mem_type_check(bad_test).unwrap_err().err);
    }
}

#[test]
fn test_at_block() {
    let good = [("(at-block (sha256 u0) u1)", "uint")];

    let bad = [
        (
            "(at-block (sha512 u0) u1)",
            CheckErrors::TypeError(BUFF_32.clone(), BUFF_64.clone()),
        ),
        (
            "(at-block (sha256 u0) u1 u2)",
            CheckErrors::IncorrectArgumentCount(2, 3),
        ),
    ];

    for (good_test, expected) in good.iter() {
        assert_eq!(
            expected,
            &format!("{}", type_check_helper(good_test).unwrap())
        );
    }

    for (bad_test, expected) in bad.iter() {
        assert_eq!(expected, &type_check_helper(bad_test).unwrap_err().err);
    }
}

#[apply(test_clarity_versions)]
fn test_trait_reference_unknown(#[case] version: ClarityVersion, #[case] epoch: StacksEpochId) {
    let bad = [(
        "(+ 1 <kvstore>)",
        ParseErrors::TraitReferenceUnknown("kvstore".to_string()),
    )];

    let contract_identifier = QualifiedContractIdentifier::transient();
    for (bad_test, expected) in bad.iter() {
        let res = build_ast(&contract_identifier, bad_test, &mut (), version, epoch).unwrap_err();
        assert_eq!(expected, &res.err);
    }
}

#[test]
fn test_unexpected_use_of_field_or_trait_reference() {
    let bad = [(
        "(+ 1 'SZ2J6ZY48GV1EZ5V2V5RB9MP66SW86PYKKQ9H6DPR.contract.field)",
        CheckErrors::UnexpectedTraitOrFieldReference,
    )];

    for (bad_test, expected) in bad.iter() {
        assert_eq!(expected, &type_check_helper(bad_test).unwrap_err().err);
    }
}

#[test]
fn test_bitwise_good_checks() {
    let good = [
        "(bit-and 24 16)",
        "(bit-xor u24 u16)",
        "(bit-or 2 1)",
        "(bit-shift-left 1 u2)",
        "(bit-shift-right u1 u2)",
        "(bit-or 1 2 4)",
        "(bit-or -1 -2 4)",
        "(bit-or u1 u2 u4)",
    ];
    let expected = ["int", "uint", "int", "int", "uint", "int", "int", "uint"];

    for (good_test, expected) in good.iter().zip(expected.iter()) {
        assert_eq!(
            expected,
            &format!("{}", type_check_helper(good_test).unwrap())
        );
    }
}

#[test]
fn test_bitwise_bad_checks() {
    let bad = [
        "(xor 1)",
        "(bit-xor 1 u2)",
        "(bit-or u2 1)",
        "(bit-not \"hello\")",
        "(bit-not 1 2)",
        "(bit-and 1 u2)",
        "(bit-shift-right 1)",
        "(bit-shift-left 1)",
        "(bit-shift-left true false)",
        "(bit-shift-right 1 1)",
        "(bit-shift-left 2 1)",
        "(bit-or 1 2 u4)",
    ];
    let bad_expected = [
        CheckErrors::IncorrectArgumentCount(2, 1),
        CheckErrors::TypeError(IntType, UIntType),
        CheckErrors::TypeError(UIntType, IntType),
        CheckErrors::UnionTypeError(
            vec![IntType, UIntType],
            SequenceType(StringType(ASCII(BufferLength::try_from(5u32).unwrap()))),
        ),
        CheckErrors::IncorrectArgumentCount(1, 2),
        CheckErrors::TypeError(IntType, UIntType),
        CheckErrors::IncorrectArgumentCount(2, 1),
        CheckErrors::IncorrectArgumentCount(2, 1),
        CheckErrors::UnionTypeError(vec![IntType, UIntType], BoolType),
        CheckErrors::TypeError(UIntType, IntType),
        CheckErrors::TypeError(UIntType, IntType),
        CheckErrors::TypeError(IntType, UIntType),
    ];

    for (bad_test, expected) in bad.iter().zip(bad_expected.iter()) {
        assert_eq!(expected, &type_check_helper(bad_test).unwrap_err().err);
    }
}

#[test]
fn test_simple_arithmetic_checks() {
    let good = [
        "(>= (+ 1 2 3) (- 1 2))",
        "(is-eq (+ 1 2 3) 6 0)",
        "(and (or true false) false)",
    ];
    let expected = ["bool", "bool", "bool"];
    let bad = [
        "(+ 1 2 3 (>= 5 7))",
        "(-)",
        "(xor 1)",
        "(+ x y z)", // unbound variables.
        "(+ 1 2 3 (is-eq 1 2))",
        "(and (or true false) (+ 1 2 3))",
    ];
    let bad_expected = [
        CheckErrors::TypeError(IntType, BoolType),
        CheckErrors::RequiresAtLeastArguments(1, 0),
        CheckErrors::IncorrectArgumentCount(2, 1),
        CheckErrors::UndefinedVariable("x".to_string()),
        CheckErrors::TypeError(IntType, BoolType),
        CheckErrors::TypeError(BoolType, IntType),
    ];

    for (good_test, expected) in good.iter().zip(expected.iter()) {
        assert_eq!(
            expected,
            &format!("{}", type_check_helper(good_test).unwrap())
        );
    }

    for (bad_test, expected) in bad.iter().zip(bad_expected.iter()) {
        assert_eq!(expected, &type_check_helper(bad_test).unwrap_err().err);
    }
}

#[test]
fn test_simple_hash_checks() {
    let good = [
        "(hash160 u1)",
        "(hash160 1)",
        "(sha512 u10)",
        "(sha512 10)",
        "(sha512/256 u10)",
        "(sha512/256 10)",
        "(sha256 (keccak256 u1))",
        "(sha256 (keccak256 1))",
    ];
    let expected = [
        "(buff 20)",
        "(buff 20)",
        "(buff 64)",
        "(buff 64)",
        "(buff 32)",
        "(buff 32)",
        "(buff 32)",
        "(buff 32)",
    ];

    let bad_types = [
        "(hash160 true)",
        "(sha256 false)",
        "(sha512 false)",
        "(sha512/256 false)",
        "(keccak256 (list 1 2 3))",
    ];
    let invalid_args = [
        "(sha256 u1 u2 u3)",
        "(sha512 u1 u2 u3)",
        "(sha512/256 u1 u2 u3)",
    ];

    for (good_test, expected) in good.iter().zip(expected.iter()) {
        assert_eq!(
            expected,
            &format!("{}", type_check_helper(good_test).unwrap())
        );
    }

    for bad_test in bad_types.iter() {
        assert!(matches!(
            type_check_helper(bad_test).unwrap_err().err,
            CheckErrors::UnionTypeError(_, _)
        ));
    }

    for bad_test in invalid_args.iter() {
        assert!(matches!(
            type_check_helper(bad_test).unwrap_err().err,
            CheckErrors::IncorrectArgumentCount(_, _)
        ));
    }
}

#[test]
fn test_simple_ifs() {
    let good = [
        "(if (> 1 2) (+ 1 2 3) (- 1 2))",
        "(if true true false)",
        "(if true \"abcdef\" \"abc\")",
        "(if true \"a\" \"abcdef\")",
    ];
    let expected = ["int", "bool", "(string-ascii 6)", "(string-ascii 6)"];

    let bad = [
        "(if true true 1)",
        "(if true \"a\" false)",
        "(if)",
        "(if 0 1 0)",
    ];

    let bad_expected = [
        CheckErrors::IfArmsMustMatch(BoolType, IntType),
        CheckErrors::IfArmsMustMatch(ascii_type(1), BoolType),
        CheckErrors::IncorrectArgumentCount(3, 0),
        CheckErrors::TypeError(BoolType, IntType),
    ];

    for (good_test, expected) in good.iter().zip(expected.iter()) {
        assert_eq!(
            expected,
            &format!("{}", type_check_helper(good_test).unwrap())
        );
    }

    for (bad_test, expected) in bad.iter().zip(bad_expected.iter()) {
        assert_eq!(expected, &type_check_helper(bad_test).unwrap_err().err);
    }
}

#[test]
fn test_simple_lets() {
    let good = [
        "(let ((x 1) (y 2) (z 3)) (if (> x 2) (+ 1 x y) (- 1 z)))",
        "(let ((x true) (y (+ 1 2)) (z 3)) (if x (+ 1 z y) (- 1 z)))",
        "(let ((x true) (y (+ 1 2)) (z 3)) (print x) (if x (+ 1 z y) (- 1 z)))",
        "(let ((x 1) (y u2) (z u3) (a (+ y z)) (b (* 2 x)) (c { foo: a, bar: b })) c)",
    ];

    let expected = ["int", "int", "int", "(tuple (bar int) (foo uint))"];

    let bad = [
        "(let ((1)) (+ 1 2))",
        "(let ((1 2)) (+ 1 2))",
        "(let ((x 1) (y u2) (z (+ x y))) x)",
    ];

    let bad_expected = [
        CheckErrors::BadSyntaxBinding,
        CheckErrors::BadSyntaxBinding,
        CheckErrors::TypeError(TypeSignature::IntType, TypeSignature::UIntType),
    ];

    for (good_test, expected) in good.iter().zip(expected.iter()) {
        assert_eq!(
            expected,
            &format!("{}", type_check_helper(good_test).unwrap())
        );
    }

    for (bad_test, expected) in bad.iter().zip(bad_expected.iter()) {
        assert_eq!(expected, &type_check_helper(bad_test).unwrap_err().err);
    }
}

#[test]
fn test_index_of() {
    let good = [
        "(index-of (list 1 2 3 4 5 4) 100)",
        "(index-of (list 1 2 3 4 5 4) 4)",
        "(index-of \"abcd\" \"a\")",
        "(index-of u\"abcd\" u\"a\")",
        "(index-of 0xfedb 0xdb)",
        "(index-of \"abcd\" \"\")",
        "(index-of u\"abcd\" u\"\")",
        "(index-of 0xfedb 0x)",
        "(index-of \"abcd\" \"z\")",
        "(index-of u\"abcd\" u\"e\")",
        "(index-of 0xfedb 0x01)",
        "(index-of (list (list 1) (list 2)) (list))",
        "(index-of? (list 1 2 3 4 5 4) 100)",
        "(index-of? (list 1 2 3 4 5 4) 4)",
        "(index-of? \"abcd\" \"a\")",
        "(index-of? u\"abcd\" u\"a\")",
        "(index-of? 0xfedb 0xdb)",
        "(index-of? \"abcd\" \"\")",
        "(index-of? u\"abcd\" u\"\")",
        "(index-of? 0xfedb 0x)",
        "(index-of? \"abcd\" \"z\")",
        "(index-of? u\"abcd\" u\"e\")",
        "(index-of? 0xfedb 0x01)",
    ];

    let expected = "(optional uint)";

    for good_test in good.iter() {
        assert_eq!(
            expected,
            &format!("{}", type_check_helper(good_test).unwrap())
        );
    }

    let bad = [
        "(index-of 3 \"a\")",
        "(index-of (list 1 2 3 4) u1)",
        "(index-of 0xfedb \"a\")",
        "(index-of u\"a\" \"a\")",
        "(index-of \"a\" u\"a\")",
        "(index-of (list (list 1) (list 2)) (list 33 44))",
        "(index-of? 3 \"a\")",
        "(index-of? (list 1 2 3 4) u1)",
        "(index-of? 0xfedb \"a\")",
        "(index-of? u\"a\" \"a\")",
        "(index-of? \"a\" u\"a\")",
        "(index-of (list) none)",    // cannot determine type of list element
        "(index-of (list) (ok u1))", // cannot determine complete type of list element
        "(index-of (list) (err none))", // cannot determine complete type of list element
    ];

    let bad_expected = [
        CheckErrors::ExpectedSequence(TypeSignature::IntType),
        CheckErrors::TypeError(TypeSignature::IntType, TypeSignature::UIntType),
        CheckErrors::TypeError(
            TypeSignature::min_buffer().unwrap(),
            TypeSignature::min_string_ascii().unwrap(),
        ),
        CheckErrors::TypeError(
            TypeSignature::min_string_utf8().unwrap(),
            TypeSignature::min_string_ascii().unwrap(),
        ),
        CheckErrors::TypeError(
            TypeSignature::min_string_ascii().unwrap(),
            TypeSignature::min_string_utf8().unwrap(),
        ),
        CheckErrors::TypeError(
            TypeSignature::list_of(TypeSignature::IntType, 1).unwrap(),
            TypeSignature::list_of(TypeSignature::IntType, 2).unwrap(),
        ),
        CheckErrors::ExpectedSequence(TypeSignature::IntType),
        CheckErrors::TypeError(TypeSignature::IntType, TypeSignature::UIntType),
        CheckErrors::TypeError(
            TypeSignature::min_buffer().unwrap(),
            TypeSignature::min_string_ascii().unwrap(),
        ),
        CheckErrors::TypeError(
            TypeSignature::min_string_utf8().unwrap(),
            TypeSignature::min_string_ascii().unwrap(),
        ),
        CheckErrors::TypeError(
            TypeSignature::min_string_ascii().unwrap(),
            TypeSignature::min_string_utf8().unwrap(),
        ),
        CheckErrors::CouldNotDetermineType,
        CheckErrors::CouldNotDetermineType,
        CheckErrors::CouldNotDetermineType,
    ];

    for (bad_test, expected) in bad.iter().zip(bad_expected.iter()) {
        assert_eq!(expected, &type_check_helper(bad_test).unwrap_err().err);
    }
}

#[test]
fn test_element_at() {
    let good = [
        "(element-at (list 1 2 3 4 5) u100)",
        "(element-at (list 1 2 3 4 5) (+ u1 u2))",
        "(element-at \"abcd\" u100)",
        "(element-at 0xfedb u100)",
        "(element-at u\"abcd\" u100)",
        "(element-at? (list 1 2 3 4 5) u100)",
        "(element-at? (list 1 2 3 4 5) (+ u1 u2))",
        "(element-at? \"abcd\" u100)",
        "(element-at? 0xfedb u100)",
        "(element-at? u\"abcd\" u100)",
    ];

    let expected = [
        "(optional int)",
        "(optional int)",
        "(optional (string-ascii 1))",
        "(optional (buff 1))",
        "(optional (string-utf8 1))",
        "(optional int)",
        "(optional int)",
        "(optional (string-ascii 1))",
        "(optional (buff 1))",
        "(optional (string-utf8 1))",
    ];

    let bad = [
        "(element-at (list 1 2 3 4 5) 100)",
        "(element-at 3 u100)",
        "(element-at? (list 1 2 3 4 5) 100)",
        "(element-at? 3 u100)",
    ];

    let bad_expected = [
        CheckErrors::TypeError(TypeSignature::UIntType, TypeSignature::IntType),
        CheckErrors::ExpectedSequence(TypeSignature::IntType),
        CheckErrors::TypeError(TypeSignature::UIntType, TypeSignature::IntType),
        CheckErrors::ExpectedSequence(TypeSignature::IntType),
    ];

    for (good_test, expected) in good.iter().zip(expected.iter()) {
        assert_eq!(
            expected,
            &format!("{}", type_check_helper(good_test).unwrap())
        );
    }

    for (bad_test, expected) in bad.iter().zip(bad_expected.iter()) {
        assert_eq!(expected, &type_check_helper(bad_test).unwrap_err().err);
    }
}

#[apply(test_clarity_versions)]
fn test_eqs(#[case] version: ClarityVersion, #[case] epoch: StacksEpochId) {
    let good = [
        "(is-eq (list 1 2 3 4 5) (list 1 2 3 4 5 6 7))",
        "(is-eq (tuple (good 1) (bad 2)) (tuple (good 2) (bad 3)))",
        "(is-eq \"abcdef\" \"abc\" \"a\")",
    ];

    let expected = ["bool", "bool", "bool"];

    let bad = [
        "(is-eq 1 2 false)",
        "(is-eq 1 2 3 (list 2))",
        "(is-eq (some 1) (some true))",
    ];

    let bad_expected = [
        CheckErrors::TypeError(BoolType, IntType),
        CheckErrors::TypeError(TypeSignature::list_of(IntType, 1).unwrap(), IntType),
        CheckErrors::TypeError(
            TypeSignature::from_string("(optional bool)", version, epoch),
            TypeSignature::from_string("(optional int)", version, epoch),
        ),
    ];

    for (good_test, expected) in good.iter().zip(expected.iter()) {
        assert_eq!(
            expected,
            &format!("{}", type_check_helper(good_test).unwrap())
        );
    }

    for (bad_test, expected) in bad.iter().zip(bad_expected.iter()) {
        assert_eq!(expected, &type_check_helper(bad_test).unwrap_err().err);
    }
}

#[test]
fn test_asserts() {
    let good = [
        "(asserts! (is-eq 1 1) false)",
        "(asserts! (is-eq 1 1) (err 1))",
    ];

    let expected = ["bool", "bool"];

    let bad = [
        "(asserts! (is-eq 1 0))",
        "(asserts! 1 false)",
        "(asserts! 1 0 false)",
    ];

    let bad_expected = [
        CheckErrors::IncorrectArgumentCount(2, 1),
        CheckErrors::TypeError(BoolType, IntType),
        CheckErrors::IncorrectArgumentCount(2, 3),
    ];

    for (good_test, expected) in good.iter().zip(expected.iter()) {
        assert_eq!(
            expected,
            &format!("{}", type_check_helper(good_test).unwrap())
        );
    }

    for (bad_test, expected) in bad.iter().zip(bad_expected.iter()) {
        assert_eq!(expected, &type_check_helper(bad_test).unwrap_err().err);
    }
}

#[test]
fn test_lists() {
    let good = [
        "(map hash160 (list u1 u2 u3 u4 u5))",
        "(map hash160 (list 1 2 3 4 5))",
        "(map + (list 1 2 3 4 5) (list 1 2 3 4 5) (list 1 2 3 4 5))",
        "(map + (list 1 2 3 4 5) (list 1 2 3 4) (list 1 2 3 4 5))",
        "(list (list 1 2) (list 3 4) (list 5 1 7))",
        "(filter not (list false true false))",
        "(fold and (list true true false false) true)",
        "(map - (list (+ 1 2) 3 (+ 4 5) (* (+ 1 2) 3)))",
        "(if true (list 1 2 3 4) (list))",
        "(if true (list) (list 1 2 3 4))",
        "(len (list 1 2 3 4))",
    ];
    let expected = [
        "(list 5 (buff 20))",
        "(list 5 (buff 20))",
        "(list 5 int)",
        "(list 4 int)",
        "(list 3 (list 3 int))",
        "(list 3 bool)",
        "bool",
        "(list 4 int)",
        "(list 4 int)",
        "(list 4 int)",
        "uint",
    ];

    let bad = [
        "(fold and (list true false) 2)",
        "(fold hash160 (list u1 u2 u3 u4) u2)",
        "(fold hash160 (list 1 2 3 4) 2)",
        "(fold >= (list 1 2 3 4) 2)",
        "(list (list 1 2) (list true) (list 5 1 7))",
        "(list 1 2 3 true false 4 5 6)",
        "(filter hash160 (list u1 u2 u3 u4))",
        "(filter hash160 (list 1 2 3 4))",
        "(filter not (list 1 2 3 4))",
        "(filter not (list 1 2 3 4) 1)",
        "(filter ynot (list 1 2 3 4))",
        "(map if (list 1 2 3 4 5))",
        "(map mod (list 1 2 3 4 5))",
        "(map - (list true false true false))",
        "(map hash160 (+ u1 u2))",
        "(len 1)",
        "(map + (list 1 2 3 4 5) (list true true true true true))",
    ];
    let bad_expected = [
        CheckErrors::TypeError(BoolType, IntType),
        CheckErrors::IncorrectArgumentCount(1, 2),
        CheckErrors::IncorrectArgumentCount(1, 2),
        CheckErrors::TypeError(IntType, BoolType),
        CheckErrors::TypeError(IntType, BoolType),
        CheckErrors::TypeError(IntType, BoolType),
        CheckErrors::TypeError(BoolType, buff_type(20)),
        CheckErrors::TypeError(BoolType, buff_type(20)),
        CheckErrors::TypeError(BoolType, IntType),
        CheckErrors::IncorrectArgumentCount(2, 3),
        CheckErrors::UnknownFunction("ynot".to_string()),
        CheckErrors::IllegalOrUnknownFunctionApplication("if".to_string()),
        CheckErrors::IncorrectArgumentCount(2, 1),
        CheckErrors::UnionTypeError(vec![IntType, UIntType], BoolType),
        CheckErrors::ExpectedSequence(UIntType),
        CheckErrors::ExpectedSequence(IntType),
        CheckErrors::TypeError(IntType, BoolType),
    ];

    for (good_test, expected) in good.iter().zip(expected.iter()) {
        assert_eq!(
            expected,
            &format!("{}", type_check_helper(good_test).unwrap())
        );
    }

    for (bad_test, expected) in bad.iter().zip(bad_expected.iter()) {
        assert_eq!(expected, &type_check_helper(bad_test).unwrap_err().err);
    }
}

#[test]
fn test_buff() {
    let good = [
        "(if true \"blockstack\" \"block\")",
        "(if true \"block\" \"blockstack\")",
        "(len \"blockstack\")",
        "(len 0x)",
    ];
    let expected = ["(string-ascii 10)", "(string-ascii 10)", "uint", "uint"];
    let bad = [
        "(fold and (list true false) 2)",
        "(fold hash160 (list 1 2 3 4) 2)",
        "(fold >= (list 1 2 3 4) 2)",
        "(list (list 1 2) (list true) (list 5 1 7))",
        "(list 1 2 3 true false 4 5 6)",
        "(filter hash160 (list 1 2 3 4))",
        "(filter not (list 1 2 3 4))",
        "(filter not (list 1 2 3 4) 1)",
        "(filter ynot (list 1 2 3 4))",
        "(map if (list 1 2 3 4 5))",
        "(map mod (list 1 2 3 4 5))",
        "(map - (list true false true false))",
        "(map hash160 (+ u1 u2))",
        "(len 1)",
    ];
    let bad_expected = [
        CheckErrors::TypeError(BoolType, IntType),
        CheckErrors::IncorrectArgumentCount(1, 2),
        CheckErrors::TypeError(IntType, BoolType),
        CheckErrors::TypeError(IntType, BoolType),
        CheckErrors::TypeError(IntType, BoolType),
        CheckErrors::TypeError(BoolType, buff_type(20)),
        CheckErrors::TypeError(BoolType, IntType),
        CheckErrors::IncorrectArgumentCount(2, 3),
        CheckErrors::UnknownFunction("ynot".to_string()),
        CheckErrors::IllegalOrUnknownFunctionApplication("if".to_string()),
        CheckErrors::IncorrectArgumentCount(2, 1),
        CheckErrors::UnionTypeError(vec![IntType, UIntType], BoolType),
        CheckErrors::ExpectedSequence(UIntType),
        CheckErrors::ExpectedSequence(IntType),
    ];

    for (good_test, expected) in good.iter().zip(expected.iter()) {
        assert_eq!(
            expected,
            &format!("{}", type_check_helper(good_test).unwrap())
        );
    }

    for (bad_test, expected) in bad.iter().zip(bad_expected.iter()) {
        assert_eq!(expected, &type_check_helper(bad_test).unwrap_err().err);
    }
}

#[test]
fn test_buff_fold() {
    let good = [
        "(define-private (get-len (x (buff 1)) (acc uint)) (+ acc u1))
        (fold get-len 0x000102030405 u0)",
        "(define-private (get-slice (x (buff 1)) (acc (tuple (limit uint) (cursor uint) (data (buff 10)))))
            (if (< (get cursor acc) (get limit acc))
                (let ((data (default-to (get data acc) (as-max-len? (concat (get data acc) x) u10))))
                    (tuple (limit (get limit acc)) (cursor (+ u1 (get cursor acc))) (data data)))
                acc))
        (fold get-slice 0x00010203040506070809 (tuple (limit u5) (cursor u0) (data 0x)))"];
    let expected = [
        "uint",
        "(tuple (cursor uint) (data (buff 10)) (limit uint))",
    ];

    for (good_test, expected) in good.iter().zip(expected.iter()) {
        let type_sig = mem_type_check(good_test).unwrap().0.unwrap();
        assert_eq!(expected, &type_sig.to_string());
    }
}

#[test]
fn test_buff_map() {
    let good = ["(map hash160 0x0102030405)"];
    let expected = ["(list 5 (buff 20))"];

    for (good_test, expected) in good.iter().zip(expected.iter()) {
        assert_eq!(
            expected,
            &format!("{}", type_check_helper(good_test).unwrap())
        );
    }
}

#[test]
fn test_native_as_max_len() {
    let good = ["(as-max-len? (list 1 2 3 4) u5)"];
    let expected = ["(optional (list 5 int))"];

    for (good_test, expected) in good.iter().zip(expected.iter()) {
        assert_eq!(
            expected,
            &format!("{}", type_check_helper(good_test).unwrap())
        );
    }

    let bad = [
        "(as-max-len? \"\" u1048577)",
        "(as-max-len? u\"\" u1048577)",
        "(as-max-len? 0x01 u1048577)",
    ];
    let bad_expected = [
        CheckErrors::ValueTooLarge,
        CheckErrors::ValueTooLarge,
        CheckErrors::ValueTooLarge,
    ];
    for (bad_test, expected) in bad.iter().zip(bad_expected.iter()) {
        assert_eq!(expected, &type_check_helper(bad_test).unwrap_err().err);
    }
}

#[test]
fn test_buff_as_max_len() {
    let tests = [
        "(as-max-len? \"12345\" u5)",
        "(as-max-len? \"12345\" u8)",
        "(as-max-len? \"12345\" u4)",
    ];
    let expected = [
        "(optional (string-ascii 5))",
        "(optional (string-ascii 8))",
        "(optional (string-ascii 4))",
    ];

    for (test, expected) in tests.iter().zip(expected.iter()) {
        assert_eq!(expected, &format!("{}", type_check_helper(test).unwrap()));
    }
}

#[test]
fn test_native_append() {
    let good = ["(append (list 2 3) 4)", "(append (list u0) u0)"];
    let expected = ["(list 3 int)", "(list 2 uint)"];

    for (good_test, expected) in good.iter().zip(expected.iter()) {
        assert_eq!(
            expected,
            &format!("{}", type_check_helper(good_test).unwrap())
        );
    }

    let bad = [
        "(append (list 2 3) u4)",
        "(append (list u0) 1)",
        "(append (list u0))",
    ];

    let bad_expected = [
        CheckErrors::TypeError(IntType, UIntType),
        CheckErrors::TypeError(UIntType, IntType),
        CheckErrors::IncorrectArgumentCount(2, 1),
    ];
    for (bad_test, expected) in bad.iter().zip(bad_expected.iter()) {
        assert_eq!(expected, &type_check_helper(bad_test).unwrap_err().err);
    }
}

#[test]
fn test_slice_list() {
    let good = [
        "(slice? (list 2 3 4 5 6 7 8) u0 u3)",
        "(slice? (list u0 u1 u2 u3 u4) u3 u2)",
        "(slice? (list 2 3 4 5 6 7 8) u0 u0)",
        "(slice? (list 2 3 4 5 6 7 8) u10 u3)",
        "(slice? (list) u0 u3)",
    ];
    let expected = [
        "(optional (list 7 int))",
        "(optional (list 5 uint))",
        "(optional (list 7 int))",
        "(optional (list 7 int))",
        "(optional (list 0 UnknownType))",
    ];

    for (good_test, expected) in good.iter().zip(expected.iter()) {
        assert_eq!(
            expected,
            &format!("{}", type_check_helper(good_test).unwrap())
        );
    }

    let bad = [
        "(slice? (list 2 3) 3 u4)",
        "(slice? (list 2 3) u3 4)",
        "(slice? (list u0) u1)",
    ];

    let bad_expected = [
        CheckErrors::TypeError(UIntType, IntType),
        CheckErrors::TypeError(UIntType, IntType),
        CheckErrors::IncorrectArgumentCount(3, 2),
    ];
    for (bad_test, expected) in bad.iter().zip(bad_expected.iter()) {
        assert_eq!(expected, &type_check_helper(bad_test).unwrap_err().err);
    }
}

#[test]
fn test_slice_buff() {
    let good = [
        "(slice? 0x000102030405 u0 u3)",
        "(slice? 0x000102030405 u3 u2)",
    ];
    let expected = ["(optional (buff 6))", "(optional (buff 6))"];

    for (good_test, expected) in good.iter().zip(expected.iter()) {
        assert_eq!(
            expected,
            &format!("{}", type_check_helper(good_test).unwrap())
        );
    }

    let bad = [
        "(slice? 0x000102030405 3 u4)",
        "(slice? 0x000102030405 u3 4)",
        "(slice? 0x000102030405 u1)",
    ];

    let bad_expected = [
        CheckErrors::TypeError(UIntType, IntType),
        CheckErrors::TypeError(UIntType, IntType),
        CheckErrors::IncorrectArgumentCount(3, 2),
    ];
    for (bad_test, expected) in bad.iter().zip(bad_expected.iter()) {
        assert_eq!(expected, &type_check_helper(bad_test).unwrap_err().err);
    }
}

#[test]
fn test_slice_ascii() {
    let good = [
        "(slice? \"blockstack\" u4 u5)",
        "(slice? \"blockstack\" u0 u5)",
    ];
    let expected = [
        "(optional (string-ascii 10))",
        "(optional (string-ascii 10))",
    ];

    for (good_test, expected) in good.iter().zip(expected.iter()) {
        assert_eq!(
            expected,
            &format!("{}", type_check_helper(good_test).unwrap())
        );
    }

    let bad = [
        "(slice? \"blockstack\" 3 u4)",
        "(slice? \"blockstack\" u3 4)",
        "(slice? \"blockstack\" u1)",
    ];

    let bad_expected = [
        CheckErrors::TypeError(UIntType, IntType),
        CheckErrors::TypeError(UIntType, IntType),
        CheckErrors::IncorrectArgumentCount(3, 2),
    ];
    for (bad_test, expected) in bad.iter().zip(bad_expected.iter()) {
        assert_eq!(expected, &type_check_helper(bad_test).unwrap_err().err);
    }
}

#[test]
fn test_slice_utf8() {
    let good = [
        "(slice? u\"blockstack\" u4 u5)",
        "(slice? u\"blockstack\" u4 u5)",
    ];
    let expected = ["(optional (string-utf8 10))", "(optional (string-utf8 10))"];

    for (good_test, expected) in good.iter().zip(expected.iter()) {
        assert_eq!(
            expected,
            &format!("{}", type_check_helper(good_test).unwrap())
        );
    }

    let bad = [
        "(slice? u\"blockstack\" 3 u4)",
        "(slice? u\"blockstack\" u3 4)",
        "(slice? u\"blockstack\" u1)",
    ];

    let bad_expected = [
        CheckErrors::TypeError(UIntType, IntType),
        CheckErrors::TypeError(UIntType, IntType),
        CheckErrors::IncorrectArgumentCount(3, 2),
    ];
    for (bad_test, expected) in bad.iter().zip(bad_expected.iter()) {
        assert_eq!(expected, &type_check_helper(bad_test).unwrap_err().err);
    }
}

#[test]
fn test_replace_at_list() {
    let good = [
        "(replace-at? (list 2 3 4 5 6 7 8) u0 10)",
        "(replace-at? (list u0 u1 u2 u3 u4) u3 u10)",
        "(replace-at? (list true) u0 false)",
        "(replace-at? (list 2 3 4 5 6 7 8) u6 10)",
        "(replace-at? (list (list 1) (list 2)) u0 (list 33))",
        "(replace-at? (list (list 1 2) (list 3 4)) u0 (list 0))",
        "(replace-at? (list (list 1 2 3)) u0 (list 0))",
    ];
    let expected = [
        "(optional (list 7 int))",
        "(optional (list 5 uint))",
        "(optional (list 1 bool))",
        "(optional (list 7 int))",
        "(optional (list 2 (list 1 int)))",
        "(optional (list 2 (list 2 int)))",
        "(optional (list 1 (list 3 int)))",
        "(optional (list 2 (list 1 int)))",
    ];

    for (good_test, expected) in good.iter().zip(expected.iter()) {
        assert_eq!(
            expected,
            &format!("{}", type_check_helper(good_test).unwrap())
        );
    }

    let bad = [
        "(replace-at? (list 2 3) u0 (list 4))",
        "(replace-at? (list 2 3) u0 true)",
        "(replace-at? (list 2 3) 0 4)",
        "(replace-at? (list 2 3) u0 4 5)",
        "(replace-at? (list u0) u0)",
        "(replace-at? (list (list 1) (list 2)) u0 (list 33 44))",
    ];

    let bad_expected = [
        CheckErrors::TypeError(
            IntType,
            SequenceType(ListType(ListTypeData::new_list(IntType, 1).unwrap())),
        ),
        CheckErrors::TypeError(IntType, BoolType),
        CheckErrors::TypeError(UIntType, IntType),
        CheckErrors::IncorrectArgumentCount(3, 4),
        CheckErrors::IncorrectArgumentCount(3, 2),
        CheckErrors::TypeError(
            SequenceType(ListType(ListTypeData::new_list(IntType, 1).unwrap())),
            SequenceType(ListType(ListTypeData::new_list(IntType, 2).unwrap())),
        ),
    ];
    for (bad_test, expected) in bad.iter().zip(bad_expected.iter()) {
        assert_eq!(expected, &type_check_helper(bad_test).unwrap_err().err);
    }
}

#[test]
fn test_replace_at_buff() {
    let good = [
        "(replace-at? 0x00112233 u0 0x44)",
        "(replace-at? 0x00112233 u3 0x66)",
        "(replace-at? 0x00 u0 0x22)",
        "(replace-at? 0x001122334455 u2 0x66)",
    ];
    let expected = [
        "(optional (buff 4))",
        "(optional (buff 4))",
        "(optional (buff 1))",
        "(optional (buff 6))",
    ];

    for (good_test, expected) in good.iter().zip(expected.iter()) {
        assert_eq!(
            expected,
            &format!("{}", type_check_helper(good_test).unwrap())
        );
    }

    let bad = [
        "(replace-at? 0x0011 u0 (list 0))",
        "(replace-at? 0x0011 u0 \"a\")",
        "(replace-at? 0x0011 0 0x22)",
        "(replace-at? 0x0011 u0 0x44 0x55)",
        "(replace-at? 0x11 u0)",
        "(replace-at? 0x001122334455 u2 0x6677)",
    ];

    let buff_len = BufferLength::try_from(1u32).unwrap();
    let buff_len_two = BufferLength::try_from(2u32).unwrap();
    let bad_expected = [
        CheckErrors::TypeError(
            SequenceType(BufferType(buff_len.clone())),
            SequenceType(ListType(ListTypeData::new_list(IntType, 1).unwrap())),
        ),
        CheckErrors::TypeError(
            SequenceType(BufferType(buff_len.clone())),
            SequenceType(StringType(ASCII(buff_len.clone()))),
        ),
        CheckErrors::TypeError(UIntType, IntType),
        CheckErrors::IncorrectArgumentCount(3, 4),
        CheckErrors::IncorrectArgumentCount(3, 2),
        CheckErrors::TypeError(
            SequenceType(BufferType(buff_len)),
            SequenceType(BufferType(buff_len_two)),
        ),
    ];
    for (bad_test, expected) in bad.iter().zip(bad_expected.iter()) {
        assert_eq!(expected, &type_check_helper(bad_test).unwrap_err().err);
    }
}

#[test]
fn test_replace_at_ascii() {
    let good = [
        "(replace-at? \"abcd\" u0 \"f\")",
        "(replace-at? \"abcd\" u3 \"f\")",
        "(replace-at? \"a\" u0 \"f\")",
        "(replace-at? \"abcdefg\" u2 \"h\")",
    ];
    let expected = [
        "(optional (string-ascii 4))",
        "(optional (string-ascii 4))",
        "(optional (string-ascii 1))",
        "(optional (string-ascii 7))",
        "(optional (string-ascii 7))",
    ];

    for (good_test, expected) in good.iter().zip(expected.iter()) {
        assert_eq!(
            expected,
            &format!("{}", type_check_helper(good_test).unwrap())
        );
    }

    let bad = [
        "(replace-at? \"abcd\" u0 (list 0))",
        "(replace-at? \"abcd\" u0 0x00)",
        "(replace-at? \"abcd\" 0 \"e\")",
        "(replace-at? \"abcd\" u0 \"a\" \"d\")",
        "(replace-at? \"abcd\" u0)",
        "(replace-at? \"abcdefg\" u2 \"hi\")",
    ];

    let buff_len = BufferLength::try_from(1u32).unwrap();
    let buff_len_two = BufferLength::try_from(2u32).unwrap();
    let bad_expected = [
        CheckErrors::TypeError(
            SequenceType(StringType(ASCII(buff_len.clone()))),
            SequenceType(ListType(ListTypeData::new_list(IntType, 1).unwrap())),
        ),
        CheckErrors::TypeError(
            SequenceType(StringType(ASCII(buff_len.clone()))),
            SequenceType(BufferType(buff_len.clone())),
        ),
        CheckErrors::TypeError(UIntType, IntType),
        CheckErrors::IncorrectArgumentCount(3, 4),
        CheckErrors::IncorrectArgumentCount(3, 2),
        CheckErrors::TypeError(
            SequenceType(StringType(ASCII(buff_len))),
            SequenceType(StringType(ASCII(buff_len_two))),
        ),
    ];
    for (bad_test, expected) in bad.iter().zip(bad_expected.iter()) {
        assert_eq!(expected, &type_check_helper(bad_test).unwrap_err().err);
    }
}

#[test]
fn test_replace_at_utf8() {
    let good = [
        "(replace-at? u\"abcd\" u0 u\"f\")",
        "(replace-at? u\"abcd\" u3 u\"f\")",
        "(replace-at? u\"a\" u0 u\"f\")",
        "(replace-at? u\"abcdefg\" u2 u\"h\")",
    ];
    let expected = [
        "(optional (string-utf8 4))",
        "(optional (string-utf8 4))",
        "(optional (string-utf8 1))",
        "(optional (string-utf8 7))",
    ];

    for (good_test, expected) in good.iter().zip(expected.iter()) {
        assert_eq!(
            expected,
            &format!("{}", type_check_helper(good_test).unwrap())
        );
    }

    let bad = [
        "(replace-at? u\"abcd\" u0 (list 0))",
        "(replace-at? u\"abcd\" u0 0x00)",
        "(replace-at? u\"abcd\" 0 u\"a\")",
        "(replace-at? u\"abcd\" u0 u\"a\" u\"d\")",
        "(replace-at? u\"abcd\" u0)",
        "(replace-at? u\"abcdefg\" u2 u\"hi\")",
    ];

    let buff_len = BufferLength::try_from(1u32).unwrap();
    let str_len = StringUTF8Length::try_from(1u32).unwrap();
    let str_len_two = StringUTF8Length::try_from(2u32).unwrap();
    let bad_expected = [
        CheckErrors::TypeError(
            SequenceType(StringType(UTF8(str_len.clone()))),
            SequenceType(ListType(ListTypeData::new_list(IntType, 1).unwrap())),
        ),
        CheckErrors::TypeError(
            SequenceType(StringType(UTF8(str_len.clone()))),
            SequenceType(BufferType(buff_len)),
        ),
        CheckErrors::TypeError(UIntType, IntType),
        CheckErrors::IncorrectArgumentCount(3, 4),
        CheckErrors::IncorrectArgumentCount(3, 2),
        CheckErrors::TypeError(
            SequenceType(StringType(UTF8(str_len))),
            SequenceType(StringType(UTF8(str_len_two))),
        ),
    ];
    for (bad_test, expected) in bad.iter().zip(bad_expected.iter()) {
        assert_eq!(expected, &type_check_helper(bad_test).unwrap_err().err);
    }
}

#[test]
fn test_native_concat() {
    let good = ["(concat (list 2 3) (list 4 5))"];
    let expected = ["(list 4 int)"];

    for (good_test, expected) in good.iter().zip(expected.iter()) {
        assert_eq!(
            expected,
            &format!("{}", type_check_helper(good_test).unwrap())
        );
    }

    let bad = [
        "(concat (list 2 3) (list u4))",
        "(concat (list u0) (list 1))",
        "(concat (list u0))",
    ];

    let bad_expected = [
        CheckErrors::TypeError(IntType, UIntType),
        CheckErrors::TypeError(UIntType, IntType),
        CheckErrors::IncorrectArgumentCount(2, 1),
    ];
    for (bad_test, expected) in bad.iter().zip(bad_expected.iter()) {
        assert_eq!(expected, &type_check_helper(bad_test).unwrap_err().err);
    }
}

#[test]
fn test_concat_append_supertypes() {
    let good = [
        "(concat (list) (list 4 5))",
        "(concat (list (list 2) (list) (list 4 5))
                 (list (list) (list) (list 7 8 9)))",
        "(append (list) 1)",
        "(append (list (list 3 4) (list)) (list 4 5 7))",
    ];
    let expected = [
        "(list 2 int)",
        "(list 6 (list 3 int))",
        "(list 1 int)",
        "(list 3 (list 3 int))",
    ];

    for (good_test, expected) in good.iter().zip(expected.iter()) {
        eprintln!("{}", good_test);
        assert_eq!(
            expected,
            &format!("{}", type_check_helper(good_test).unwrap())
        );
    }
}

#[test]
fn test_buff_concat() {
    let good = ["(concat 0x010203 0x0405)"];
    let expected = ["(buff 5)"];

    for (good_test, expected) in good.iter().zip(expected.iter()) {
        assert_eq!(
            expected,
            &format!("{}", type_check_helper(good_test).unwrap())
        );
    }
}

#[test]
fn test_buff_filter() {
    let good = ["(define-private (f (e (string-ascii 1))) (is-eq e \"1\"))
        (filter f \"101010\")"];
    let expected = ["(string-ascii 6)"];

    for (good_test, expected) in good.iter().zip(expected.iter()) {
        let type_sig = mem_type_check(good_test).unwrap().0.unwrap();
        assert_eq!(expected, &type_sig.to_string());
    }
}

#[test]
fn test_lists_in_defines() {
    let good = "
    (define-private (test (x int)) (is-eq 0 (mod x 2)))
    (filter test (list 1 2 3 4 5))";
    assert_eq!(
        "(list 5 int)",
        &format!("{}", mem_type_check(good).unwrap().0.unwrap())
    );
}

#[test]
fn test_tuples() {
    let good = [
        "(+ 1 2     (get abc (tuple (abc 1) (def true))))",
        "(and true (get def (tuple (abc 1) (def true))))",
    ];

    let expected = ["int", "bool"];

    let bad = [
        "(+ 1 2      (get def (tuple (abc 1) (def true))))",
        "(and true  (get abc (tuple (abc 1) (def true))))",
    ];

    let bad_expected = [
        CheckErrors::TypeError(IntType, BoolType),
        CheckErrors::TypeError(BoolType, IntType),
    ];

    for (good_test, expected) in good.iter().zip(expected.iter()) {
        assert_eq!(
            expected,
            &format!("{}", type_check_helper(good_test).unwrap())
        );
    }

    for (bad_test, expected) in bad.iter().zip(bad_expected.iter()) {
        assert_eq!(expected, &type_check_helper(bad_test).unwrap_err().err);
    }
}

#[test]
fn test_empty_tuple_should_fail() {
    let contract_src = r#"
        (define-private (set-cursor (value (tuple)))
            value)
    "#;

    assert_eq!(
        mem_type_check(contract_src).unwrap_err().err,
        CheckErrors::BadSyntaxBinding
    );
}

#[test]
fn test_define() {
    let good = ["(define-private (foo (x int) (y int)) (+ x y))
                     (define-private (bar (x int) (y bool)) (if y (+ 1 x) 0))
                     (* (foo 1 2) (bar 3 false))"];

    let bad = ["(define-private (foo ((x int) (y int)) (+ x y)))
                     (define-private (bar ((x int) (y bool)) (if y (+ 1 x) 0)))
                     (* (foo 1 2) (bar 3 3))"];

    for good_test in good.iter() {
        mem_type_check(good_test).unwrap();
    }

    for bad_test in bad.iter() {
        mem_type_check(bad_test).unwrap_err();
    }
}

#[test]
fn test_high_order_map() {
    let good = [
        "(define-private (foo (x int)) (list x x x x x))
         (map foo (list 1 2 3))",
        "(define-private (foo (x int)) (list x x x x x))
         (map foo (list 1 2 3 4 5 6))",
    ];

    let expected = ["(list 3 (list 5 int))", "(list 6 (list 5 int))"];

    for (good_test, expected) in good.iter().zip(expected.iter()) {
        let type_sig = mem_type_check(good_test).unwrap().0.unwrap();
        assert_eq!(expected, &type_sig.to_string());
    }
}

#[test]
fn test_function_order_tuples() {
    let snippet = "
(define-read-only (get-score)
    (ok 
        (tuple
            (score (get-zero))
        )
    )
)

(define-private (get-zero)
    0
)

1
";

    assert_eq!(
        &mem_type_check(snippet).unwrap().0.unwrap().to_string(),
        "int"
    );
}

#[test]
fn test_simple_uints() {
    let good = [
        "(define-private (foo (x uint)) (+ x u1))
         (foo u2)",
        "(define-private (foo (x uint)) (+ x x))
         (foo (foo u0))",
        "(+ u10 (to-uint 15))",
        "(- 10 (to-int u1))",
    ];

    let expected = ["uint", "uint", "uint", "int"];

    let bad = ["(> u1 1)", "(to-uint true)", "(to-int false)"];

    let bad_expected = [
        CheckErrors::TypeError(UIntType, IntType),
        CheckErrors::TypeError(IntType, BoolType),
        CheckErrors::TypeError(UIntType, BoolType),
    ];

    for (good_test, expected) in good.iter().zip(expected.iter()) {
        let type_sig = mem_type_check(good_test).unwrap().0.unwrap();
        assert_eq!(expected, &type_sig.to_string());
    }

    for (bad_test, expected) in bad.iter().zip(bad_expected.iter()) {
        assert_eq!(&mem_type_check(bad_test).unwrap_err().err, expected);
    }
}

#[test]
fn test_buffer_to_ints() {
    let good = [
        "(buff-to-int-le 0x0001)",
        "(buff-to-uint-le 0x0001)",
        "(buff-to-int-be 0x0001)",
        "(buff-to-uint-be 0x0001)",
    ];

    let expected = ["int", "uint", "int", "uint"];

    let bad = [
        "(buff-to-int-le 0x0001 0x0001)",
        "(buff-to-int-le)",
        "(buff-to-uint-be 0x000102030405060708090a0b0c0d0e0f00)",
        "(buff-to-uint-be \"a\")",
    ];

    let bad_expected = [
        CheckErrors::IncorrectArgumentCount(1, 2),
        CheckErrors::IncorrectArgumentCount(1, 0),
        CheckErrors::TypeError(
            SequenceType(BufferType(BufferLength::try_from(16_u32).unwrap())),
            SequenceType(BufferType(BufferLength::try_from(17_u32).unwrap())),
        ),
        CheckErrors::TypeError(
            SequenceType(BufferType(BufferLength::try_from(16_u32).unwrap())),
            SequenceType(StringType(ASCII(BufferLength::try_from(1_u32).unwrap()))),
        ),
    ];

    for (good_test, expected) in good.iter().zip(expected.iter()) {
        let type_sig = mem_type_check(good_test).unwrap().0.unwrap();
        assert_eq!(expected, &type_sig.to_string());
    }

    for (bad_test, expected) in bad.iter().zip(bad_expected.iter()) {
        assert_eq!(&mem_type_check(bad_test).unwrap_err().err, expected);
    }
}

#[test]
fn test_string_to_ints() {
    let good = [
        r#"(int-to-ascii 1)"#,
        r#"(int-to-ascii u1)"#,
        r#"(int-to-utf8 1)"#,
        r#"(int-to-utf8 u1)"#,
        r#"(string-to-int? "1")"#,
        r#"(string-to-int? u"1")"#,
        r#"(string-to-uint? "1")"#,
        r#"(string-to-uint? u"1")"#,
    ];

    let expected = [
        "(string-ascii 40)",
        "(string-ascii 40)",
        "(string-utf8 40)",
        "(string-utf8 40)",
        "(optional int)",
        "(optional int)",
        "(optional uint)",
        "(optional uint)",
    ];

    let bad = [
        r#"(int-to-ascii 0x0001 0x0001)"#,
        r#"(int-to-ascii)"#,
        r#"(int-to-ascii 0x000102030405060708090a0b0c0d0e0f00)"#,
        r#"(int-to-ascii "a")"#,
        r#"(int-to-utf8 0x0001 0x0001)"#,
        r#"(int-to-utf8)"#,
        r#"(int-to-utf8 0x000102030405060708090a0b0c0d0e0f00)"#,
        r#"(int-to-utf8 "a")"#,
        r#"(string-to-int? 0x0001 0x0001)"#,
        r#"(string-to-int?)"#,
        r#"(string-to-int? 0x000102030405060708090a0b0c0d0e0f00)"#,
        r#"(string-to-int? 1)"#,
        r#"(string-to-uint? 0x0001 0x0001)"#,
        r#"(string-to-uint?)"#,
        r#"(string-to-uint? 0x000102030405060708090a0b0c0d0e0f00)"#,
        r#"(string-to-uint? 1)"#,
    ];

    let bad_expected = [
        CheckErrors::IncorrectArgumentCount(1, 2),
        CheckErrors::IncorrectArgumentCount(1, 0),
        CheckErrors::UnionTypeError(
            vec![IntType, UIntType],
            SequenceType(BufferType(BufferLength::try_from(17_u32).unwrap())),
        ),
        CheckErrors::UnionTypeError(
            vec![IntType, UIntType],
            SequenceType(StringType(ASCII(BufferLength::try_from(1_u32).unwrap()))),
        ),
        CheckErrors::IncorrectArgumentCount(1, 2),
        CheckErrors::IncorrectArgumentCount(1, 0),
        CheckErrors::UnionTypeError(
            vec![IntType, UIntType],
            SequenceType(BufferType(BufferLength::try_from(17_u32).unwrap())),
        ),
        CheckErrors::UnionTypeError(
            vec![IntType, UIntType],
            SequenceType(StringType(ASCII(BufferLength::try_from(1_u32).unwrap()))),
        ),
        CheckErrors::IncorrectArgumentCount(1, 2),
        CheckErrors::IncorrectArgumentCount(1, 0),
        CheckErrors::UnionTypeError(
            vec![
                TypeSignature::max_string_ascii().unwrap(),
                TypeSignature::max_string_utf8().unwrap(),
            ],
            SequenceType(BufferType(BufferLength::try_from(17_u32).unwrap())),
        ),
        CheckErrors::UnionTypeError(
            vec![
                TypeSignature::max_string_ascii().unwrap(),
                TypeSignature::max_string_utf8().unwrap(),
            ],
            IntType,
        ),
        CheckErrors::IncorrectArgumentCount(1, 2),
        CheckErrors::IncorrectArgumentCount(1, 0),
        CheckErrors::UnionTypeError(
            vec![
                TypeSignature::max_string_ascii().unwrap(),
                TypeSignature::max_string_utf8().unwrap(),
            ],
            SequenceType(BufferType(BufferLength::try_from(17_u32).unwrap())),
        ),
        CheckErrors::UnionTypeError(
            vec![
                TypeSignature::max_string_ascii().unwrap(),
                TypeSignature::max_string_utf8().unwrap(),
            ],
            IntType,
        ),
    ];

    for (good_test, expected) in good.iter().zip(expected.iter()) {
        let type_sig = mem_type_check(good_test).unwrap().0.unwrap();
        assert_eq!(expected, &type_sig.to_string());
    }

    for (bad_test, expected) in bad.iter().zip(bad_expected.iter()) {
        assert_eq!(&mem_type_check(bad_test).unwrap_err().err, expected);
    }
}

#[apply(test_clarity_versions)]
fn test_response_inference(#[case] version: ClarityVersion, #[case] epoch: StacksEpochId) {
    let good = [
        "(define-private (foo (x int)) (err x))
                 (define-private (bar (x bool)) (ok x))
                 (if true (foo 1) (bar false))",
        "(define-private (check (x (response bool int))) (is-ok x))
                 (check (err 1))",
        "(define-private (check (x (response bool int))) (is-ok x))
                 (check (ok true))",
        "(define-private (check (x (response bool int))) (is-ok x))
                 (check (if true (err 1) (ok false)))",
        "(define-private (check (x (response int bool)))
                   (if (> 10 (unwrap! x 10))
                       2
                       (let ((z (unwrap! x 1))) z)))
                 (check (ok 1))",
        // tests top-level `unwrap!` type-check behavior
        // (i.e., let it default to anything, since it will always cause a tx abort if the expectation is unmet.)
        "(unwrap! (ok 2) true)",
    ];

    let expected = ["(response bool int)", "bool", "bool", "bool", "int", "int"];

    let bad = [
        "(define-private (check (x (response bool int))) (is-ok x))
                (check true)",
        "(define-private (check (x (response int bool)))
                   (if (> 10 (unwrap! x 10))
                       2
                       (let ((z (unwrap! x true))) z)))
                 (check (ok 1))",
        "(unwrap! (err 2) true)",
    ];

    let bad_expected = [
        CheckErrors::TypeError(
            TypeSignature::from_string("(response bool int)", version, epoch),
            BoolType,
        ),
        CheckErrors::ReturnTypesMustMatch(IntType, BoolType),
        CheckErrors::CouldNotDetermineResponseOkType,
    ];

    for (good_test, expected) in good.iter().zip(expected.iter()) {
        let type_sig = mem_type_check(good_test).unwrap().0.unwrap();
        assert_eq!(expected, &type_sig.to_string());
    }

    for (bad_test, expected) in bad.iter().zip(bad_expected.iter()) {
        assert_eq!(&mem_type_check(bad_test).unwrap_err().err, expected);
    }
}

#[test]
fn test_function_arg_names() {
    let functions = [
        "(define-private (test (x int)) (ok 0))
         (define-public (test-pub (x int)) (ok 0))
         (define-read-only (test-ro (x int)) (ok 0))",
        "(define-private (test (x int) (y bool)) (ok 0))
         (define-public (test-pub (x int) (y bool)) (ok 0))
         (define-read-only (test-ro (x int) (y bool)) (ok 0))",
        "(define-private (test (name-1 int) (name-2 int) (name-3 int)) (ok 0))
         (define-public (test-pub (name-1 int) (name-2 int) (name-3 int)) (ok 0))
         (define-read-only (test-ro (name-1 int) (name-2 int) (name-3 int)) (ok 0))",
        "(define-private (test) (ok 0))
         (define-public (test-pub) (ok 0))
         (define-read-only (test-ro) (ok 0))",
    ];

    let expected_arg_names: Vec<Vec<&str>> = vec![
        vec!["x"],
        vec!["x", "y"],
        vec!["name-1", "name-2", "name-3"],
        vec![],
    ];

    for (func_test, arg_names) in functions.iter().zip(expected_arg_names.iter()) {
        let contract_analysis = mem_type_check(func_test).unwrap().1;

        let func_type_priv = contract_analysis.get_private_function("test").unwrap();
        let func_type_pub = contract_analysis
            .get_public_function_type("test-pub")
            .unwrap();
        let func_type_ro = contract_analysis
            .get_read_only_function_type("test-ro")
            .unwrap();

        for func_type in &[func_type_priv, func_type_pub, func_type_ro] {
            let func_args = match func_type {
                FunctionType::Fixed(FixedFunction { args, .. }) => args,
                _ => panic!("Unexpected function type"),
            };

            for (expected_name, actual_name) in
                arg_names.iter().zip(func_args.iter().map(|x| &x.name))
            {
                assert_eq!(*expected_name, &**actual_name);
            }
        }
    }
}

#[test]
fn test_factorial() {
    let contract = "(define-map factorials { id: int } { current: int, index: int })
         (define-private (init-factorial (id int) (factorial int))
           (print (map-insert factorials (tuple (id id)) (tuple (current 1) (index factorial)))))
         (define-public (compute (id int))
           (let ((entry (unwrap! (map-get? factorials (tuple (id id)))
                                 (err false))))
                    (let ((current (get current entry))
                          (index   (get index entry)))
                         (if (<= index 1)
                             (ok true)
                             (begin
                               (map-set factorials (tuple (id id))
                                                      (tuple (current (* current index))
                                                             (index (- index 1))))
                               (ok false))))))
        (begin (init-factorial 1337 3)
               (init-factorial 8008 5))
        ";

    mem_type_check(contract).unwrap();
}

#[apply(test_clarity_versions)]
fn test_options(#[case] version: ClarityVersion, #[case] epoch: StacksEpochId) {
    let contract = "
         (define-private (foo (id (optional int)))
           (+ 1 (default-to 1 id)))
         (define-private (bar (x int))
           (if (> 0 x)
               (some x)
               none))
         (+ (foo none)
            (foo (bar 1))
            (foo (bar 0)))
         ";

    mem_type_check(contract).unwrap();

    let contract = "
         (define-private (foo (id (optional bool)))
           (if (default-to false id)
               1
               0))
         (define-private (bar (x int))
           (if (> 0 x)
               (some x)
               none))
         (+ (foo (bar 1)) 1)
         ";

    if version < ClarityVersion::Clarity2 {
        assert!(
            match mem_run_analysis(contract, version, epoch).unwrap_err().err {
                CheckErrors::TypeError(t1, t2) => {
                    t1 == TypeSignature::from_string("(optional bool)", version, epoch)
                        && t2 == TypeSignature::from_string("(optional int)", version, epoch)
                }
                _ => false,
            }
        );
    } else {
        assert!(
            match mem_run_analysis(contract, version, epoch).unwrap_err().err {
                CheckErrors::TypeError(t1, t2) => {
                    t1 == TypeSignature::from_string("bool", version, epoch)
                        && t2 == TypeSignature::from_string("int", version, epoch)
                }
                _ => false,
            }
        );
    }
}

#[test]
fn test_list_nones() {
    let contract = "
         (begin
           (let ((a (list none none none))) (print a)))";
    assert_eq!(
        "(list 3 (optional UnknownType))",
        &format!("{}", mem_type_check(contract).unwrap().0.unwrap())
    );
}

#[test]
fn test_set_int_variable() {
    let contract_src = r#"
        (define-data-var cursor int 0)
        (define-private (get-cursor)
            (var-get cursor))
        (define-private (set-cursor (value int))
            (if (var-set cursor value)
                value
                0))
        (define-private (increment-cursor)
            (begin
                (var-set cursor (+ 1 (get-cursor)))
                (get-cursor)))
    "#;

    mem_type_check(contract_src).unwrap();
}

#[test]
fn test_set_bool_variable() {
    let contract_src = r#"
        (define-data-var is-ok bool true)
        (define-private (get-ok)
            (var-get is-ok))
        (define-private (set-cursor (new-ok bool))
            (if (var-set is-ok new-ok)
                new-ok
                (get-ok)))
    "#;

    mem_type_check(contract_src).unwrap();
}

#[test]
fn test_set_tuple_variable() {
    let contract_src = r#"
        (define-data-var cursor (tuple (k1 int) (v1 int)) (tuple (k1 1) (v1 1)))
        (define-private (get-cursor)
            (var-get cursor))
        (define-private (set-cursor (value (tuple (k1 int) (v1 int))))
            (if (var-set cursor value)
                value
                (get-cursor)))
    "#;

    mem_type_check(contract_src).unwrap();
}

#[test]
fn test_set_list_variable() {
    let contract_src = r#"
        (define-data-var ranking (list 3 int) (list 1 2 3))
        (define-private (get-ranking)
            (var-get ranking))
        (define-private (set-ranking (new-ranking (list 3 int)))
            (if (var-set ranking new-ranking)
                new-ranking
                (get-ranking)))
    "#;

    mem_type_check(contract_src).unwrap();
}

#[test]
fn test_set_buffer_variable() {
    let contract_src = r#"
        (define-data-var name (string-ascii 5) "alice")
        (define-private (get-name)
            (var-get name))
        (define-private (set-name (new-name (string-ascii 3)))
            (if (var-set name new-name)
                new-name
                (get-name)))
    "#;

    mem_type_check(contract_src).unwrap();
}

#[test]
fn test_missing_value_on_declaration_should_fail() {
    let contract_src = r#"
        (define-data-var cursor int)
    "#;

    let res = mem_type_check(contract_src).unwrap_err();
    assert!(matches!(res.err, CheckErrors::IncorrectArgumentCount(_, _)));
}

#[test]
fn test_mismatching_type_on_declaration_should_fail() {
    let contract_src = r#"
        (define-data-var cursor int true)
    "#;

    let res = mem_type_check(contract_src).unwrap_err();
    assert!(matches!(res.err, CheckErrors::TypeError(_, _)));
}

#[test]
fn test_mismatching_type_on_update_should_fail() {
    let contract_src = r#"
        (define-data-var cursor int 0)
        (define-private (get-cursor)
            (var-get cursor))
        (define-private (set-cursor (value principal))
            (if (var-set cursor value)
                value
                0))
    "#;

    let res = mem_type_check(contract_src).unwrap_err();
    assert!(matches!(res.err, CheckErrors::TypeError(_, _)));
}

#[test]
fn test_direct_access_to_persisted_var_should_fail() {
    let contract_src = r#"
        (define-data-var cursor int 0)
        (define-private (get-cursor)
            cursor)
    "#;

    let res = mem_type_check(contract_src).unwrap_err();
    assert!(matches!(res.err, CheckErrors::UndefinedVariable(_)));
}

#[test]
fn test_data_var_shadowed_by_let_should_fail() {
    let contract_src = r#"
        (define-data-var cursor int 0)
        (define-private (set-cursor (value int))
            (let ((cursor 0))
               (if (var-set cursor value)
                   value
                    0)))
    "#;

    let res = mem_type_check(contract_src).unwrap_err();
    assert!(matches!(res.err, CheckErrors::NameAlreadyUsed(_)));
}

#[test]
fn test_mutating_unknown_data_var_should_fail() {
    let contract_src = r#"
        (define-private (set-cursor (value int))
            (if (var-set cursor value)
                value
                0))
    "#;

    let res = mem_type_check(contract_src).unwrap_err();
    assert!(matches!(res.err, CheckErrors::NoSuchDataVariable(_)));
}

#[test]
fn test_accessing_unknown_data_var_should_fail() {
    let contract_src = r#"
        (define-private (get-cursor)
            (unwrap! (var-get cursor) 0))
    "#;

    let res = mem_type_check(contract_src).unwrap_err();
    assert!(matches!(res.err, CheckErrors::NoSuchDataVariable(_)));
}

#[test]
fn test_let_shadowed_by_let_should_fail() {
    let contract_src = r#"
        (let ((cursor 1) (cursor 2))
            cursor)
    "#;

    let res = mem_type_check(contract_src).unwrap_err();
    assert!(matches!(res.err, CheckErrors::NameAlreadyUsed(_)));
}

#[test]
fn test_let_shadowed_by_nested_let_should_fail() {
    let contract_src = r#"
        (let ((cursor 1))
            (let ((cursor 2))
                cursor))
    "#;

    let res = mem_type_check(contract_src).unwrap_err();
    assert!(matches!(res.err, CheckErrors::NameAlreadyUsed(_)));
}

#[test]
fn test_define_constant_shadowed_by_let_should_fail() {
    let contract_src = r#"
        (define-private (cursor) 0)
        (define-private (set-cursor (value int))
            (let ((cursor 1))
               cursor))
    "#;

    let res = mem_type_check(contract_src).unwrap_err();
    assert!(matches!(res.err, CheckErrors::NameAlreadyUsed(_)));
}

#[test]
fn test_define_constant_shadowed_by_argument_should_fail() {
    let contract_src = r#"
        (define-private (cursor) 0)
        (define-private (set-cursor (cursor int))
            cursor)
    "#;

    let res = mem_type_check(contract_src).unwrap_err();
    assert!(matches!(res.err, CheckErrors::NameAlreadyUsed(_)));
}

#[test]
fn test_combine_tuples() {
    let ok = [
        "(merge { a: 1, b: 2, c: 3 } { a: 1 })",
        "(merge { a: { x: 0, y: 1 }, b: 2, c: 3 } { a: { x: 5 } })",
        "(merge { a: (some { x: 0, y: 1 }), b: 2, c: 3 } { a: none })",
        "(merge { b: 2, c: 3 } { a: none })",
        "(merge { a: 1, b: 2, c: 3 } { a: 4, b: 5, c: 6 })",
        "(merge { a: 1, b: 2, c: 3 } { d: 1 })",
        "(merge { a: { x: 0, y: 1 }, b: 2, c: 3 } { a: { x: 5, z: 0 } })",
        "(merge { a: 1, b: 2, c: 3 } { a: u1 })",
    ];

    let expected = [
        "(tuple (a int) (b int) (c int))",
        "(tuple (a (tuple (x int))) (b int) (c int))",
        "(tuple (a (optional UnknownType)) (b int) (c int))",
        "(tuple (a (optional UnknownType)) (b int) (c int))",
        "(tuple (a int) (b int) (c int))",
        "(tuple (a int) (b int) (c int) (d int))",
        "(tuple (a (tuple (x int) (z int))) (b int) (c int))",
        "(tuple (a uint) (b int) (c int))",
    ];

    for (will_pass, expected) in ok.iter().zip(expected.iter()) {
        let type_sig = mem_type_check(will_pass).unwrap().0.unwrap();
        assert_eq!(expected, &type_sig.to_string());
    }

    mem_type_check("(merge { a: 1, b: 2, c: 3 } 5)").unwrap_err();
}

#[test]
fn test_using_merge() {
    let t = "(define-map users uint
                                    { address: principal, name: (optional (string-ascii 32)) })
        (let
            ((user (unwrap-panic (map-get? users u0))))
            (map-set users u0 (merge user { name: none })))
        ";
    mem_type_check(t).unwrap();
}

#[test]
fn test_tuple_map() {
    let t = "(define-map tuples { name: int }
                            { contents: (tuple (name (buff 5))
                                              (owner (buff 5))) })

         (define-private (add-tuple (name int) (content (buff 5)))
           (map-insert tuples (tuple (name name))
                                 (tuple (contents
                                   (tuple (name content)
                                          (owner content))))))
         (define-private (get-tuple (name int))
            (get name (get contents (map-get? tuples (tuple (name name))))))


         (add-tuple 0 0x0102030405)
         (add-tuple 1 0x01020304)
         (list      (get-tuple 0)
                    (get-tuple 1))
        ";
    mem_type_check(t).unwrap();
}

#[test]
fn test_non_tuple_map_get_set() {
    let t = "(define-map entries uint (string-ascii 32))

         (define-private (add-entry (entry-id uint) (content (string-ascii 32)))
           (map-insert entries entry-id content))
         (define-private (get-entry (entry-id uint))
            (map-get? entries entry-id))


         (add-entry u0 \"john\")
         (add-entry u1 \"doe\")
         (list      (get-entry u0)
                    (get-entry u1))
        ";
    mem_type_check(t).unwrap();
}

#[test]
fn test_non_tuple_map_kv_store() {
    let contract = "(define-map kv-store int int)
        (define-private (kv-add (key int) (value int))
        (begin
            (map-insert kv-store key value)
            value))

        (define-private (kv-get (key int))
            (unwrap! (map-get? kv-store key) 0))

        (define-private (kv-set (key int) (value int))
            (begin
                (map-set kv-store key value)
                value))
        (define-private (kv-del (key int))
            (begin
                (map-delete kv-store key)
                key))
   ";
    mem_type_check(contract).unwrap();
}

#[test]
fn test_explicit_tuple_map() {
    let contract = "(define-map kv-store { key: int } { value: int })
          (define-private (kv-add (key int) (value int))
             (begin
                 (map-insert kv-store (tuple (key key))
                                     (tuple (value value)))
             value))
          (define-private (kv-get (key int))
             (unwrap! (get value (map-get? kv-store (tuple (key key)))) 0))
          (define-private (kv-set (key int) (value int))
             (begin
                 (map-set kv-store (tuple (key key))
                                    (tuple (value value)))
                 value))
          (define-private (kv-del (key int))
             (begin
                 (map-delete kv-store (tuple (key key)))
                 key))
         ";

    mem_type_check(contract).unwrap();
}

#[test]
fn test_bound_tuple_map() {
    let contract = "(define-map kv-store { key: int } { value: int })
         (define-private (kv-add (key int) (value int))
            (begin
                (let ((my-tuple (tuple (key key))))
                (map-insert kv-store (tuple (key key))
                                    (tuple (value value))))
            value))
         (define-private (kv-get (key int))
            (let ((my-tuple (tuple (key key))))
            (unwrap! (get value (map-get? kv-store my-tuple)) 0)))
         (define-private (kv-set (key int) (value int))
            (begin
                (let ((my-tuple (tuple (key key))))
                (map-set kv-store my-tuple
                                   (tuple (value value))))
                value))
         (define-private (kv-del (key int))
            (begin
                (let ((my-tuple (tuple (key key))))
                (map-delete kv-store my-tuple))
                key))
        ";

    mem_type_check(contract).unwrap();
}

#[test]
fn test_fetch_entry_matching_type_signatures() {
    let cases = [
        "map-get? kv-store { key: key }",
        "map-get? kv-store { key: 0 }",
        "map-get? kv-store (tuple (key 0))",
        "map-get? kv-store (compatible-tuple)",
    ];

    for case in cases.iter() {
        let contract_src = format!(
            "(define-map kv-store {{ key: int }} {{ value: int }})
             (define-private (compatible-tuple) (tuple (key 1)))
             (define-private (kv-get (key int))
                ({}))",
            case
        );

        mem_type_check(&contract_src).unwrap();
    }
}

#[test]
fn test_fetch_entry_mismatching_type_signatures() {
    let cases = [
        "map-get? kv-store { incomptible-key: key }",
        "map-get? kv-store { key: true }",
        "map-get? kv-store true",
        "map-get? kv-store (incompatible-tuple)",
    ];

    for case in cases.iter() {
        let contract_src = format!(
            "(define-map kv-store {{ key: int }} {{ value: int }})
             (define-private (incompatible-tuple) (tuple (k 1)))
             (define-private (kv-get (key int))
                ({}))",
            case
        );
        let res = mem_type_check(&contract_src).unwrap_err();
        assert!(matches!(res.err, CheckErrors::TypeError(_, _)));
    }
}

#[test]
fn test_fetch_entry_unbound_variables() {
    let cases = ["map-get? kv-store { key: unknown-value }"];

    for case in cases.iter() {
        let contract_src = format!(
            "(define-map kv-store {{ key: int }} {{ value: int }})
             (define-private (kv-get (key int))
                ({}))",
            case
        );
        let res = mem_type_check(&contract_src).unwrap_err();
        assert!(matches!(res.err, CheckErrors::UndefinedVariable(_)));
    }
}

#[test]
fn test_insert_entry_matching_type_signatures() {
    let cases = [
        "map-insert kv-store { key: key } { value: value }",
        "map-insert kv-store { key: 0 } { value: 1 }",
        "map-insert kv-store (tuple (key 0)) (tuple (value 1))",
        "map-insert kv-store (compatible-tuple) { value: 1 }",
    ];

    for case in cases.iter() {
        let contract_src = format!(
            "(define-map kv-store {{ key: int }} {{ value: int }})
             (define-private (compatible-tuple) (tuple (key 1)))
             (define-private (kv-add (key int) (value int))
                ({}))",
            case
        );
        mem_type_check(&contract_src).unwrap();
    }
}

#[test]
fn test_insert_entry_mismatching_type_signatures() {
    let cases = [
        "map-insert kv-store { incomptible-key: key } { value: value }",
        "map-insert kv-store { key: key } { incomptible-key: value }",
        "map-insert kv-store { key: true } { value: 1 }",
        "map-insert kv-store { key: key } { value: true }",
        "map-insert kv-store (incompatible-tuple) { value: 1 }",
    ];

    for case in cases.iter() {
        let contract_src = format!(
            "(define-map kv-store {{ key: int }} {{ value: int }})
             (define-private (incompatible-tuple) (tuple (k 1)))
             (define-private (kv-add (key int) (value int))
                ({}))",
            case
        );
        let res = mem_type_check(&contract_src).unwrap_err();
        assert!(matches!(res.err, CheckErrors::TypeError(_, _)));
    }
}

#[test]
fn test_insert_entry_unbound_variables() {
    let cases = [
        "map-insert kv-store { key: unknown-value } { value: 1 }",
        "map-insert kv-store { key: key } { value: unknown-value }",
    ];

    for case in cases.iter() {
        let contract_src = format!(
            "(define-map kv-store {{ key: int }} {{ value: int }})
             (define-private (kv-add (key int))
                ({}))",
            case
        );
        let res = mem_type_check(&contract_src).unwrap_err();
        assert!(matches!(res.err, CheckErrors::UndefinedVariable(_)));
    }
}

#[test]
fn test_delete_entry_matching_type_signatures() {
    let cases = [
        "map-delete kv-store (tuple (key key))",
        "map-delete kv-store { key: 1 }",
        "map-delete kv-store (tuple (key 1))",
        "map-delete kv-store (compatible-tuple)",
    ];

    for case in cases.iter() {
        let contract_src = format!(
            "(define-map kv-store {{ key: int }} {{ value: int }})
             (define-private (compatible-tuple) (tuple (key 1)))
             (define-private (kv-del (key int))
                ({}))",
            case
        );
        mem_type_check(&contract_src).unwrap();
    }
}

#[test]
fn test_delete_entry_mismatching_type_signatures() {
    let cases = [
        "map-delete kv-store (tuple (incomptible-key key))",
        "map-delete kv-store { key: true }",
        "map-delete kv-store (incompatible-tuple)",
    ];

    for case in cases.iter() {
        let contract_src = format!(
            "(define-map kv-store {{ key: int }} {{ value: int }})
             (define-private (incompatible-tuple) (tuple (k 1)))
             (define-private (kv-del (key int))
                ({}))",
            case
        );
        let res = mem_type_check(&contract_src).unwrap_err();
        assert!(matches!(res.err, CheckErrors::TypeError(_, _)));
    }
}

#[test]
fn test_delete_entry_unbound_variables() {
    let cases = ["map-delete kv-store { key: unknown-value }"];

    for case in cases.iter() {
        let contract_src = format!(
            "(define-map kv-store {{ key: int }} {{ value: int }})
             (define-private (kv-del (key int))
                ({}))",
            case
        );
        let res = mem_type_check(&contract_src).unwrap_err();
        assert!(matches!(res.err, CheckErrors::UndefinedVariable(_)));
    }
}

#[test]
fn test_set_entry_matching_type_signatures() {
    let cases = [
        "map-set kv-store { key: key } { value: value }",
        "map-set kv-store { key: 0 } { value: 1 }",
        "map-set kv-store (tuple (key 0)) (tuple (value 1))",
        "map-set kv-store (tuple (key 0)) (tuple (value known-value))",
        "map-set kv-store (compatible-tuple) { value: 1 }",
    ];

    for case in cases.iter() {
        let contract_src = format!(
            "(define-map kv-store {{ key: int }} {{ value: int }})
             (define-private (compatible-tuple) (tuple (key 1)))
             (define-private (kv-set (key int) (value int))
                (let ((known-value 2))
                ({})))",
            case
        );
        mem_type_check(&contract_src).unwrap();
    }
}

#[test]
fn test_set_entry_mismatching_type_signatures() {
    let cases = [
        "map-set kv-store (tuple (incomptible-key key)) (tuple (value value))",
        "map-set kv-store { key: key } { incomptible-key: value }",
        "map-set kv-store { key: true } { value: 1 }",
        "map-set kv-store { key: key } { value: true }",
        "map-set kv-store (incompatible-tuple) { value: 1 }",
    ];

    for case in cases.iter() {
        let contract_src = format!(
            "(define-map kv-store {{ key: int }} {{ value: int }})
             (define-private (incompatible-tuple) (tuple (k 1)))
             (define-private (kv-set (key int) (value int))
                ({}))",
            case
        );
        let res = mem_type_check(&contract_src).unwrap_err();
        assert!(matches!(res.err, CheckErrors::TypeError(_, _)));
    }
}

#[test]
fn test_set_entry_unbound_variables() {
    let cases = [
        "map-set kv-store { key: unknown-value } { value: 1 }",
        "map-set kv-store { key: key } { value: unknown-value }",
    ];

    for case in cases.iter() {
        let contract_src = format!(
            "(define-map kv-store {{ key: int }} {{ value: int }})
             (define-private (kv-set (key int) (value int))
                ({}))",
            case
        );
        let res = mem_type_check(&contract_src).unwrap_err();
        assert!(matches!(res.err, CheckErrors::UndefinedVariable(_)));
    }
}

#[test]
fn test_string_ascii_fold() {
    let good = [
        "(define-private (get-len (x (string-ascii 1)) (acc uint)) (+ acc u1))
        (fold get-len \"blockstack\" u0)",
        "(define-private (get-slice (x (string-ascii 1)) (acc (tuple (limit uint) (cursor uint) (data (string-ascii 10)))))
            (if (< (get cursor acc) (get limit acc))
                (let ((data (default-to (get data acc) (as-max-len? (concat (get data acc) x) u10))))
                    (tuple (limit (get limit acc)) (cursor (+ u1 (get cursor acc))) (data data)))
                acc))
        (fold get-slice \"blockstack\" (tuple (limit u5) (cursor u0) (data \"\")))"];
    let expected = [
        "uint",
        "(tuple (cursor uint) (data (string-ascii 10)) (limit uint))",
    ];

    for (good_test, expected) in good.iter().zip(expected.iter()) {
        let type_sig = mem_type_check(good_test).unwrap().0.unwrap();
        assert_eq!(expected, &type_sig.to_string());
    }
}

#[test]
fn test_string_ascii_as_max_len() {
    let tests = [
        "(as-max-len? \"12345\" u5)",
        "(as-max-len? \"12345\" u8)",
        "(as-max-len? \"12345\" u4)",
    ];
    let expected = [
        "(optional (string-ascii 5))",
        "(optional (string-ascii 8))",
        "(optional (string-ascii 4))",
    ];

    for (test, expected) in tests.iter().zip(expected.iter()) {
        assert_eq!(expected, &format!("{}", type_check_helper(test).unwrap()));
    }
}

#[test]
fn test_string_ascii_concat() {
    let good = ["(concat \"block\" \"stack\")"];
    let expected = ["(string-ascii 10)"];

    for (good_test, expected) in good.iter().zip(expected.iter()) {
        assert_eq!(
            expected,
            &format!("{}", type_check_helper(good_test).unwrap())
        );
    }
}

#[test]
fn test_string_utf8_fold() {
    let good = [
        "(define-private (get-len (x (string-utf8 1)) (acc uint)) (+ acc u1))
        (fold get-len u\"blockstack\" u0)",
        "(define-private (get-slice (x (string-utf8 1)) (acc (tuple (limit uint) (cursor uint) (data (string-utf8 11)))))
            (if (< (get cursor acc) (get limit acc))
                (let ((data (default-to (get data acc) (as-max-len? (concat (get data acc) x) u11))))
                    (tuple (limit (get limit acc)) (cursor (+ u1 (get cursor acc))) (data data)))
                acc))
        (fold get-slice u\"blockstack\\u{1F926}\" (tuple (limit u5) (cursor u0) (data u\"\")))"];
    let expected = [
        "uint",
        "(tuple (cursor uint) (data (string-utf8 11)) (limit uint))",
    ];

    for (good_test, expected) in good.iter().zip(expected.iter()) {
        let type_sig = mem_type_check(good_test).unwrap().0.unwrap();
        assert_eq!(expected, &type_sig.to_string());
    }
}

#[test]
fn test_string_utf8_as_max_len() {
    let tests = [
        "(as-max-len? u\"1234\\u{1F926}\" u5)",
        "(as-max-len? u\"1234\\u{1F926}\" u8)",
        "(as-max-len? u\"1234\\u{1F926}\" u4)",
    ];
    let expected = [
        "(optional (string-utf8 5))",
        "(optional (string-utf8 8))",
        "(optional (string-utf8 4))",
    ];

    for (test, expected) in tests.iter().zip(expected.iter()) {
        assert_eq!(expected, &format!("{}", type_check_helper(test).unwrap()));
    }
}

#[test]
fn test_string_utf8_concat() {
    let good = ["(concat u\"block\" u\"stack\\u{1F926}\")"];
    let expected = ["(string-utf8 11)"];

    for (good_test, expected) in good.iter().zip(expected.iter()) {
        assert_eq!(
            expected,
            &format!("{}", type_check_helper(good_test).unwrap())
        );
    }
}

#[test]
fn test_buff_negative_len() {
    let contract_src = "(define-private (func (x (buff -12))) (len x))
        (func 0x00)";

    let res = mem_type_check(contract_src).unwrap_err();
    assert!(matches!(res.err, CheckErrors::BadSyntaxBinding));
}

#[test]
fn test_string_ascii_negative_len() {
    let contract_src = "(define-private (func (x (string-ascii -12))) (len x))
        (func \"\")";

    let res = mem_type_check(contract_src).unwrap_err();
    assert!(matches!(res.err, CheckErrors::BadSyntaxBinding));
}

#[test]
fn test_string_utf8_negative_len() {
    let contract_src = "(define-private (func (x (string-utf8 -12))) (len x))
        (func u\"\")";

    let res = mem_type_check(contract_src).unwrap_err();
    assert!(matches!(res.err, CheckErrors::BadSyntaxBinding));
}

#[test]
fn test_comparison_types() {
    let good = [
        r#"(<= "aaa" "aa")"#,
        r#"(>= "aaa" "aa")"#,
        r#"(< "aaa" "aa")"#,
        r#"(> "aaa" "aa")"#,
        r#"(<= u"aaa" u"aa")"#,
        r#"(>= u"aaa" u"aa")"#,
        r#"(< u"aaa" u"aa")"#,
        r#"(> u"aaa" u"aa")"#,
        r#"(<= 0x01 0x02)"#,
        r#"(>= 0x01 0x02)"#,
        r#"(< 0x01 0x02)"#,
        r#"(> 0x01 0x02)"#,
    ];

    let expected = [
        "bool", "bool", "bool", "bool", "bool", "bool", "bool", "bool", "bool", "bool", "bool",
        "bool",
    ];

    for (good_test, expected) in good.iter().zip(expected.iter()) {
        assert_eq!(
            expected,
            &format!("{}", type_check_helper(good_test).unwrap())
        );
    }

    let bad = [
        r#"(<= 'SZ2J6ZY48GV1EZ5V2V5RB9MP66SW86PYKKQ9H6DPR 'SZ2J6ZY48GV1EZ5V2V5RB9MP66SW86PYKKQ9H6DPR)"#,
        r#"(<= (list 1 2 3) (list 1 2 3))"#,
        r#"(<= u"aaa" "aa")"#,
        r#"(>= "aaa" 0x0101)"#,
        r#"(>= 0x0101 u"aaa")"#,
        r#"(>= 0x0101 "aaa")"#,
        r#"(>=)"#,
        r#"(>= "aaa")"#,
        r#"(>= "aaa" "aaa" "aaa")"#,
    ];
    let bad_expected = [
        CheckErrors::UnionTypeError(
            vec![
                IntType,
                UIntType,
                SequenceType(StringType(ASCII(
                    BufferLength::try_from(1048576_u32).unwrap(),
                ))),
                SequenceType(StringType(UTF8(
                    StringUTF8Length::try_from(262144_u32).unwrap(),
                ))),
                SequenceType(BufferType(BufferLength::try_from(1048576_u32).unwrap())),
            ],
            PrincipalType,
        ),
        CheckErrors::UnionTypeError(
            vec![
                IntType,
                UIntType,
                SequenceType(StringType(ASCII(
                    BufferLength::try_from(1048576_u32).unwrap(),
                ))),
                SequenceType(StringType(UTF8(
                    StringUTF8Length::try_from(262144_u32).unwrap(),
                ))),
                SequenceType(BufferType(BufferLength::try_from(1048576_u32).unwrap())),
            ],
            SequenceType(ListType(ListTypeData::new_list(IntType, 3).unwrap())),
        ),
        CheckErrors::TypeError(
            SequenceType(StringType(UTF8(StringUTF8Length::try_from(3u32).unwrap()))),
            SequenceType(StringType(ASCII(BufferLength::try_from(2_u32).unwrap()))),
        ),
        CheckErrors::TypeError(
            SequenceType(StringType(ASCII(BufferLength::try_from(3_u32).unwrap()))),
            SequenceType(BufferType(BufferLength::try_from(2_u32).unwrap())),
        ),
        CheckErrors::TypeError(
            SequenceType(BufferType(BufferLength::try_from(2_u32).unwrap())),
            SequenceType(StringType(UTF8(StringUTF8Length::try_from(3u32).unwrap()))),
        ),
        CheckErrors::TypeError(
            SequenceType(BufferType(BufferLength::try_from(2_u32).unwrap())),
            SequenceType(StringType(ASCII(BufferLength::try_from(3_u32).unwrap()))),
        ),
        CheckErrors::IncorrectArgumentCount(2, 0),
        CheckErrors::IncorrectArgumentCount(2, 1),
        CheckErrors::IncorrectArgumentCount(2, 3),
    ];

    for (bad_test, expected) in bad.iter().zip(bad_expected.iter()) {
        assert_eq!(expected, &type_check_helper(bad_test).unwrap_err().err);
    }
}

#[test]
fn test_principal_destruct() {
    let good = [
        // Standard good examples.
        r#"(principal-destruct? 'STB44HYPYAT2BB2QE513NSP81HTMYWBJP02HPGK6)"#,
        r#"(principal-destruct? 'STB44HYPYAT2BB2QE513NSP81HTMYWBJP02HPGK6.foo)"#,
    ];
    let expected = [
        "(response (tuple (hash-bytes (buff 20)) (name (optional (string-ascii 40))) (version (buff 1))) (tuple (hash-bytes (buff 20)) (name (optional (string-ascii 40))) (version (buff 1))))",
        "(response (tuple (hash-bytes (buff 20)) (name (optional (string-ascii 40))) (version (buff 1))) (tuple (hash-bytes (buff 20)) (name (optional (string-ascii 40))) (version (buff 1))))"
    ];

    let bad = [
        // Too many arguments.
        r#"(principal-destruct? 'STB44HYPYAT2BB2QE513NSP81HTMYWBJP02HPGK6 'STB44HYPYAT2BB2QE513NSP81HTMYWBJP02HPGK6)"#,
        // Too few arguments.
        r#"(principal-destruct?)"#,
        // Wrong type of arguments.
        r#"(principal-destruct? 0x22)"#,
    ];
    let bad_expected = [
        CheckErrors::IncorrectArgumentCount(1, 2),
        CheckErrors::IncorrectArgumentCount(1, 0),
        CheckErrors::TypeError(TypeSignature::PrincipalType, BUFF_1.clone()),
    ];

    for (good_test, expected) in good.iter().zip(expected.iter()) {
        assert_eq!(
            expected,
            &format!("{}", type_check_helper(good_test).unwrap())
        );
    }

    for (bad_test, expected) in bad.iter().zip(bad_expected.iter()) {
        assert_eq!(expected, &type_check_helper(bad_test).unwrap_err().err);
    }
}

#[test]
fn test_principal_construct() {
    // This is the type we expect on success.
    let expected_type =
        "(response principal (tuple (error_code uint) (value (optional principal))))";
    let good_pairs = [
        // Standard good example of a standard principal
        (
            r#"(principal-construct? 0x22 0xfa6bf38ed557fe417333710d6033e9419391a320)"#,
            expected_type,
        ),
        // Standard good example of a contract principal.
        (
            r#"(principal-construct? 0x22 0xfa6bf38ed557fe417333710d6033e9419391a320 "foo")"#,
            expected_type,
        ),
        // Note: This following buffer is too short. It type-checks but triggers a runtime error.
        (r#"(principal-construct? 0x22 0x00)"#, expected_type),
        // Note: This following name is too short. It type-checks but triggers a runtime error.
        (
            r#"(principal-construct? 0x22 0xfa6bf38ed557fe417333710d6033e9419391a320 "")"#,
            expected_type,
        ),
    ];

    for (good_test, expected) in good_pairs.iter() {
        assert_eq!(
            expected,
            &format!("{}", type_check_helper(good_test).unwrap())
        );
    }

    let bad_pairs = [
        // Too few arguments, just has the `(buff 1)`.
        (
            r#"(principal-construct? 0x22)"#,
            CheckErrors::RequiresAtLeastArguments(2, 1),
        ),
        // Too few arguments, just hs the `(buff 20)`.
        (
            r#"(principal-construct? 0xfa6bf38ed557fe417333710d6033e9419391a320)"#,
            CheckErrors::RequiresAtLeastArguments(2, 1),
        ),
        // The first buffer is too long, should be `(buff 1)`.
        (
            r#"(principal-construct? 0xfa6bf38ed557fe417333710d6033e9419391a320 0xfa6bf38ed557fe417333710d6033e9419391a320)"#,
            CheckErrors::TypeError(BUFF_1.clone(), BUFF_20.clone()),
        ),
        // The second buffer is too long, should be `(buff 20)`.
        (
            r#"(principal-construct? 0x22 0xfa6bf38ed557fe417333710d6033e9419391a32009)"#,
            CheckErrors::TypeError(BUFF_20.clone(), BUFF_21.clone()),
        ),
        // `int` argument instead of `(buff 1)` for version.
        (
            r#"(principal-construct? 22 0xfa6bf38ed557fe417333710d6033e9419391a320)"#,
            CheckErrors::TypeError(BUFF_1.clone(), IntType),
        ),
        // `name` argument is too long
        (
            r#"(principal-construct? 0x22 0xfa6bf38ed557fe417333710d6033e9419391a320 "foooooooooooooooooooooooooooooooooooooooo")"#,
            CheckErrors::TypeError(
                TypeSignature::contract_name_string_ascii_type().unwrap(),
                TypeSignature::bound_string_ascii_type(41).unwrap(),
            ),
        ),
        // bad argument type for `name`
        (
            r#"(principal-construct? 0x22 0xfa6bf38ed557fe417333710d6033e9419391a320 u123)"#,
            CheckErrors::TypeError(
                TypeSignature::contract_name_string_ascii_type().unwrap(),
                UIntType,
            ),
        ),
        // too many arguments
        (
            r#"(principal-construct? 0x22 0xfa6bf38ed557fe417333710d6033e9419391a320 "foo" "bar")"#,
            CheckErrors::RequiresAtMostArguments(3, 4),
        ),
    ];

    for (bad_test, expected) in bad_pairs.iter() {
        assert_eq!(expected, &type_check_helper(bad_test).unwrap_err().err);
    }
}

#[test]
fn test_trait_args() {
    let good = [
        "(define-trait trait-foo ((foo () (response uint uint))))
        (define-private (call-foo (f <trait-foo>))
            (contract-call? f foo)
        )
        (define-public (call-foo-outer (f <trait-foo>))
            (begin
                (call-foo f)
            )
        )",
        "(define-trait trait-foobar
            (
                (foo () (response uint uint))
                (bar () (response uint uint))
            )
        )
        (define-trait trait-foo ((foo () (response uint uint))))
        (define-private (call-foo (f <trait-foo>))
            (contract-call? f foo)
        )
        (define-public (call-foo-foobar (f <trait-foobar>))
            (begin
                (call-foo f)
            )
        )",
    ];

    let bad = ["(define-trait trait-bar
            (
                (bar () (response uint uint))
            )
        )
        (define-trait trait-foo ((foo () (response uint uint))))
        (define-private (call-foo (f <trait-foo>))
            (contract-call? f foo)
        )
        (define-public (call-foo-foobar (f <trait-bar>))
            (begin
                (call-foo f)
            )
        )"];

    let contract_identifier = QualifiedContractIdentifier::transient();
    let bad_expected = [CheckErrors::IncompatibleTrait(
        TraitIdentifier {
            name: ClarityName::from("trait-foo"),
            contract_identifier: contract_identifier.clone(),
        },
        TraitIdentifier {
            name: ClarityName::from("trait-bar"),
            contract_identifier,
        },
    )];

    for good_test in good.iter() {
        assert!(mem_type_check(good_test).is_ok());
    }

    for (bad_test, expected) in bad.iter().zip(bad_expected.iter()) {
        assert_eq!(expected, &mem_type_check(bad_test).unwrap_err().err);
    }
}

#[test]
fn test_wrapped_trait() {
    let good = [
        "(define-trait trait-foo ((foo () (response uint uint))))
        (define-public (call-foo-if (opt (optional <trait-foo>)))
            (match opt
                f (contract-call? f foo)
                (ok u1)
            )
        )",
        "(define-trait trait-foo ((foo () (response uint uint))))
        (define-private (call-foo (f <trait-foo>))
            (unwrap! (contract-call? f foo) u2)
        )
        (define-public (call-foo-list (l (list 5 <trait-foo>)))
            (ok (map call-foo l))
        )",
        "(define-trait trait-foo ((foo () (response uint uint))))
        (define-private (return-f (f <trait-foo>))
            (if true (ok f) (err u1))
        )
        (define-public (call-foo (f <trait-foo>))
            (match (return-f f)
                f-prime (contract-call? f-prime foo)
                e (err u1)
            )
        )",
        "(define-trait trait-foo ((foo () (response uint uint))))
        (define-private (return-f (f <trait-foo>))
            (if true (err f) (ok u1))
        )
        (define-public (call-foo (f <trait-foo>))
            (match (return-f f)
                v (ok v)
                f-prime (contract-call? f-prime foo)
            )
        )",
    ];

    for good_test in good.iter() {
        assert!(mem_type_check(good_test).is_ok());
    }
}

#[test]
fn test_let_bind_trait() {
    let good = ["(define-trait trait-foo ((foo () (response uint uint))))
        (define-public (call-foo (f <trait-foo>))
            (let ((g f))
                (contract-call? g foo)
            )
        )"];

    for good_test in good.iter() {
        assert!(mem_type_check(good_test).is_ok());
    }
}

#[apply(test_clarity_versions)]
fn test_trait_same_contract(#[case] version: ClarityVersion, #[case] epoch: StacksEpochId) {
    let good = ["(define-trait trait-foo ((foo () (response uint uint))))
        (define-public (call-foo (f <trait-foo>))
            (contract-call? f foo)
        )
        (define-public (trigger (f <trait-foo>)) (call-foo f))"];

    for good_test in good.iter() {
        let result = mem_run_analysis(good_test, version, epoch);
        assert!(result.is_ok());
    }
}

#[test]
fn test_tuple_arg() {
    let contract = "(define-private (add (value {a: int, b: uint}))
            (get a value))
         (define-private (test-call)
            (add {a: 3, b: u5}))
        ";

    mem_type_check(contract).unwrap();

    let bad_contracts = [
        "(define-private (bad1 (value {a: int, b: uint}))
            (get a value))
        (define-private (test-call)
            (bad1 {a: u3, b: u5}))
        ",
        "(define-private (bad2 (value {a: int, b: uint}))
            (get a value))
         (define-private (test-call)
            (bad2 {a: 3}))
        ",
        "(define-private (bad3 (value {a: int, b: uint}))
            (get a value))
         (define-private (test-call)
            (bad3 {a: 3, b: u5, c: 4}))
        ",
    ];
    for bad_test in bad_contracts.iter() {
        mem_type_check(bad_test).unwrap_err();
    }
}

#[apply(test_clarity_versions)]
fn test_list_arg(#[case] version: ClarityVersion, #[case] epoch: StacksEpochId) {
    let good = [
        "(define-private (foo (l (list 3 int)))
            (element-at l u0))
         (define-private (test-call)
            (foo (list 1 2 3)))
        ",
        "(define-private (foo (l (list 3 int)))
            (element-at l u0))
         (define-private (test-call)
            (foo (list 1)))
        ",
        "(define-private (foo (l (list 3 int)))
            (element-at l u0))
         (define-private (test-call)
            (foo (list)))
        ",
    ];

    for good_test in good.iter() {
        assert!(mem_run_analysis(good_test, version, epoch).is_ok());
    }

    let bad = [
        "(define-private (foo (l (list 3 int)))
            (element-at l u0))
         (define-private (test-call)
            (foo (list 1 2 3 4)))
        ",
        "(define-private (foo (l (list 3 int)))
            (element-at l u0))
         (define-private (test-call)
            (foo (list u1)))
        ",
        "(define-private (foo (l (list 3 int)))
            (element-at l u0))
         (define-private (test-call)
            (foo (list (list))))
        ",
    ];
    let bad_expected = [
        CheckErrors::TypeError(
            TypeSignature::list_of(TypeSignature::IntType, 3).unwrap(),
            TypeSignature::list_of(TypeSignature::IntType, 4).unwrap(),
        ),
        CheckErrors::TypeError(
            TypeSignature::list_of(TypeSignature::IntType, 3).unwrap(),
            TypeSignature::list_of(TypeSignature::UIntType, 1).unwrap(),
        ),
        CheckErrors::TypeError(
            TypeSignature::list_of(TypeSignature::IntType, 3).unwrap(),
            TypeSignature::list_of(TypeSignature::list_of(TypeSignature::NoType, 0).unwrap(), 1)
                .unwrap(),
        ),
    ];
    let bad_expected2 = [
        CheckErrors::TypeError(
            TypeSignature::list_of(TypeSignature::IntType, 3).unwrap(),
            TypeSignature::list_of(TypeSignature::IntType, 4).unwrap(),
        ),
        CheckErrors::TypeError(TypeSignature::IntType, TypeSignature::UIntType),
        CheckErrors::TypeError(
            TypeSignature::IntType,
            TypeSignature::list_of(TypeSignature::NoType, 0).unwrap(),
        ),
    ];

    for (bad_test, expected) in bad.iter().zip(
        if version == ClarityVersion::Clarity1 {
            bad_expected
        } else {
            bad_expected2
        }
        .iter(),
    ) {
        assert_eq!(
            expected,
            &mem_run_analysis(bad_test, version, epoch).unwrap_err().err
        );
    }
}

#[test]
fn test_principal_admits() {
    let good = ["(define-public (set-extensions (extension-list (list 200 {extension: principal, enabled: bool})))
    (ok true)
  )
  (define-private (init)
    (set-extensions (list
      { extension: .fake-b, enabled: true }
    ))
  )",
  "(define-public (set-extensions (extension-list (list 200 {extension: principal, enabled: bool})))
    (ok true)
  )
  (define-private (init)
    (set-extensions (list
      { extension: .fake-b, enabled: true }
      { extension: .fake-b, enabled: true }
    ))
  )",
  "(define-public (set-extensions (extension-list (list 200 {extension: principal, enabled: bool})))
    (ok true)
  )
  (define-private (init)
    (set-extensions (list
      { extension: .fake-b, enabled: true }
      { extension: .fake-c, enabled: true }
    ))
  )"];

    for good_test in good.iter() {
        let res = mem_type_check(good_test);
        println!("{:?}", res);
        assert!(res.is_ok());
    }

    let bad = ["(define-public (set-extensions (extension-list (list 200 {extension: principal, enabled: bool})))
    (ok true)
  )
  (define-trait fake-trait ())
  (define-private (init (fake <fake-trait>))
    (set-extensions (list
      { extension: fake, enabled: true }
    ))
  )",
  "(define-public (set-extensions (extension-list (list 200 {extension: principal, enabled: bool})))
    (ok true)
  )
  (define-trait fake-trait ())
  (define-private (init (fake <fake-trait>))
    (set-extensions (list
      { extension: fake, enabled: true }
      { extension: .fake-b, enabled: true }
    ))
  )"];

    for bad_test in bad.iter() {
        let res = mem_type_check(bad_test);
        println!("{:?}", res);
        assert!(res.is_err());
    }
}
