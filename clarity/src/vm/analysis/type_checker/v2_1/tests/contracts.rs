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

use std::fs::read_to_string;

use assert_json_diff::assert_json_eq;
use serde_json;
use stacks_common::types::StacksEpochId;

use crate::vm::analysis::contract_interface_builder::build_contract_interface;
use crate::vm::analysis::errors::CheckErrors;
use crate::vm::analysis::type_checker::v2_1::tests::mem_type_check;
use crate::vm::analysis::{
    mem_type_check as mem_run_analysis, run_analysis, AnalysisDatabase, CheckError, CheckResult,
    ContractAnalysis,
};
use crate::vm::ast::parse;
use crate::vm::costs::LimitedCostTracker;
use crate::vm::database::MemoryBackingStore;
use crate::vm::tests::test_clarity_versions;
use crate::vm::types::signatures::CallableSubtype;
use crate::vm::types::{QualifiedContractIdentifier, TypeSignature};
use crate::vm::{ClarityVersion, SymbolicExpression};

fn mem_type_check_v1(snippet: &str) -> CheckResult<(Option<TypeSignature>, ContractAnalysis)> {
    mem_run_analysis(snippet, ClarityVersion::Clarity1, StacksEpochId::latest())
}

#[template]
#[rstest]
#[case(ClarityVersion::Clarity1)]
#[case(ClarityVersion::Clarity2)]
fn test_epoch21_clarity_versions(#[case] version: ClarityVersion) {}

/// backwards-compatibility shim
pub fn type_check(
    contract_identifier: &QualifiedContractIdentifier,
    expressions: &mut [SymbolicExpression],
    analysis_db: &mut AnalysisDatabase,
    save_contract: bool,
) -> Result<ContractAnalysis, CheckError> {
    type_check_version(
        contract_identifier,
        expressions,
        analysis_db,
        save_contract,
        StacksEpochId::Epoch21,
        ClarityVersion::Clarity2,
    )
}

pub fn type_check_version(
    contract_identifier: &QualifiedContractIdentifier,
    expressions: &mut [SymbolicExpression],
    analysis_db: &mut AnalysisDatabase,
    save_contract: bool,
    epoch: StacksEpochId,
    version: ClarityVersion,
) -> Result<ContractAnalysis, CheckError> {
    run_analysis(
        contract_identifier,
        expressions,
        analysis_db,
        save_contract,
        LimitedCostTracker::new_free(),
        epoch,
        version,
        false,
    )
    .map_err(|(e, _)| e)
}

const SIMPLE_TOKENS: &str = "(define-map tokens { account: principal } { balance: uint })
         (define-read-only (my-get-token-balance (account principal))
            (let ((balance
                  (get balance (map-get? tokens (tuple (account account))))))
              (default-to u0 balance)))

         (define-private (token-credit! (account principal) (amount uint))
            (if (<= amount u0)
                (err 1)
                (let ((current-amount (my-get-token-balance account)))
                  (begin
                    (map-set tokens (tuple (account account))
                                       (tuple (balance (+ amount current-amount))))
                    (ok u0)))))
         (define-public (token-transfer (to principal) (amount uint))
          (let ((balance (my-get-token-balance tx-sender)))
             (if (or (> amount balance) (<= amount u0))
                 (err 2)
                 (begin
                   (map-set tokens (tuple (account tx-sender))
                                      (tuple (balance (- balance amount))))
                   (token-credit! to amount)))))
         (begin (unwrap-panic (token-credit! 'SZ2J6ZY48GV1EZ5V2V5RB9MP66SW86PYKKQ9H6DPR u10000))
                (unwrap-panic (token-credit! 'SM2J6ZY48GV1EZ5V2V5RB9MP66SW86PYKKQVX8X0G u300)))";

const SIMPLE_NAMES: &str = "(define-constant burn-address 'SP000000000000000000002Q6VF78)
         (define-private (price-function (name uint))
           (if (< name u100000) u1000 u100))
         
         (define-map name-map 
           { name: uint } { owner: principal })
         (define-map preorder-map
           { name-hash: (buff 20) }
           { buyer: principal, paid: uint })

         (define-private (check-balance)
           (contract-call? .tokens my-get-token-balance tx-sender))

         (define-public (preorder 
                        (name-hash (buff 20))
                        (name-price uint))
           (let ((xfer-result (contract-call? .tokens token-transfer
                                  burn-address name-price)))
            (if (is-ok xfer-result)
               (if
                 (map-insert preorder-map
                   (tuple (name-hash name-hash))
                   (tuple (paid name-price)
                          (buyer tx-sender)))
                 (ok 0) (err 2))
               (if (is-eq (unwrap-err! xfer-result (err (- 1)))
                        2)
                   (err 1) (err 3)))))

         (define-public (register
                        (recipient-principal principal)
                        (name uint)
                        (salt uint))
           (let ((preorder-entry
                   ;; preorder entry must exist!
                   (unwrap! (map-get? preorder-map
                                  (tuple (name-hash (hash160 (xor name salt))))) (err 2)))
                 (name-entry 
                   (map-get? name-map (tuple (name name)))))
             (if (and
                  ;; name shouldn't *already* exist
                  (is-none name-entry)
                  ;; preorder must have paid enough
                  (<= (price-function name) 
                      (get paid preorder-entry))
                  ;; preorder must have been the current principal
                  (is-eq tx-sender
                       (get buyer preorder-entry)))
                  (if (and
                    (map-insert name-map
                      (tuple (name name))
                      (tuple (owner recipient-principal)))
                    (map-delete preorder-map
                      (tuple (name-hash (hash160 (xor name salt))))))
                    (ok 0)
                    (err 3))
                  (err 4))))";

#[test]
fn test_names_tokens_contracts_interface() {
    const INTERFACE_TEST_CONTRACT: &str = "
        (define-constant var1 'SP000000000000000000002Q6VF78)
        (define-constant var2 true)
        (define-constant var3 45)

        (define-data-var d-var1 bool true)
        (define-data-var d-var2 int 2)
        (define-data-var d-var3 (buff 5) 0xdeadbeef)

        (define-map map1 { name: int } { owner: principal })
        (define-map map2 { k-name-1: bool } { v-name-1: (buff 33) })
        (define-map map3 { k-name-2: bool } { v-name-2: (tuple (n1 int) (n2 bool)) })

        (define-private (f00 (a1 int)) true)
        (define-private (f01 (a1 bool)) true)
        (define-private (f02 (a1 principal)) true)
        (define-private (f03 (a1 (buff 54))) true)
        (define-private (f04 (a1 (tuple (t-name1 bool) (t-name2 int)))) true)
        (define-private (f05 (a1 (list 7 (list 3 int)))) true)

        (define-private (f06) 1)
        (define-private (f07) true)
        (define-private (f08) 'SP000000000000000000002Q6VF78)
        (define-private (f09) 0xdeadbeef)
        (define-private (f10) (tuple (tn1 true) (tn2 0) (tn3 0xff) ))
        (define-private (f11) (map-get? map1 (tuple (name 0))))
        (define-private (f12) (ok 3))
        (define-private (f13) (err 6))
        (define-private (f14) (if true (ok 1) (err 2)))
        (define-private (f15) (list 1 2 3))
        (define-private (f16) (list (list (list 5)) (list (list 55))))

        (define-public (pub-f01) (ok 1))
        (define-public (pub-f02) (ok true))
        (define-public (pub-f03) (err true))
        (define-public (pub-f04) (if true (ok 1) (err 2)))
        (define-public (pub-f05 (a1 int)) (ok true))

        (define-read-only (ro-f01) 0)
        (define-read-only (ro-f02 (a1 int)) 0)
    ";

    let contract_analysis = mem_type_check(INTERFACE_TEST_CONTRACT).unwrap().1;
    let test_contract_json_str = build_contract_interface(&contract_analysis)
        .unwrap()
        .serialize()
        .unwrap();
    let test_contract_json: serde_json::Value =
        serde_json::from_str(&test_contract_json_str).unwrap();

    let test_contract_json_expected: serde_json::Value = serde_json::from_str(r#"{
        "functions": [
            { "name": "f00",
                "access": "private",
                "args": [{ "name": "a1", "type": "int128" }],
                "outputs": { "type": "bool" }
            },
            { "name": "f01",
                "access": "private",
                "args": [{ "name": "a1", "type": "bool" }],
                "outputs": { "type": "bool" }
            },
            { "name": "f02",
                "access": "private",
                "args": [{ "name": "a1", "type": "principal" }],
                "outputs": { "type": "bool" }
            },
            { "name": "f03",
                "access": "private",
                "args": [{ "name": "a1", "type": { "buffer": { "length": 54 } } }],
                "outputs": { "type": "bool" }
            },
            { "name": "f04",
                "access": "private",
                "args": [{ "name": "a1", "type": { "tuple": [
                    { "name": "t-name1", "type": "bool" },
                    { "name": "t-name2", "type": "int128" }
                ] } }],
                "outputs": { "type": "bool" }
            },
            { "name": "f05",
                "access": "private",
                "args": [{ "name": "a1", "type": { "list": { "type": { "list": { "type": "int128", "length": 3 } }, "length": 7 } } }],
                "outputs": { "type": "bool" }
            },
            { "name": "f06",
                "access": "private",
                "args": [],
                "outputs": { "type": "int128" }
            },
            { "name": "f07",
                "access": "private",
                "args": [],
                "outputs": { "type": "bool" }
            },
            { "name": "f08",
                "access": "private",
                "args": [],
                "outputs": { "type": "principal" }
            },
            { "name": "f09",
                "access": "private",
                "args": [],
                "outputs": { "type": { "buffer": { "length": 4 } } }
            },
            { "name": "f10",
                "access": "private",
                "args": [],
                "outputs": { "type": { "tuple": [
                    { "name": "tn1", "type": "bool" },
                    { "name": "tn2", "type": "int128" },
                    { "name": "tn3", "type": { "buffer": { "length": 1 } }}
                ] } } 
            },
            { "name": "f11",
                "access": "private",
                "args": [],
                "outputs": { "type": { "optional": { "tuple": [ {
                    "name": "owner",
                    "type": "principal"
                 } ] } } }
            },
            { "name": "f12",
                "access": "private",
                "args": [],
                "outputs": { "type": { "response": { "ok": "int128", "error": "none" } } }
            },
            { "name": "f13",
                "access": "private",
                "args": [],
                "outputs": { "type": { "response": { "ok": "none", "error": "int128" } } }
            },
            { "name": "f14",
                "access": "private",
                "args": [],
                "outputs": { "type": { "response": { "ok": "int128", "error": "int128" } } }
            },
            { "name": "f15",
                "access": "private",
                "args": [],
                "outputs": { "type": { "list": { "type": "int128", "length": 3 } } }
            },
            { "name": "f16",
                "access": "private",
                "args": [],
                "outputs": {
                  "type": { "list": {
                      "type": { "list": {
                            "type": { "list": { "type": "int128", "length": 1 } },
                            "length": 1 }
                              },
                      "length": 2 }
                          }
                }
            },
            { "name": "pub-f01",
                "access": "public",
                "args": [],
                "outputs": { "type": { "response": { "ok": "int128", "error": "none" } } }
            },
            { "name": "pub-f02",
                "access": "public",
                "args": [],
                "outputs": { "type": { "response": { "ok": "bool", "error": "none" } } }
            },
            { "name": "pub-f03",
                "access": "public",
                "args": [],
                "outputs": { "type": { "response": { "ok": "none", "error": "bool" } } }
            },
            { "name": "pub-f04",
                "access": "public",
                "args": [],
                "outputs": { "type": { "response": { "ok": "int128", "error": "int128" } } }
            },
            { "name": "pub-f05",
                "access": "public",
                "args": [{ "name": "a1", "type": "int128" }],
                "outputs": { "type": { "response": { "ok": "bool", "error": "none" } } }
            },
            { "name": "ro-f01",
                "access": "read_only",
                "args": [],
                "outputs": { "type": "int128" }
            },
            { "name": "ro-f02",
                "access": "read_only",
                "args": [{ "name": "a1", "type": "int128" }],
                "outputs": { "type": "int128" }
            }
        ],
        "maps": [
            {
                "name": "map1",
                "key": {
                    "tuple": [{
                        "name": "name",
                        "type": "int128"
                    }]
                },
                "value": {
                    "tuple": [{
                        "name": "owner",
                        "type": "principal"
                    }]
                }
            },
            {
                "name": "map2",
                "key": {
                    "tuple": [{
                        "name": "k-name-1",
                        "type": "bool"
                    }]
                },
                "value": {
                    "tuple": [{
                        "name": "v-name-1",
                        "type": {
                            "buffer": { "length": 33 }
                        }
                    }]
                }
            },
            {
                "name": "map3",
                "key": {
                    "tuple": [{
                        "name": "k-name-2",
                        "type": "bool"
                    }]
                },
                "value": {
                    "tuple": [{
                        "name": "v-name-2",
                        "type": {
                            "tuple": [
                                {
                                    "name": "n1",
                                    "type": "int128"
                                },
                                {
                                    "name": "n2",
                                    "type": "bool"
                                }
                            ] 
                        }
                    }]
                }
            }
        ],
        "variables": [
            { "name": "var1", "access": "constant", "type": "principal" },
            { "name": "var2", "access": "constant", "type": "bool" },
            { "name": "var3", "access": "constant", "type": "int128" },
            { "name": "d-var1", "access": "variable", "type": "bool" },
            { "name": "d-var2", "access": "variable", "type": "int128" },
            { "name": "d-var3", "access": "variable", "type": { "buffer": { "length": 5 } } }
        ],
        "fungible_tokens": [],
        "non_fungible_tokens": [],
        "epoch": "Epoch21",
        "clarity_version": "Clarity3"
    }"#).unwrap();

    eprintln!("{}", test_contract_json_str);

    assert_json_eq!(test_contract_json, test_contract_json_expected);
}

#[apply(test_clarity_versions)]
fn test_names_tokens_contracts(#[case] version: ClarityVersion, #[case] epoch: StacksEpochId) {
    let tokens_contract_id = QualifiedContractIdentifier::local("tokens").unwrap();
    let names_contract_id = QualifiedContractIdentifier::local("names").unwrap();

    let mut tokens_contract = parse(&tokens_contract_id, SIMPLE_TOKENS, version, epoch).unwrap();
    let mut names_contract = parse(&names_contract_id, SIMPLE_NAMES, version, epoch).unwrap();
    let mut marf = MemoryBackingStore::new();
    let mut db = marf.as_analysis_db();

    db.execute(|db| {
        type_check(&tokens_contract_id, &mut tokens_contract, db, true)?;
        type_check(&names_contract_id, &mut names_contract, db, true)
    })
    .unwrap();
}

#[apply(test_clarity_versions)]
fn test_names_tokens_contracts_bad(#[case] version: ClarityVersion, #[case] epoch: StacksEpochId) {
    let broken_public = "
         (define-public (broken-cross-contract (name-hash (buff 20)) (name-price uint))
           (if (is-ok (contract-call? .tokens token-transfer
                 burn-address true))
               (begin (map-insert preorder-map
                 (tuple (name-hash name-hash))
                 (tuple (paid name-price)
                        (buyer tx-sender))) (ok u1))
               (err 1)))";

    let names_contract = format!(
        "{}
                 {}",
        SIMPLE_NAMES, broken_public
    );

    let tokens_contract_id = QualifiedContractIdentifier::local("tokens").unwrap();
    let names_contract_id = QualifiedContractIdentifier::local("names").unwrap();

    let mut tokens_contract = parse(&tokens_contract_id, SIMPLE_TOKENS, version, epoch).unwrap();
    let mut names_contract = parse(&names_contract_id, &names_contract, version, epoch).unwrap();
    let mut marf = MemoryBackingStore::new();
    let mut db = marf.as_analysis_db();

    db.execute(|db| {
        db.test_insert_contract_hash(&tokens_contract_id);
        type_check(&tokens_contract_id, &mut tokens_contract, db, true)
    })
    .unwrap();

    let err = db
        .execute(|db| type_check(&names_contract_id, &mut names_contract, db, true))
        .unwrap_err();
    assert!(matches!(err.err, CheckErrors::TypeError(_, _)));
}

#[test]
fn test_bad_map_usage() {
    let bad_fetch = "(define-map tokens { account: principal } { balance: int })
         (define-private (my-get-token-balance (account int))
            (let ((balance
                  (get balance (map-get? tokens (tuple (account account))))))
              balance))";
    let bad_delete = "(define-map tokens { account: principal } { balance: int })
         (define-private (del-balance (account principal))
            (map-delete tokens (tuple (balance account))))";
    let bad_set_1 = "(define-map tokens { account: principal } { balance: int })
         (define-private (set-balance (account principal))
            (map-set tokens (tuple (account account)) (tuple (balance \"foo\"))))";
    let bad_set_2 = "(define-map tokens { account: principal } { balance: int })
         (define-private (set-balance (account principal))
            (map-set tokens (tuple (account \"abc\")) (tuple (balance 0))))";
    let bad_insert_1 = "(define-map tokens { account: principal } { balance: int })
         (define-private (set-balance (account principal))
            (map-insert tokens (tuple (account account)) (tuple (balance \"foo\"))))";
    let bad_insert_2 = "(define-map tokens { account: principal } { balance: int })
         (define-private (set-balance (account principal))
            (map-insert tokens (tuple (account \"abc\")) (tuple (balance 0))))";

    let unhandled_option = "(define-map tokens { account: principal } { balance: int })
         (define-private (plus-balance (account principal))
           (+ (get balance (map-get? tokens (tuple (account account)))) 1))";

    let tests = [
        bad_fetch,
        bad_delete,
        bad_set_1,
        bad_set_2,
        bad_insert_1,
        bad_insert_2,
    ];

    for contract in tests.iter() {
        let err = mem_type_check(contract).unwrap_err();
        assert!(matches!(err.err, CheckErrors::TypeError(_, _)));
    }

    assert!(matches!(
        mem_type_check(unhandled_option).unwrap_err().err,
        CheckErrors::UnionTypeError(_, _)
    ));
}

#[apply(test_clarity_versions)]
fn test_same_function_name(#[case] version: ClarityVersion, #[case] epoch: StacksEpochId) {
    let ca_id = QualifiedContractIdentifier::local("contract-a").unwrap();
    let cb_id = QualifiedContractIdentifier::local("contract-b").unwrap();

    let contract_b = "(define-read-only (foo-function (a int)) (+ a 1))";

    let contract_a = "(define-read-only (foo-function (a int))
           (contract-call? .contract-b foo-function a))";

    let mut ca = parse(&ca_id, contract_a, version, epoch).unwrap();
    let mut cb = parse(&cb_id, contract_b, version, epoch).unwrap();
    let mut marf = MemoryBackingStore::new();
    let mut db = marf.as_analysis_db();

    db.execute(|db| {
        type_check(&cb_id, &mut cb, db, true)?;
        type_check(&ca_id, &mut ca, db, true)
    })
    .unwrap();
}

#[test]
fn test_expects() {
    let okay = "(define-map tokens { id: int } { balance: int })
         (define-private (my-get-token-balance)
            (let ((balance (unwrap!
                              (get balance (map-get? tokens (tuple (id 0))))
                              0)))
              (+ 0 balance)))
         (define-private (my-get-token-balance-2)
            (let ((balance
                    (get balance (unwrap! (map-get? tokens (tuple (id 0))) 0))
                              ))
              (+ 0 balance)))
          (define-private (my-get-token-balance-3)
             (let ((balance
                     (unwrap! (get balance (map-get? tokens (tuple (id 0))))
                              (err false))))
               (ok balance)))
          (define-private (my-get-token-balance-4)
             (unwrap! (my-get-token-balance-3) 0))

          (define-private (t-1)
             (err 3))
          (define-private (my-get-token-balance-5)
             (unwrap-err! (t-1) 0))

          (+ (my-get-token-balance) (my-get-token-balance-2) (my-get-token-balance-5))";

    let bad_return_types_tests = [
        "(define-map tokens { id: int } { balance: int })
         (define-private (my-get-token-balance)
            (let ((balance (unwrap!
                              (get balance (map-get? tokens (tuple (id 0))))
                              false)))
              (+ 0 balance)))",
        "(define-map tokens { id: int } { balance: int })
         (define-private (my-get-token-balance)
            (let ((balance (unwrap!
                              (get balance (map-get? tokens (tuple (id 0))))
                              (err 1))))
              (err false)))",
    ];

    let bad_default_type = "(define-map tokens { id: int } { balance: int })
         (default-to false (get balance (map-get? tokens (tuple (id 0)))))";

    let notype_response_type = "
         (define-private (t1) (ok 3))
         (define-private (t2) (unwrap-err! (t1) 0))
    ";

    let notype_response_type_2 = "
         (define-private (t1) (err 3))
         (define-private (t2) (unwrap! (t1) 0))
    ";

    mem_type_check(okay).unwrap();

    for unmatched_return_types in bad_return_types_tests.iter() {
        let err = mem_type_check(unmatched_return_types).unwrap_err();
        eprintln!("unmatched_return_types returned check error: {}", err);
        assert!(matches!(err.err, CheckErrors::ReturnTypesMustMatch(_, _)));
    }

    let err = mem_type_check(bad_default_type).unwrap_err();
    eprintln!("bad_default_types returned check error: {}", err);
    assert!(matches!(err.err, CheckErrors::DefaultTypesMustMatch(_, _)));

    let err = mem_type_check(notype_response_type).unwrap_err();
    eprintln!("notype_response_type returned check error: {}", err);
    assert!(matches!(
        err.err,
        CheckErrors::CouldNotDetermineResponseErrType
    ));

    let err = mem_type_check(notype_response_type_2).unwrap_err();
    eprintln!("notype_response_type_2 returned check error: {}", err);
    assert!(matches!(
        err.err,
        CheckErrors::CouldNotDetermineResponseOkType
    ));
}

/// Pass a trait to a trait parameter with the same type
#[test]
fn test_trait_to_trait() {
    let trait_to_trait = "(define-trait trait-1 (
        (get-1 (uint) (response uint uint))
    ))
    (define-public (wrapped-get-1 (contract <trait-1>))
        (internal-get-1 contract))
    (define-public (internal-get-1 (contract <trait-1>))
        (contract-call? contract get-1 u1))";

    mem_type_check(trait_to_trait).unwrap();
    mem_type_check_v1(trait_to_trait).unwrap();
}

/// Pass a trait to a trait parameter with a compatible trait type
#[test]
fn test_trait_to_compatible_trait() {
    let trait_to_compatible_trait = "(define-trait trait-1 (
        (echo (uint) (response uint uint))
    ))
    (define-trait trait-2 (
        (echo (uint) (response uint uint))
    ))
    (define-public (wrapped-echo (contract <trait-1>))
        (internal-echo contract))
    (define-public (internal-echo (contract <trait-2>))
        (ok true))";

    mem_type_check(trait_to_compatible_trait).unwrap();
    let err = mem_type_check_v1(trait_to_compatible_trait).unwrap_err();
    assert!(match err {
        CheckError {
            err: CheckErrors::TypeError(expected, found),
            expressions: _,
            diagnostic: _,
        } => {
            match (expected, found) {
                (
                    TypeSignature::CallableType(CallableSubtype::Trait(expected_trait)),
                    TypeSignature::CallableType(CallableSubtype::Trait(found_trait)),
                ) => {
                    assert_eq!(expected_trait.name.as_str(), "trait-2");
                    assert_eq!(found_trait.name.as_str(), "trait-1");
                    true
                }
                _ => false,
            }
        }
        _ => false,
    });
}

/// Pass a principal to a trait parameter
#[test]
fn test_bad_principal_to_trait() {
    let bad_principal_to_trait = "(define-trait trait-1 (
        (get-1 (uint) (response uint uint))
    ))
    (define-public (wrapped-get-1 (contract principal))
        (internal-get-1 contract))
    (define-public (internal-get-1 (contract <trait-1>))
        (contract-call? contract get-1 u1))";

    let err = mem_type_check(bad_principal_to_trait).unwrap_err();
    assert!(match err {
        CheckError {
            err: CheckErrors::TypeError(expected, found),
            expressions: _,
            diagnostic: _,
        } => {
            match (expected, found) {
                (
                    TypeSignature::CallableType(CallableSubtype::Trait(expected_trait)),
                    TypeSignature::PrincipalType,
                ) => {
                    assert_eq!(expected_trait.name.as_str(), "trait-1");
                    true
                }
                _ => false,
            }
        }
        _ => false,
    });
    let err = mem_type_check_v1(bad_principal_to_trait).unwrap_err();
    assert!(match err {
        CheckError {
            err: CheckErrors::TypeError(expected, found),
            expressions: _,
            diagnostic: _,
        } => {
            match (expected, found) {
                (
                    TypeSignature::CallableType(CallableSubtype::Trait(expected_trait)),
                    TypeSignature::PrincipalType,
                ) => {
                    assert_eq!(expected_trait.name.as_str(), "trait-1");
                    true
                }
                _ => false,
            }
        }
        _ => false,
    });
}

/// Pass a trait to a trait parameter which is not compatible
#[test]
fn test_bad_other_trait() {
    let bad_other_trait = "(define-trait trait-1 (
        (get-1 (uint) (response uint uint))
    ))
    (define-trait trait-2 (
        (get-2 (uint) (response uint uint))
    ))
    (define-public (wrapped-get-2 (contract <trait-1>))
        (internal-get-2 contract))
    (define-public (internal-get-2 (contract <trait-2>))
        (contract-call? contract get-2 u1))";

    let err = mem_type_check(bad_other_trait).unwrap_err();
    assert!(match err {
        CheckError {
            err: CheckErrors::IncompatibleTrait(expected, actual),
            expressions: _,
            diagnostic: _,
        } => {
            assert_eq!(expected.name.as_str(), "trait-2");
            assert_eq!(actual.name.as_str(), "trait-1");
            true
        }
        _ => false,
    });
    let err = mem_type_check_v1(bad_other_trait).unwrap_err();
    assert!(match err {
        CheckError {
            err: CheckErrors::TypeError(expected, found),
            expressions: _,
            diagnostic: _,
        } => {
            match (expected, found) {
                (
                    TypeSignature::CallableType(CallableSubtype::Trait(expected_trait)),
                    TypeSignature::CallableType(CallableSubtype::Trait(found_trait)),
                ) => {
                    assert_eq!(expected_trait.name.as_str(), "trait-2");
                    assert_eq!(found_trait.name.as_str(), "trait-1");
                    true
                }
                _ => false,
            }
        }
        _ => false,
    });
}

/// Pass a trait embedded in a compound type
#[test]
fn test_embedded_trait() {
    let embedded_trait = "(define-trait trait-12 (
        (get-1 (uint) (response uint uint))
        (get-2 (uint) (response uint uint))
    ))
    (define-public (wrapped-opt-get-1 (contract <trait-12>))
        (internal-get-1 (some contract)))
    (define-public (internal-get-1 (opt-contract (optional <trait-12>)))
        (match opt-contract
            contract (contract-call? contract get-1 u1)
            (err u1)
        )
    )";

    mem_type_check(embedded_trait).unwrap();
    let err = mem_type_check_v1(embedded_trait).unwrap_err();
    assert!(match err {
        CheckError {
            err: CheckErrors::TraitReferenceUnknown(name),
            expressions: _,
            diagnostic: _,
        } => {
            assert_eq!(name.as_str(), "contract");
            true
        }
        _ => false,
    });
}

/// Pass a trait embedded in a compound type to a parameter with a compatible
/// trait type
#[test]
fn test_embedded_trait_compatible() {
    let embedded_trait_compatible = "(define-trait trait-1 (
        (get-1 (uint) (response uint uint))
    ))
    (define-trait trait-12 (
        (get-1 (uint) (response uint uint))
        (get-2 (uint) (response uint uint))
    ))
    (define-public (wrapped-opt-get-1 (contract <trait-12>))
        (internal-get-1 (some contract)))
    (define-public (internal-get-1 (opt-contract (optional <trait-1>)))
        (match opt-contract
            contract (contract-call? contract get-1 u1)
            (err u1)
        )
    )";

    mem_type_check(embedded_trait_compatible).unwrap();
    let err = mem_type_check_v1(embedded_trait_compatible).unwrap_err();
    assert!(match err {
        CheckError {
            err: CheckErrors::TraitReferenceUnknown(name),
            expressions: _,
            diagnostic: _,
        } => {
            assert_eq!(name.as_str(), "contract");
            true
        }
        _ => false,
    });
}

/// Pass a trait embedded in a compound type to a parameter with an
/// incompatible trait type
#[test]
fn test_bad_embedded_trait() {
    let bad_embedded_trait = "(define-trait trait-1 (
        (get-1 (uint) (response uint uint))
    ))
    (define-trait trait-12 (
        (get-1 (uint) (response uint uint))
        (get-2 (uint) (response uint uint))
    ))
    (define-public (wrapped-opt-get-1 (contract <trait-1>))
        ;; Passing (optional <trait-1>) as an (optional <trait-12>) should be an error
        (wrapped-get-1 (some contract)))
    (define-public (wrapped-get-1 (opt-contract (optional <trait-12>)))
        (internal-get-1 opt-contract)
    )
    (define-public (internal-get-1 (opt-contract (optional <trait-12>)))
        (match opt-contract
            contract (contract-call? contract get-1 u1)
            (err u1)
        )
    )";

    let err = mem_type_check(bad_embedded_trait).unwrap_err();
    assert!(match err {
        CheckError {
            err: CheckErrors::IncompatibleTrait(expected, actual),
            expressions: _,
            diagnostic: _,
        } => {
            assert_eq!(expected.name.as_str(), "trait-12");
            assert_eq!(actual.name.as_str(), "trait-1");
            true
        }
        _ => false,
    });
    let err = mem_type_check_v1(bad_embedded_trait).unwrap_err();
    assert!(match err {
        CheckError {
            err: CheckErrors::TraitReferenceUnknown(name),
            expressions: _,
            diagnostic: _,
        } => {
            assert_eq!(name.as_str(), "contract");
            true
        }
        _ => false,
    });
}

/// Bind a trait in a let expression
#[test]
fn test_let_trait() {
    let let_trait = "(define-trait trait-1 (
        (echo (uint) (response uint uint))
    ))
    (define-public (let-echo (t <trait-1>))
        (let ((t1 t))
            (contract-call? t1 echo u42)
        )
    )";

    mem_type_check(let_trait).unwrap();
    let err = mem_type_check_v1(let_trait).unwrap_err();
    assert!(match err {
        CheckError {
            err: CheckErrors::TraitReferenceUnknown(name),
            expressions: _,
            diagnostic: _,
        } => {
            assert_eq!(name.as_str(), "t1");
            true
        }
        _ => false,
    });
}

/// Bind a trait in transitively in multiple let expressions
#[test]
fn test_let3_trait() {
    let let3_trait = "(define-trait trait-1 (
        (echo (uint) (response uint uint))
    ))
    (define-public (let-echo (t <trait-1>))
        (let ((t1 t))
            (let ((t2 t1))
                (let ((t3 t2))
                    (contract-call? t3 echo u42)
                )
            )
        )
    )";

    mem_type_check(let3_trait).unwrap();
    let err = mem_type_check_v1(let3_trait).unwrap_err();
    assert!(match err {
        CheckError {
            err: CheckErrors::TraitReferenceUnknown(name),
            expressions: _,
            diagnostic: _,
        } => {
            assert_eq!(name.as_str(), "t3");
            true
        }
        _ => false,
    });
}

/// Bind a trait transitively in multiple let expressions with compound types
#[test]
fn test_let3_compound_trait() {
    let let3_compound_trait = "(define-trait trait-1 (
        (echo (uint) (response uint uint))
    ))
    (define-private (foo (a (response (optional <trait-1>) uint)))
        (ok true)
    )
    (define-public (let-echo (t <trait-1>))
        (let ((t1 t))
            (let ((t2-opt (some t1)))
                (let ((t3-res (ok t2-opt)))
                    (foo t3-res)
                )
            )
        )
    )";

    mem_type_check(let3_compound_trait).unwrap();
    mem_type_check_v1(let3_compound_trait).unwrap();
}

/// Bind a trait transitively in multiple let expressions with compound types,
/// then unwrap it and use it to call the contract.
#[test]
fn test_let3_compound_trait_call() {
    let let3_compound_trait_call = "(define-trait trait-1 (
        (echo (uint) (response uint uint))
    ))
    (define-private (foo (a (response (optional <trait-1>) uint)))
        (ok true)
    )
    (define-public (let-echo (t <trait-1>))
        (let ((t1 t))
            (let ((t2-opt (some t1)))
                (let ((t3-res (ok t2-opt)))
                    (let ((t4 (unwrap! (unwrap! t3-res (err u1)) (err u2))))
                        (contract-call? t4 echo u23)
                    )
                )
            )
        )
    )";

    mem_type_check(let3_compound_trait_call).unwrap();
    let err = mem_type_check_v1(let3_compound_trait_call).unwrap_err();
    assert!(match err {
        CheckError {
            err: CheckErrors::TraitReferenceUnknown(name),
            expressions: _,
            diagnostic: _,
        } => {
            assert_eq!(name.as_str(), "t4");
            true
        }
        _ => false,
    });
}

/// Check for compatibility between traits where the function parameter type
/// differs
#[test]
fn test_trait_args_differ() {
    let trait_args_differ = "(define-trait trait-1 (
        (echo (uint) (response uint uint))
    ))
    (define-trait trait-2 (
        (echo (int) (response uint uint))
    ))
    (define-public (wrapped-echo (contract <trait-1>))
        (internal-echo contract))
    (define-public (internal-echo (contract <trait-2>))
        (ok true))";

    let err = mem_type_check(trait_args_differ).unwrap_err();
    assert!(match err {
        CheckError {
            err: CheckErrors::IncompatibleTrait(expected, actual),
            expressions: _,
            diagnostic: _,
        } => {
            assert_eq!(expected.name.as_str(), "trait-2");
            assert_eq!(actual.name.as_str(), "trait-1");
            true
        }
        _ => false,
    });
    let err = mem_type_check_v1(trait_args_differ).unwrap_err();
    assert!(match err {
        CheckError {
            err: CheckErrors::TypeError(expected, found),
            expressions: _,
            diagnostic: _,
        } => {
            match (expected, found) {
                (
                    TypeSignature::CallableType(CallableSubtype::Trait(expected_trait)),
                    TypeSignature::CallableType(CallableSubtype::Trait(found_trait)),
                ) => {
                    assert_eq!(expected_trait.name.as_str(), "trait-2");
                    assert_eq!(found_trait.name.as_str(), "trait-1");
                    true
                }
                _ => false,
            }
        }
        _ => false,
    });
}

/// Pass a trait to a trait parameter with an compatible trait type
#[test]
fn test_trait_arg_counts_differ1() {
    let trait_to_compatible_trait = "(define-trait trait-1 (
        (echo (uint) (response uint uint))
    ))
    (define-trait trait-2 (
        (echo (uint uint) (response uint uint))
    ))
    (define-public (wrapped-echo (contract <trait-1>))
        (internal-echo contract))
    (define-public (internal-echo (contract <trait-2>))
        (ok true))";

    let err = mem_type_check(trait_to_compatible_trait).unwrap_err();
    assert!(match err {
        CheckError {
            err: CheckErrors::IncompatibleTrait(expected, found),
            expressions: _,
            diagnostic: _,
        } => {
            assert_eq!(expected.name.as_str(), "trait-2");
            assert_eq!(found.name.as_str(), "trait-1");
            true
        }
        _ => false,
    });
    let err = mem_type_check_v1(trait_to_compatible_trait).unwrap_err();
    assert!(match err {
        CheckError {
            err: CheckErrors::TypeError(expected, found),
            expressions: _,
            diagnostic: _,
        } => {
            match (expected, found) {
                (
                    TypeSignature::CallableType(CallableSubtype::Trait(expected_trait)),
                    TypeSignature::CallableType(CallableSubtype::Trait(found_trait)),
                ) => {
                    assert_eq!(expected_trait.name.as_str(), "trait-2");
                    assert_eq!(found_trait.name.as_str(), "trait-1");
                    true
                }
                _ => false,
            }
        }
        _ => false,
    });
}

/// Pass a trait to a trait parameter with an compatible trait type
#[test]
fn test_trait_arg_counts_differ2() {
    let trait_to_compatible_trait = "(define-trait trait-1 (
        (echo (uint uint) (response uint uint))
    ))
    (define-trait trait-2 (
        (echo (uint) (response uint uint))
    ))
    (define-public (wrapped-echo (contract <trait-1>))
        (internal-echo contract))
    (define-public (internal-echo (contract <trait-2>))
        (ok true))";

    let err = mem_type_check(trait_to_compatible_trait).unwrap_err();
    assert!(match err {
        CheckError {
            err: CheckErrors::IncompatibleTrait(expected, found),
            expressions: _,
            diagnostic: _,
        } => {
            assert_eq!(expected.name.as_str(), "trait-2");
            assert_eq!(found.name.as_str(), "trait-1");
            true
        }
        _ => false,
    });
    let err = mem_type_check_v1(trait_to_compatible_trait).unwrap_err();
    assert!(match err {
        CheckError {
            err: CheckErrors::TypeError(expected, found),
            expressions: _,
            diagnostic: _,
        } => {
            match (expected, found) {
                (
                    TypeSignature::CallableType(CallableSubtype::Trait(expected_trait)),
                    TypeSignature::CallableType(CallableSubtype::Trait(found_trait)),
                ) => {
                    assert_eq!(expected_trait.name.as_str(), "trait-2");
                    assert_eq!(found_trait.name.as_str(), "trait-1");
                    true
                }
                _ => false,
            }
        }
        _ => false,
    });
}

/// Check for compatibility between traits where the response types differ
#[test]
fn test_trait_ret_ty_differ() {
    let trait_ret_ty_differ = "(define-trait trait-1 (
        (echo (uint) (response int uint))
    ))
    (define-trait trait-2 (
        (echo (uint) (response uint uint))
    ))
    (define-public (wrapped-echo (contract <trait-1>))
        (internal-echo contract))
    (define-public (internal-echo (contract <trait-2>))
        (contract-call? contract echo u1))";

    let err = mem_type_check(trait_ret_ty_differ).unwrap_err();
    assert!(match err {
        CheckError {
            err: CheckErrors::IncompatibleTrait(expected, actual),
            expressions: _,
            diagnostic: _,
        } => {
            assert_eq!(expected.name.as_str(), "trait-2");
            assert_eq!(actual.name.as_str(), "trait-1");
            true
        }
        _ => false,
    });
    let err = mem_type_check_v1(trait_ret_ty_differ).unwrap_err();
    assert!(match err {
        CheckError {
            err: CheckErrors::TypeError(expected, found),
            expressions: _,
            diagnostic: _,
        } => {
            match (expected, found) {
                (
                    TypeSignature::CallableType(CallableSubtype::Trait(expected_trait)),
                    TypeSignature::CallableType(CallableSubtype::Trait(found_trait)),
                ) => {
                    assert_eq!(expected_trait.name.as_str(), "trait-2");
                    assert_eq!(found_trait.name.as_str(), "trait-1");
                    true
                }
                _ => false,
            }
        }
        _ => false,
    });
}

/// Check for compatibility of traits where a function parameter has a
/// compatible type
#[test]
fn test_trait_with_compatible_trait_arg() {
    let trait_with_compatible_trait_arg = "(define-trait trait-1 (
        (echo (uint) (response uint uint))
    ))
    (define-trait trait-2 (
        (echo (uint) (response uint uint))
    ))
    (define-trait trait-a (
        (echo (<trait-1>) (response uint uint))
    ))
    (define-trait trait-b (
        (echo (<trait-2>) (response uint uint))
    ))
    (define-public (wrapped-echo (contract <trait-a>))
        (internal-echo contract))
    (define-public (internal-echo (contract <trait-b>) (callee <trait-2>))
        (contract-call? contract echo callee))";

    mem_type_check(trait_with_compatible_trait_arg).unwrap();
    let err = mem_type_check_v1(trait_with_compatible_trait_arg).unwrap_err();
    assert!(match err {
        CheckError {
            err: CheckErrors::TypeError(expected, found),
            expressions: _,
            diagnostic: _,
        } => {
            match (expected, found) {
                (
                    TypeSignature::CallableType(CallableSubtype::Trait(expected_trait)),
                    TypeSignature::CallableType(CallableSubtype::Trait(found_trait)),
                ) => {
                    assert_eq!(expected_trait.name.as_str(), "trait-b");
                    assert_eq!(found_trait.name.as_str(), "trait-a");
                    true
                }
                _ => false,
            }
        }
        _ => false,
    });
}

/// Check for compatibility of traits where a function parameter has an
/// incompatible trait type
#[test]
fn test_trait_with_bad_trait_arg() {
    let trait_with_bad_trait_arg = "(define-trait trait-1 (
        (echo (uint) (response uint uint))
    ))
    (define-trait trait-2 (
        (echo (uint) (response int uint))
    ))
    (define-trait trait-a (
        (echo (<trait-1>) (response uint uint))
    ))
    (define-trait trait-b (
        (echo (<trait-2>) (response uint uint))
    ))
    (define-public (wrapped-echo (contract <trait-a>))
        (internal-echo contract))
    (define-public (internal-echo (contract <trait-b>) (callee <trait-2>))
        (contract-call? contract echo callee))";

    let err = mem_type_check(trait_with_bad_trait_arg).unwrap_err();
    assert!(match err {
        CheckError {
            err: CheckErrors::IncompatibleTrait(expected, actual),
            expressions: _,
            diagnostic: _,
        } => {
            assert_eq!(expected.name.as_str(), "trait-b");
            assert_eq!(actual.name.as_str(), "trait-a");
            true
        }
        _ => false,
    });
    let err = mem_type_check_v1(trait_with_bad_trait_arg).unwrap_err();
    assert!(match err {
        CheckError {
            err: CheckErrors::TypeError(expected, found),
            expressions: _,
            diagnostic: _,
        } => {
            match (expected, found) {
                (
                    TypeSignature::CallableType(CallableSubtype::Trait(expected_trait)),
                    TypeSignature::CallableType(CallableSubtype::Trait(found_trait)),
                ) => {
                    assert_eq!(expected_trait.name.as_str(), "trait-b");
                    assert_eq!(found_trait.name.as_str(), "trait-a");
                    true
                }
                _ => false,
            }
        }
        _ => false,
    });
}

/// Check for compatibility of traits where a function parameter from one trait
/// has a trait type which is a superset of the corresponding trait
#[test]
fn test_trait_with_superset_trait_arg() {
    let trait_with_superset_trait_arg = "(define-trait trait-1 (
        (echo (uint) (response uint uint))
    ))
    (define-trait trait-2 (
        (echo (uint) (response uint uint))
        (foo (uint) (response uint uint))
    ))
    (define-trait trait-a (
        (echo (<trait-1>) (response uint uint))
    ))
    (define-trait trait-b (
        (echo (<trait-2>) (response uint uint))
    ))
    (define-public (wrapped-echo (contract <trait-a>) (callee <trait-2>))
        (internal-echo contract callee))
    (define-public (internal-echo (contract <trait-b>) (callee <trait-2>))
        (contract-call? contract echo callee))";

    let err = mem_type_check(trait_with_superset_trait_arg).unwrap_err();
    assert!(match err {
        CheckError {
            err: CheckErrors::IncompatibleTrait(expected, actual),
            expressions: _,
            diagnostic: _,
        } => {
            assert_eq!(expected.name.as_str(), "trait-b");
            assert_eq!(actual.name.as_str(), "trait-a");
            true
        }
        _ => false,
    });
    let err = mem_type_check_v1(trait_with_superset_trait_arg).unwrap_err();
    assert!(match err {
        CheckError {
            err: CheckErrors::TypeError(expected, found),
            expressions: _,
            diagnostic: _,
        } => {
            match (expected, found) {
                (
                    TypeSignature::CallableType(CallableSubtype::Trait(expected_trait)),
                    TypeSignature::CallableType(CallableSubtype::Trait(found_trait)),
                ) => {
                    assert_eq!(expected_trait.name.as_str(), "trait-b");
                    assert_eq!(found_trait.name.as_str(), "trait-a");
                    true
                }
                _ => false,
            }
        }
        _ => false,
    });
}

/// Check for compatibility of traits where a function parameter from one trait
/// has a trait type which is a subset of the corresponding trait
#[test]
fn test_trait_with_subset_trait_arg() {
    let trait_with_subset_trait_arg = "(define-trait trait-1 (
        (echo (uint) (response uint uint))
    ))
    (define-trait trait-2 (
        (echo (uint) (response uint uint))
        (foo (uint) (response uint uint))
    ))
    (define-trait trait-a (
        (echo (<trait-1>) (response uint uint))
    ))
    (define-trait trait-b (
        (echo (<trait-2>) (response uint uint))
    ))
    (define-public (wrapped-echo (contract <trait-b>) (callee <trait-1>))
        (internal-echo contract callee))
    (define-public (internal-echo (contract <trait-a>) (callee <trait-1>))
        (contract-call? contract echo callee))";

    mem_type_check(trait_with_subset_trait_arg).unwrap();
    let err = mem_type_check_v1(trait_with_subset_trait_arg).unwrap_err();
    assert!(match err {
        CheckError {
            err: CheckErrors::TypeError(expected, found),
            expressions: _,
            diagnostic: _,
        } => {
            match (expected, found) {
                (
                    TypeSignature::CallableType(CallableSubtype::Trait(expected_trait)),
                    TypeSignature::CallableType(CallableSubtype::Trait(found_trait)),
                ) => {
                    assert_eq!(expected_trait.name.as_str(), "trait-a");
                    assert_eq!(found_trait.name.as_str(), "trait-b");
                    true
                }
                _ => false,
            }
        }
        _ => false,
    });
}

/// Define a trait with a duplicated method name
#[test]
fn test_trait_with_duplicate_method() {
    let trait_with_duplicate_method = "(define-trait double-method (
        (foo (uint) (response uint uint))
        (foo (bool) (response bool bool))
      ))";

    let err = mem_type_check(trait_with_duplicate_method).unwrap_err();
    assert!(match err {
        CheckError {
            err: CheckErrors::DefineTraitDuplicateMethod(method_name),
            expressions: _,
            diagnostic: _,
        } => {
            assert_eq!(method_name.as_str(), "foo");
            true
        }
        _ => false,
    });
    mem_type_check_v1(trait_with_duplicate_method).unwrap();
}

/// Pass a trait to a subtrait, then back to the original trait
#[test]
fn test_trait_to_subtrait_and_back() {
    let trait_to_subtrait_and_back = "(define-trait trait-1 (
        (echo (uint) (response uint uint))
    ))
    (define-trait trait-2 (
        (echo (uint) (response uint uint))
        (foo (uint) (response uint uint))
    ))
    (define-private (foo-0 (impl-contract <trait-2>))
        (foo-1 impl-contract))
 
    (define-private (foo-1 (impl-contract <trait-1>))
        (foo-2 impl-contract))
    
    (define-private (foo-2 (impl-contract <trait-2>))
        true)";

    let err = mem_type_check(trait_to_subtrait_and_back).unwrap_err();
    assert!(match err {
        CheckError {
            err: CheckErrors::IncompatibleTrait(expected, actual),
            expressions: _,
            diagnostic: _,
        } => {
            assert_eq!(expected.name.as_str(), "trait-2");
            assert_eq!(actual.name.as_str(), "trait-1");
            true
        }
        _ => false,
    });
    let err = mem_type_check_v1(trait_to_subtrait_and_back).unwrap_err();
    assert!(match err {
        CheckError {
            err: CheckErrors::TypeError(expected, found),
            expressions: _,
            diagnostic: _,
        } => {
            match (expected, found) {
                (
                    TypeSignature::CallableType(CallableSubtype::Trait(expected_trait)),
                    TypeSignature::CallableType(CallableSubtype::Trait(found_trait)),
                ) => {
                    assert_eq!(expected_trait.name.as_str(), "trait-2");
                    assert_eq!(found_trait.name.as_str(), "trait-1");
                    true
                }
                _ => false,
            }
        }
        _ => false,
    });
}

/// Use `map` on a list of traits
#[test]
fn test_trait_list_to_map() {
    let trait_list_to_map = "(define-trait token-trait (
        (echo (uint) (response uint uint))
    ))
    (define-public (send-many (data (list 10 {amount: uint, sender: principal, recipient: principal})) (token <token-trait>))
        (ok (map my-iter data (list token token token token token token token token token token)))
    )
    (define-private (my-iter (data {amount: uint, sender: principal, recipient: principal}) (token <token-trait>))
        (contract-call? token echo u5)
    )";

    mem_type_check(trait_list_to_map).unwrap();
    mem_type_check_v1(trait_list_to_map).unwrap();
}

/// If branches with incompatible trait types
#[test]
fn test_if_branches_with_incompatible_trait_types() {
    let if_branches_with_incompatible_trait_types = "(define-trait trait-1 (
        (echo (uint) (response uint uint))
    ))
    (define-trait trait-2 (
        (foo (uint) (response uint uint))
    ))
    (define-public (foo (contract-1 <trait-1>) (contract-2 <trait-2>))
        (let ((to-invoke (if (> 1 2) contract-1 contract-2)))
            (contract-call? to-invoke method)
        )
    )";
    let err = mem_type_check(if_branches_with_incompatible_trait_types).unwrap_err();
    assert!(match err {
        CheckError {
            err: CheckErrors::IfArmsMustMatch(type1, type2),
            expressions: _,
            diagnostic: _,
        } => {
            match (type1, type2) {
                (
                    TypeSignature::CallableType(CallableSubtype::Trait(trait1)),
                    TypeSignature::CallableType(CallableSubtype::Trait(trait2)),
                ) => {
                    assert_eq!(trait1.name.as_str(), "trait-1");
                    assert_eq!(trait2.name.as_str(), "trait-2");
                    true
                }
                _ => false,
            }
        }
        _ => false,
    });
    let err = mem_type_check_v1(if_branches_with_incompatible_trait_types).unwrap_err();
    assert!(match err {
        CheckError {
            err: CheckErrors::IfArmsMustMatch(type1, type2),
            expressions: _,
            diagnostic: _,
        } => {
            match (type1, type2) {
                (
                    TypeSignature::CallableType(CallableSubtype::Trait(trait1)),
                    TypeSignature::CallableType(CallableSubtype::Trait(trait2)),
                ) => {
                    assert_eq!(trait1.name.as_str(), "trait-1");
                    assert_eq!(trait2.name.as_str(), "trait-2");
                    true
                }
                _ => false,
            }
        }
        _ => false,
    });
}

/// If branches with compatible trait types
#[test]
fn test_if_branches_with_compatible_trait_types() {
    let if_branches_with_compatible_trait_types = "(define-trait trait-1 (
            (echo (uint) (response uint uint))
        ))
        (define-trait trait-2 (
            (echo (uint) (response uint uint))
            (foo (uint) (response uint uint))
        ))
        (define-public (foo (contract-1 <trait-1>) (contract-2 <trait-2>))
            (let ((to-invoke (if (> 1 2) contract-1 contract-2)))
                (contract-call? to-invoke method)
            )
        )";

    let err = mem_type_check(if_branches_with_compatible_trait_types).unwrap_err();
    assert!(match err {
        CheckError {
            err: CheckErrors::IfArmsMustMatch(type1, type2),
            expressions: _,
            diagnostic: _,
        } => {
            match (type1, type2) {
                (
                    TypeSignature::CallableType(CallableSubtype::Trait(trait1)),
                    TypeSignature::CallableType(CallableSubtype::Trait(trait2)),
                ) => {
                    assert_eq!(trait1.name.as_str(), "trait-1");
                    assert_eq!(trait2.name.as_str(), "trait-2");
                    true
                }
                _ => false,
            }
        }
        _ => false,
    });
    let err = mem_type_check_v1(if_branches_with_compatible_trait_types).unwrap_err();
    assert!(match err {
        CheckError {
            err: CheckErrors::IfArmsMustMatch(type1, type2),
            expressions: _,
            diagnostic: _,
        } => {
            match (type1, type2) {
                (
                    TypeSignature::CallableType(CallableSubtype::Trait(trait1)),
                    TypeSignature::CallableType(CallableSubtype::Trait(trait2)),
                ) => {
                    assert_eq!(trait1.name.as_str(), "trait-1");
                    assert_eq!(trait2.name.as_str(), "trait-2");
                    true
                }
                _ => false,
            }
        }
        _ => false,
    });
}

/// Based on issue #3215 from sskeirik
#[apply(test_epoch21_clarity_versions)]
fn test_traits_multi_contract(#[case] version: ClarityVersion) {
    let epoch = StacksEpochId::latest();

    let trait_contract_src = "(define-trait a (
        (do-it () (response bool bool))
    ))";
    let use_contract_src = "(use-trait a-alias .a-trait.a)
    (define-trait a (
      (do-that () (response bool bool))
    ))
    (define-public (call-do-it (a-contract <a-alias>))
      (contract-call? a-contract do-it)
    )";

    let use_contract_id = QualifiedContractIdentifier::local("use-a-trait").unwrap();
    let trait_contract_id = QualifiedContractIdentifier::local("a-trait").unwrap();

    let mut use_contract = parse(&use_contract_id, use_contract_src, version, epoch).unwrap();
    let mut trait_contract = parse(&trait_contract_id, trait_contract_src, version, epoch).unwrap();
    let mut marf = MemoryBackingStore::new();
    let mut db = marf.as_analysis_db();

    match db.execute(|db| {
        type_check_version(
            &trait_contract_id,
            &mut trait_contract,
            db,
            true,
            StacksEpochId::Epoch21,
            version,
        )?;
        type_check_version(
            &use_contract_id,
            &mut use_contract,
            db,
            true,
            StacksEpochId::Epoch21,
            version,
        )
    }) {
        Err(CheckError {
            err: CheckErrors::TraitMethodUnknown(trait_name, function),
            expressions: _,
            diagnostic: _,
        }) if version < ClarityVersion::Clarity2 => {
            assert_eq!(trait_name.as_str(), "a");
            assert_eq!(function.as_str(), "do-it");
        }
        Ok(_) if version >= ClarityVersion::Clarity2 => (),
        res => panic!("{:?}", res),
    }
}

// Tests below are derived from https://github.com/sskeirik/clarity-trait-experiments.

fn load_versioned(
    db: &mut AnalysisDatabase,
    name: &str,
    version: ClarityVersion,
    epoch: StacksEpochId,
) -> Result<ContractAnalysis, String> {
    let source = read_to_string(format!(
        "{}/src/vm/analysis/type_checker/v2_1/tests/contracts/{}.clar",
        env!("CARGO_MANIFEST_DIR"),
        name
    ))
    .unwrap();
    let contract_id = QualifiedContractIdentifier::local(name).unwrap();
    let mut contract =
        parse(&contract_id, source.as_str(), version, epoch).map_err(|e| e.to_string())?;
    type_check_version(&contract_id, &mut contract, db, true, epoch, version)
        .map_err(|e| e.to_string())
}

fn call_versioned(
    db: &mut AnalysisDatabase,
    contract: &str,
    function: &str,
    args: &str,
    version: ClarityVersion,
    epoch: StacksEpochId,
) -> Result<ContractAnalysis, String> {
    let source = format!("(contract-call? .{} {} {})", contract, function, args);
    let contract_id = QualifiedContractIdentifier::transient();
    let mut contract =
        parse(&contract_id, source.as_str(), version, epoch).map_err(|e| e.to_string())?;
    type_check_version(&contract_id, &mut contract, db, false, epoch, version)
        .map_err(|e| e.to_string())
}

#[apply(test_clarity_versions)]
fn clarity_trait_experiments_impl(#[case] version: ClarityVersion, #[case] epoch: StacksEpochId) {
    let mut marf = MemoryBackingStore::new();
    let mut db = marf.as_analysis_db();

    let result = db.execute(|db| {
        load_versioned(db, "math-trait", version, epoch)?;
        load_versioned(db, "impl-math-trait", version, epoch)
    });
    match result {
        Ok(_) => (),
        res => panic!("expected success, got {:?}", res),
    };
}

#[apply(test_clarity_versions)]
fn clarity_trait_experiments_use(#[case] version: ClarityVersion, #[case] epoch: StacksEpochId) {
    let mut marf = MemoryBackingStore::new();
    let mut db = marf.as_analysis_db();

    let result = db.execute(|db| {
        load_versioned(db, "math-trait", version, epoch)?;
        load_versioned(db, "use-math-trait", version, epoch)
    });
    match result {
        Ok(_) => (),
        res => panic!("expected success, got {:?}", res),
    };
}

#[apply(test_clarity_versions)]
fn clarity_trait_experiments_empty_trait(
    #[case] version: ClarityVersion,
    #[case] epoch: StacksEpochId,
) {
    let mut marf = MemoryBackingStore::new();
    let mut db = marf.as_analysis_db();

    // Can we define an empty trait?
    let result = db.execute(|db| load_versioned(db, "empty-trait", version, epoch));
    match result {
        Ok(_) => (),
        res => panic!("expected success, got {:?}", res),
    };
}

#[apply(test_clarity_versions)]
fn clarity_trait_experiments_duplicate_trait(
    #[case] version: ClarityVersion,
    #[case] epoch: StacksEpochId,
) {
    let mut marf = MemoryBackingStore::new();
    let mut db = marf.as_analysis_db();

    // Can we re-define a trait with the same type and same name in a different contract?
    let result = db.execute(|db| {
        load_versioned(db, "empty-trait", version, epoch)?;
        load_versioned(db, "empty-trait-copy", version, epoch)
    });
    match result {
        Ok(_) => (),
        res => panic!("expected success, got {:?}", res),
    };
}

#[apply(test_clarity_versions)]
fn clarity_trait_experiments_use_undefined(
    #[case] version: ClarityVersion,
    #[case] epoch: StacksEpochId,
) {
    let mut marf = MemoryBackingStore::new();
    let mut db = marf.as_analysis_db();

    // Can we define traits that use traits in not-yet-deployed contracts?
    let err = db
        .execute(|db| load_versioned(db, "no-trait", version, epoch))
        .unwrap_err();
    assert!(err.starts_with(
        "ASTError(ParseError { err: TraitReferenceUnknown(\"trait-to-be-defined-later\")"
    ));
}

#[apply(test_clarity_versions)]
fn clarity_trait_experiments_circular(
    #[case] version: ClarityVersion,
    #[case] epoch: StacksEpochId,
) {
    let mut marf = MemoryBackingStore::new();
    let mut db = marf.as_analysis_db();

    // Can we define traits in a contract that are circular?
    let err = db
        .execute(|db| {
            load_versioned(db, "circular-trait-1", version, epoch)?;
            load_versioned(db, "circular-trait-2", version, epoch)
        })
        .unwrap_err();
    assert!(err.starts_with("ASTError(ParseError { err: CircularReference([\"circular\"])"));
}

#[apply(test_clarity_versions)]
fn clarity_trait_experiments_no_response(
    #[case] version: ClarityVersion,
    #[case] epoch: StacksEpochId,
) {
    let mut marf = MemoryBackingStore::new();
    let mut db = marf.as_analysis_db();

    // Can we define traits that do not return a response type?
    let err = db
        .execute(|db| load_versioned(db, "no-response-trait", version, epoch))
        .unwrap_err();
    assert!(err.starts_with("DefineTraitBadSignature"));
}

#[apply(test_clarity_versions)]
fn clarity_trait_experiments_out_of_order(
    #[case] version: ClarityVersion,
    #[case] epoch: StacksEpochId,
) {
    let mut marf = MemoryBackingStore::new();
    let mut db = marf.as_analysis_db();

    // Can we define traits that occur in a contract out-of-order?
    let result = db.execute(|db| load_versioned(db, "out-of-order-traits", version, epoch));
    match result {
        Ok(_) => (),
        res => panic!("expected success, got {:?}", res),
    };
}

#[apply(test_clarity_versions)]
fn clarity_trait_experiments_double_trait(
    #[case] version: ClarityVersion,
    #[case] epoch: StacksEpochId,
) {
    let mut marf = MemoryBackingStore::new();
    let mut db = marf.as_analysis_db();

    // Can we define a trait with two methods with the same name and different types?
    match db.execute(|db| load_versioned(db, "double-trait", version, epoch)) {
        Ok(_) if version == ClarityVersion::Clarity1 => (),
        Err(err) if version >= ClarityVersion::Clarity2 => {
            assert!(err.starts_with("DefineTraitDuplicateMethod(\"foo\")"))
        }
        res => panic!("got {:?}", res),
    }
}

#[apply(test_clarity_versions)]
fn clarity_trait_experiments_impl_double_trait_both(
    #[case] version: ClarityVersion,
    #[case] epoch: StacksEpochId,
) {
    let mut marf = MemoryBackingStore::new();
    let mut db = marf.as_analysis_db();

    // Can we implement a trait with two methods with the same name and different types?
    match db.execute(|db| {
        load_versioned(db, "double-trait", version, epoch)?;
        load_versioned(db, "impl-double-trait-both", version, epoch)
    }) {
        Ok(_) if version == ClarityVersion::Clarity1 => (),
        Err(err) if version >= ClarityVersion::Clarity2 => {
            assert!(err.starts_with("DefineTraitDuplicateMethod(\"foo\")"))
        }
        res => panic!("got {:?}", res),
    }
}

#[apply(test_clarity_versions)]
fn clarity_trait_experiments_impl_double_trait_1(
    #[case] version: ClarityVersion,
    #[case] epoch: StacksEpochId,
) {
    let mut marf = MemoryBackingStore::new();
    let mut db = marf.as_analysis_db();

    // Can we implement a trait with two methods with the same name and different types?
    match db.execute(|db| {
        load_versioned(db, "double-trait", version, epoch)?;
        load_versioned(db, "impl-double-trait-1", version, epoch)
    }) {
        Err(err) if version == ClarityVersion::Clarity1 => {
            assert!(err.starts_with("BadTraitImplementation(\"double-method\", \"foo\")"))
        }
        Err(err) if version >= ClarityVersion::Clarity2 => {
            assert!(err.starts_with("DefineTraitDuplicateMethod(\"foo\")"))
        }
        res => panic!("got {:?}", res),
    }
}

#[apply(test_clarity_versions)]
fn clarity_trait_experiments_impl_double_trait_2(
    #[case] version: ClarityVersion,
    #[case] epoch: StacksEpochId,
) {
    let mut marf = MemoryBackingStore::new();
    let mut db = marf.as_analysis_db();

    // Can we implement a trait with two methods with the same name and different types?
    match db.execute(|db| {
        load_versioned(db, "double-trait", version, epoch)?;
        load_versioned(db, "impl-double-trait-2", version, epoch)
    }) {
        Ok(_) if version == ClarityVersion::Clarity1 => (),
        Err(err) if version >= ClarityVersion::Clarity2 => {
            assert!(err.starts_with("DefineTraitDuplicateMethod(\"foo\")"))
        }
        res => panic!("got {:?}", res),
    }
}

#[apply(test_clarity_versions)]
fn clarity_trait_experiments_use_double_trait(
    #[case] version: ClarityVersion,
    #[case] epoch: StacksEpochId,
) {
    let mut marf = MemoryBackingStore::new();
    let mut db = marf.as_analysis_db();

    // Can we implement a trait with two methods with the same name and different types?
    match db.execute(|db| {
        load_versioned(db, "double-trait", version, epoch)?;
        load_versioned(db, "partial-double-trait-1", version, epoch)?;
        load_versioned(db, "use-double-trait", version, epoch)
    }) {
        Err(err) if version == ClarityVersion::Clarity1 => {
            assert!(err.starts_with("TypeError(BoolType, UIntType)"))
        }
        Err(err) if version >= ClarityVersion::Clarity2 => {
            assert!(err.starts_with("DefineTraitDuplicateMethod(\"foo\")"))
        }
        res => panic!("got {:?}", res),
    }
}

#[apply(test_clarity_versions)]
fn clarity_trait_experiments_use_partial_double_trait_1(
    #[case] version: ClarityVersion,
    #[case] epoch: StacksEpochId,
) {
    let mut marf = MemoryBackingStore::new();
    let mut db = marf.as_analysis_db();

    // Can we implement a trait with two methods with the same name and different types?
    match db.execute(|db| {
        load_versioned(db, "double-trait", version, epoch)?;
        load_versioned(db, "partial-double-trait-1", version, epoch)?;
        load_versioned(db, "use-partial-double-trait-1", version, epoch)
    }) {
        Err(err) if version == ClarityVersion::Clarity1 => {
            assert!(err.starts_with("TypeError(BoolType, UIntType)"))
        }
        Err(err) if version >= ClarityVersion::Clarity2 => {
            assert!(err.starts_with("DefineTraitDuplicateMethod(\"foo\")"))
        }
        res => panic!("got {:?}", res),
    }
}

#[apply(test_clarity_versions)]
fn clarity_trait_experiments_use_partial_double_trait_2(
    #[case] version: ClarityVersion,
    #[case] epoch: StacksEpochId,
) {
    let mut marf = MemoryBackingStore::new();
    let mut db = marf.as_analysis_db();

    // Can we implement a trait with two methods with the same name and different types?
    match db.execute(|db| {
        load_versioned(db, "double-trait", version, epoch)?;
        load_versioned(db, "partial-double-trait-2", version, epoch)?;
        load_versioned(db, "use-partial-double-trait-2", version, epoch)
    }) {
        Ok(_) if version == ClarityVersion::Clarity1 => (),
        Err(err) if version >= ClarityVersion::Clarity2 => {
            assert!(err.starts_with("DefineTraitDuplicateMethod(\"foo\")"))
        }
        res => panic!("got {:?}", res),
    }
}

#[apply(test_clarity_versions)]
fn clarity_trait_experiments_identical_double_trait(
    #[case] version: ClarityVersion,
    #[case] epoch: StacksEpochId,
) {
    let mut marf = MemoryBackingStore::new();
    let mut db = marf.as_analysis_db();

    // Can we define a trait with two methods with the same name and the same type?
    match db.execute(|db| load_versioned(db, "identical-double-trait", version, epoch)) {
        Ok(_) if version == ClarityVersion::Clarity1 => (),
        Err(err) if version >= ClarityVersion::Clarity2 => {
            assert!(err.starts_with("DefineTraitDuplicateMethod(\"foo\")"))
        }
        res => panic!("got {:?}", res),
    }
}

#[apply(test_clarity_versions)]
fn clarity_trait_experiments_impl_identical_double_trait(
    #[case] version: ClarityVersion,
    #[case] epoch: StacksEpochId,
) {
    let mut marf = MemoryBackingStore::new();
    let mut db = marf.as_analysis_db();

    // Can we implement a trait with two methods with the same name and different types?
    match db.execute(|db| {
        load_versioned(db, "identical-double-trait", version, epoch)?;
        load_versioned(db, "impl-identical-double-trait", version, epoch)
    }) {
        Ok(_) if version == ClarityVersion::Clarity1 => (),
        Err(err) if version >= ClarityVersion::Clarity2 => {
            assert!(err.starts_with("DefineTraitDuplicateMethod(\"foo\")"))
        }
        res => panic!("got {:?}", res),
    }
}

#[apply(test_clarity_versions)]
fn clarity_trait_experiments_selfret_trait(
    #[case] version: ClarityVersion,
    #[case] epoch: StacksEpochId,
) {
    let mut marf = MemoryBackingStore::new();
    let mut db = marf.as_analysis_db();

    // Can we implement a trait that returns itself?
    let err = db
        .execute(|db| load_versioned(db, "selfret-trait", version, epoch))
        .unwrap_err();
    assert!(err.starts_with("ASTError(ParseError { err: CircularReference([\"self-return\"])"));
}

#[apply(test_clarity_versions)]
fn clarity_trait_experiments_use_math_trait_transitive_alias(
    #[case] version: ClarityVersion,
    #[case] epoch: StacksEpochId,
) {
    let mut marf = MemoryBackingStore::new();
    let mut db = marf.as_analysis_db();

    // Can we import a trait from a contract that uses but does not define the trait?
    // Does the transitive import use the trait alias or the trait name?
    let err = db
        .execute(|db| {
            load_versioned(db, "math-trait", version, epoch)?;
            load_versioned(db, "use-math-trait", version, epoch)?;
            load_versioned(db, "use-math-trait-transitive-alias", version, epoch)
        })
        .unwrap_err();
    assert!(err.starts_with("TraitReferenceUnknown(\"math-alias\")"));
}

#[apply(test_clarity_versions)]
fn clarity_trait_experiments_use_math_trait_transitive_name(
    #[case] version: ClarityVersion,
    #[case] epoch: StacksEpochId,
) {
    let mut marf = MemoryBackingStore::new();
    let mut db = marf.as_analysis_db();

    // Can we import a trait from a contract that uses but does not define the trait?
    // Does the transitive import use the trait alias or the trait name?
    match db.execute(|db| {
        load_versioned(db, "math-trait", version, epoch)?;
        load_versioned(db, "use-math-trait", version, epoch)?;
        load_versioned(db, "use-math-trait-transitive-name", version, epoch)
    }) {
        Ok(_) if version == ClarityVersion::Clarity1 => (),
        Err(err) if version >= ClarityVersion::Clarity2 => {
            assert!(err.starts_with("TraitReferenceUnknown(\"math-alias\")"))
        }
        res => panic!("got {:?}", res),
    }
}

#[apply(test_clarity_versions)]
fn clarity_trait_experiments_use_original_and_define_a_trait(
    #[case] version: ClarityVersion,
    #[case] epoch: StacksEpochId,
) {
    let mut marf = MemoryBackingStore::new();
    let mut db = marf.as_analysis_db();

    // Can we reference original trait and define trait with the same name in one contract?
    let result = db.execute(|db| {
        load_versioned(db, "a-trait", version, epoch)?;
        load_versioned(db, "use-original-and-define-a-trait", version, epoch)
    });
    match result {
        Ok(_) if version >= ClarityVersion::Clarity2 => (),
        Err(err) if version == ClarityVersion::Clarity1 => {
            assert!(err.starts_with("TraitMethodUnknown(\"a\", \"do-it\")"))
        }
        res => panic!("expected success, got {:?}", res),
    };
}

#[apply(test_clarity_versions)]
fn clarity_trait_experiments_use_redefined_and_define_a_trait(
    #[case] version: ClarityVersion,
    #[case] epoch: StacksEpochId,
) {
    let mut marf = MemoryBackingStore::new();
    let mut db = marf.as_analysis_db();

    // Can we reference redefined trait and define trait with the same name in one contract?
    // Will this redefined trait also overwrite the trait alias?
    match db.execute(|db| {
        load_versioned(db, "a-trait", version, epoch)?;
        load_versioned(db, "use-redefined-and-define-a-trait", version, epoch)
    }) {
        Ok(_) if version == ClarityVersion::Clarity1 => (),
        Err(err) if version >= ClarityVersion::Clarity2 => {
            assert!(err.starts_with("TraitMethodUnknown(\"a\", \"do-that\")"))
        }
        res => panic!("got {:?}", res),
    }
}

#[apply(test_clarity_versions)]
fn clarity_trait_experiments_use_a_trait_transitive_original(
    #[case] version: ClarityVersion,
    #[case] epoch: StacksEpochId,
) {
    let mut marf = MemoryBackingStore::new();
    let mut db = marf.as_analysis_db();

    // Can we use the original trait from a contract that redefines it?
    let err = db
        .execute(|db| {
            load_versioned(db, "a-trait", version, epoch)?;
            load_versioned(db, "use-and-define-a-trait", version, epoch)?;
            load_versioned(db, "use-a-trait-transitive-original", version, epoch)
        })
        .unwrap_err();
    assert!(err.starts_with("TraitMethodUnknown(\"a\", \"do-it\")"));
}

#[apply(test_clarity_versions)]
fn clarity_trait_experiments_use_a_trait_transitive_redefined(
    #[case] version: ClarityVersion,
    #[case] epoch: StacksEpochId,
) {
    let mut marf = MemoryBackingStore::new();
    let mut db = marf.as_analysis_db();

    // Can we use the redefined trait from a contract that redefines it?
    let result = db.execute(|db| {
        load_versioned(db, "a-trait", version, epoch)?;
        load_versioned(db, "use-and-define-a-trait", version, epoch)?;
        load_versioned(db, "use-a-trait-transitive-redefined", version, epoch)
    });
    match result {
        Ok(_) => (),
        res => panic!("expected success, got {:?}", res),
    };
}

#[apply(test_clarity_versions)]
fn clarity_trait_experiments_nested_traits(
    #[case] version: ClarityVersion,
    #[case] epoch: StacksEpochId,
) {
    let mut marf = MemoryBackingStore::new();
    let mut db = marf.as_analysis_db();

    // Can we nest traits in other types inside a function parameter type?
    let result = db.execute(|db| {
        load_versioned(db, "empty-trait", version, epoch)?;
        load_versioned(db, "nested-trait-1", version, epoch)?;
        load_versioned(db, "nested-trait-2", version, epoch)?;
        load_versioned(db, "nested-trait-3", version, epoch)?;
        load_versioned(db, "nested-trait-4", version, epoch)
    });
    match result {
        Ok(_) => (),
        res => panic!("expected success, got {:?}", res),
    };
}

#[apply(test_clarity_versions)]
fn clarity_trait_experiments_call_nested_trait_1(
    #[case] version: ClarityVersion,
    #[case] epoch: StacksEpochId,
) {
    let mut marf = MemoryBackingStore::new();
    let mut db = marf.as_analysis_db();

    // Can we call functions with nested trait types by passing a trait parameter?
    // Can we call functions with nested trait types where a trait parameter is _not_ passed? E.g. a response.
    let result = db.execute(|db| {
        load_versioned(db, "empty", version, epoch)?;
        load_versioned(db, "empty-trait", version, epoch)?;
        load_versioned(db, "math-trait", version, epoch)?;
        load_versioned(db, "nested-trait-1", version, epoch)?;
        call_versioned(
            db,
            "nested-trait-1",
            "foo",
            "(list .empty .math-trait)",
            version,
            epoch,
        )
    });
    match result {
        Err(err) if version == ClarityVersion::Clarity1 => {
            assert!(err.starts_with("TypeError"))
        }
        Ok(_) if version >= ClarityVersion::Clarity2 => (),
        res => panic!("got {:?}", res),
    };
}

#[apply(test_clarity_versions)]
fn clarity_trait_experiments_call_nested_trait_2(
    #[case] version: ClarityVersion,
    #[case] epoch: StacksEpochId,
) {
    let mut marf = MemoryBackingStore::new();
    let mut db = marf.as_analysis_db();

    // Can we call functions with nested trait types by passing a trait parameter?
    // Can we call functions with nested trait types where a trait parameter is _not_ passed? E.g. a response.
    let result = db.execute(|db| {
        load_versioned(db, "empty", version, epoch)?;
        load_versioned(db, "empty-trait", version, epoch)?;
        load_versioned(db, "math-trait", version, epoch)?;
        load_versioned(db, "nested-trait-2", version, epoch)?;
        call_versioned(db, "nested-trait-2", "foo", "(some .empty)", version, epoch)
    });
    match result {
        Err(err) if version == ClarityVersion::Clarity1 => {
            assert!(err.starts_with("TypeError"))
        }
        Ok(_) if version >= ClarityVersion::Clarity2 => (),
        res => panic!("got {:?}", res),
    };
}

#[apply(test_clarity_versions)]
fn clarity_trait_experiments_call_nested_trait_3_ok(
    #[case] version: ClarityVersion,
    #[case] epoch: StacksEpochId,
) {
    let mut marf = MemoryBackingStore::new();
    let mut db = marf.as_analysis_db();

    // Can we call functions with nested trait types by passing a trait parameter?
    // Can we call functions with nested trait types where a trait parameter is _not_ passed? E.g. a response.
    let result = db.execute(|db| {
        load_versioned(db, "empty", version, epoch)?;
        load_versioned(db, "empty-trait", version, epoch)?;
        load_versioned(db, "math-trait", version, epoch)?;
        load_versioned(db, "nested-trait-3", version, epoch)?;
        call_versioned(db, "nested-trait-3", "foo", "(ok .empty)", version, epoch)
    });
    match result {
        Err(err) if version == ClarityVersion::Clarity1 => {
            assert!(err.starts_with("TypeError"))
        }
        Ok(_) if version >= ClarityVersion::Clarity2 => (),
        res => panic!("got {:?}", res),
    };
}

#[apply(test_clarity_versions)]
fn clarity_trait_experiments_call_nested_trait_3_err(
    #[case] version: ClarityVersion,
    #[case] epoch: StacksEpochId,
) {
    let mut marf = MemoryBackingStore::new();
    let mut db = marf.as_analysis_db();

    // Can we call functions with nested trait types by passing a trait parameter?
    // Can we call functions with nested trait types where a trait parameter is _not_ passed? E.g. a response.
    let result = db.execute(|db| {
        load_versioned(db, "empty", version, epoch)?;
        load_versioned(db, "empty-trait", version, epoch)?;
        load_versioned(db, "math-trait", version, epoch)?;
        load_versioned(db, "nested-trait-3", version, epoch)?;
        call_versioned(db, "nested-trait-3", "foo", "(err false)", version, epoch)
    });
    match result {
        Ok(_) => (),
        res => panic!("got {:?}", res),
    };
}

#[apply(test_clarity_versions)]
fn clarity_trait_experiments_call_nested_trait_4(
    #[case] version: ClarityVersion,
    #[case] epoch: StacksEpochId,
) {
    let mut marf = MemoryBackingStore::new();
    let mut db = marf.as_analysis_db();

    // Can we call functions with nested trait types by passing a trait parameter?
    // Can we call functions with nested trait types where a trait parameter is _not_ passed? E.g. a response.
    let result = db.execute(|db| {
        load_versioned(db, "empty", version, epoch)?;
        load_versioned(db, "empty-trait", version, epoch)?;
        load_versioned(db, "math-trait", version, epoch)?;
        load_versioned(db, "nested-trait-4", version, epoch)?;
        call_versioned(
            db,
            "nested-trait-4",
            "foo",
            "(tuple (empty .empty))",
            version,
            epoch,
        )
    });
    match result {
        Err(err) if version == ClarityVersion::Clarity1 => {
            assert!(err.starts_with("TypeError"))
        }
        Ok(_) if version >= ClarityVersion::Clarity2 => (),
        res => panic!("got {:?}", res),
    };
}

#[apply(test_clarity_versions)]
fn clarity_trait_experiments_impl_math_trait_incomplete(
    #[case] version: ClarityVersion,
    #[case] epoch: StacksEpochId,
) {
    let mut marf = MemoryBackingStore::new();
    let mut db = marf.as_analysis_db();

    // Can we use impl-trait on a partial trait implementation?
    let err = db
        .execute(|db| {
            load_versioned(db, "math-trait", version, epoch)?;
            load_versioned(db, "impl-math-trait-incomplete", version, epoch)
        })
        .unwrap_err();
    assert!(err.starts_with("BadTraitImplementation(\"math\", \"sub\")"));
}

#[apply(test_clarity_versions)]
fn clarity_trait_experiments_trait_literal(
    #[case] version: ClarityVersion,
    #[case] epoch: StacksEpochId,
) {
    let mut marf = MemoryBackingStore::new();
    let mut db = marf.as_analysis_db();

    // Can we pass a literal where a trait is expected with a full implementation?
    let result = db.execute(|db| {
        load_versioned(db, "math-trait", version, epoch)?;
        load_versioned(db, "impl-math-trait", version, epoch)?;
        load_versioned(db, "trait-literal", version, epoch)
    });
    match result {
        Ok(_) => (),
        res => panic!("expected success, got {:?}", res),
    };
}

#[apply(test_clarity_versions)]
fn clarity_trait_experiments_pass_let_rename_trait(
    #[case] version: ClarityVersion,
    #[case] epoch: StacksEpochId,
) {
    let mut marf = MemoryBackingStore::new();
    let mut db = marf.as_analysis_db();

    // Can we rename a trait with let and pass it to a function?
    let result = db.execute(|db| {
        load_versioned(db, "math-trait", version, epoch)?;
        load_versioned(db, "pass-let-rename-trait", version, epoch)
    });
    match result {
        Ok(_) => (),
        res => panic!("expected success, got {:?}", res),
    };
}

#[apply(test_clarity_versions)]
fn clarity_trait_experiments_trait_literal_incomplete(
    #[case] version: ClarityVersion,
    #[case] epoch: StacksEpochId,
) {
    let mut marf = MemoryBackingStore::new();
    let mut db = marf.as_analysis_db();

    // Can we pass a literal where a trait is expected with a partial implementation?
    let err = db
        .execute(|db| {
            load_versioned(db, "math-trait", version, epoch)?;
            load_versioned(db, "partial-math-trait", version, epoch)?;
            load_versioned(db, "trait-literal-incomplete", version, epoch)
        })
        .unwrap_err();
    assert!(err.starts_with("BadTraitImplementation(\"math\", \"sub\")"));
}

#[apply(test_clarity_versions)]
fn clarity_trait_experiments_call_let_rename_trait(
    #[case] version: ClarityVersion,
    #[case] epoch: StacksEpochId,
) {
    let mut marf = MemoryBackingStore::new();
    let mut db = marf.as_analysis_db();

    // Can we rename a trait with let and call it?
    let result = db.execute(|db| {
        load_versioned(db, "math-trait", version, epoch)?;
        load_versioned(db, "call-let-rename-trait", version, epoch)
    });
    match result {
        Ok(_) if version >= ClarityVersion::Clarity2 => (),
        Err(err) if version == ClarityVersion::Clarity1 => {
            assert!(err.starts_with("TraitReferenceUnknown(\"new-math-contract\")"))
        }
        res => panic!("expected success, got {:?}", res),
    };
}

#[apply(test_clarity_versions)]
fn clarity_trait_experiments_trait_data_1(
    #[case] version: ClarityVersion,
    #[case] epoch: StacksEpochId,
) {
    let mut marf = MemoryBackingStore::new();
    let mut db = marf.as_analysis_db();

    // Can we save trait in data-var or data-map?
    let err = db
        .execute(|db| {
            load_versioned(db, "math-trait", version, epoch)?;
            load_versioned(db, "use-math-trait", version, epoch)?;
            load_versioned(db, "trait-data-1", version, epoch)
        })
        .unwrap_err();
    assert!(err.starts_with("ASTError(ParseError { err: TraitReferenceNotAllowed"));
}

#[apply(test_clarity_versions)]
fn clarity_trait_experiments_trait_data_2(
    #[case] version: ClarityVersion,
    #[case] epoch: StacksEpochId,
) {
    let mut marf = MemoryBackingStore::new();
    let mut db = marf.as_analysis_db();

    // Can we save trait in data-var or data-map?
    let err = db
        .execute(|db| {
            load_versioned(db, "math-trait", version, epoch)?;
            load_versioned(db, "use-math-trait", version, epoch)?;
            load_versioned(db, "trait-data-2", version, epoch)
        })
        .unwrap_err();
    assert!(err.starts_with("ASTError(ParseError { err: TraitReferenceNotAllowed"));
}

#[apply(test_clarity_versions)]
fn clarity_trait_experiments_upcast_trait_1(
    #[case] version: ClarityVersion,
    #[case] epoch: StacksEpochId,
) {
    let mut marf = MemoryBackingStore::new();
    let mut db = marf.as_analysis_db();

    // Can we use a trait exp where a principal type is expected?
    // Principal can be expected in var/map/function
    let err = db
        .execute(|db| {
            load_versioned(db, "math-trait", version, epoch)?;
            load_versioned(db, "upcast-trait-1", version, epoch)
        })
        .unwrap_err();
    if epoch <= StacksEpochId::Epoch2_05 {
        assert!(err.starts_with("TypeError(PrincipalType, TraitReferenceType"));
    } else {
        assert!(err.starts_with("TypeError(PrincipalType, CallableType"));
    }
}

#[apply(test_clarity_versions)]
fn clarity_trait_experiments_upcast_trait_2(
    #[case] version: ClarityVersion,
    #[case] epoch: StacksEpochId,
) {
    let mut marf = MemoryBackingStore::new();
    let mut db = marf.as_analysis_db();

    // Can we use a trait exp where a principal type is expected?
    // Principal can be expected in var/map/function
    let err = db
        .execute(|db| {
            load_versioned(db, "math-trait", version, epoch)?;
            load_versioned(db, "upcast-trait-2", version, epoch)
        })
        .unwrap_err();
    assert!(err.starts_with("TypeError(TupleType(TupleTypeSignature { \"val\": principal,}), TupleType(TupleTypeSignature { \"val\": <S1G2081040G2081040G2081040G208105NK8PE5.math-trait.math>,}))"));
}

#[apply(test_clarity_versions)]
fn clarity_trait_experiments_upcast_trait_3(
    #[case] version: ClarityVersion,
    #[case] epoch: StacksEpochId,
) {
    let mut marf = MemoryBackingStore::new();
    let mut db = marf.as_analysis_db();

    // Can we use a trait exp where a principal type is expected?
    // Principal can be expected in var/map/function
    let err = db
        .execute(|db| {
            load_versioned(db, "math-trait", version, epoch)?;
            load_versioned(db, "upcast-trait-3", version, epoch)
        })
        .unwrap_err();
    if epoch <= StacksEpochId::Epoch2_05 {
        assert!(err.starts_with("TypeError(PrincipalType, TraitReferenceType"));
    } else {
        assert!(err.starts_with("TypeError(PrincipalType, CallableType"));
    }
}

#[apply(test_clarity_versions)]
fn clarity_trait_experiments_return_trait(
    #[case] version: ClarityVersion,
    #[case] epoch: StacksEpochId,
) {
    let mut marf = MemoryBackingStore::new();
    let mut db = marf.as_analysis_db();

    // Can we return a trait from a function and use it?
    let result = db.execute(|db| {
        load_versioned(db, "math-trait", version, epoch)?;
        load_versioned(db, "return-trait", version, epoch)
    });
    match result {
        Ok(_) => (),
        res => panic!("expected success, got {:?}", res),
    };
}

#[apply(test_clarity_versions)]
fn clarity_trait_experiments_upcast_renamed(
    #[case] version: ClarityVersion,
    #[case] epoch: StacksEpochId,
) {
    let mut marf = MemoryBackingStore::new();
    let mut db = marf.as_analysis_db();

    // Can we use a let-renamed trait where a principal type is expected?
    // That is, does let-renaming affect the type?
    let err = db
        .execute(|db| {
            load_versioned(db, "math-trait", version, epoch)?;
            load_versioned(db, "upcast-renamed", version, epoch)
        })
        .unwrap_err();
    if epoch <= StacksEpochId::Epoch2_05 {
        assert!(err.starts_with("TypeError(PrincipalType, TraitReferenceType"));
    } else {
        assert!(err.starts_with("TypeError(PrincipalType, CallableType"));
    }
}

#[apply(test_clarity_versions)]
fn clarity_trait_experiments_constant_call(
    #[case] version: ClarityVersion,
    #[case] epoch: StacksEpochId,
) {
    let mut marf = MemoryBackingStore::new();
    let mut db = marf.as_analysis_db();

    // A principal literal in a constant should be callable.
    let result = db.execute(|db| {
        load_versioned(db, "math-trait", version, epoch)?;
        load_versioned(db, "impl-math-trait", version, epoch)?;
        load_versioned(db, "constant-call", version, epoch)
    });
    match result {
        Ok(_) if version >= ClarityVersion::Clarity2 => (),
        Err(err) if version == ClarityVersion::Clarity1 => {
            assert!(err.starts_with("TraitReferenceUnknown(\"principal-value\")"))
        }
        res => panic!("expected success, got {:?}", res),
    };
}

#[apply(test_clarity_versions)]
fn clarity_trait_experiments_constant_to_trait(
    #[case] version: ClarityVersion,
    #[case] epoch: StacksEpochId,
) {
    let mut marf = MemoryBackingStore::new();
    let mut db = marf.as_analysis_db();

    // A principal literal in a constant should be callable.
    let result = db.execute(|db| {
        load_versioned(db, "math-trait", version, epoch)?;
        load_versioned(db, "impl-math-trait", version, epoch)?;
        load_versioned(db, "constant-to-trait", version, epoch)
    });
    match result {
        Ok(_) if version >= ClarityVersion::Clarity2 => (),
        Err(err) if epoch <= StacksEpochId::Epoch2_05 => {
            assert!(err.starts_with("TypeError(TraitReferenceType"))
        }
        Err(err) if version == ClarityVersion::Clarity1 => {
            assert!(err.starts_with("TypeError(CallableType(Trait(TraitIdentifier"))
        }
        res => panic!("expected success, got {:?}", res),
    };
}

#[apply(test_clarity_versions)]
fn clarity_trait_experiments_constant_to_constant_call(
    #[case] version: ClarityVersion,
    #[case] epoch: StacksEpochId,
) {
    let mut marf = MemoryBackingStore::new();
    let mut db = marf.as_analysis_db();

    // A principal literal from a constant should be treated as a principal
    // literal (and therefore be callable)
    let result = db.execute(|db| {
        load_versioned(db, "math-trait", version, epoch)?;
        load_versioned(db, "impl-math-trait", version, epoch)?;
        load_versioned(db, "constant-to-constant-call", version, epoch)
    });
    match result {
        Ok(_) if version >= ClarityVersion::Clarity2 => (),
        Err(err) if epoch <= StacksEpochId::Epoch2_05 => {
            assert!(err.starts_with("TypeError(TraitReferenceType"))
        }
        Err(err) if version == ClarityVersion::Clarity1 => {
            assert!(err.starts_with("TypeError(CallableType(Trait(TraitIdentifier"))
        }
        res => panic!("expected success, got {:?}", res),
    };
}

#[apply(test_clarity_versions)]
fn clarity_trait_experiments_downcast_literal_1(
    #[case] version: ClarityVersion,
    #[case] epoch: StacksEpochId,
) {
    let mut marf = MemoryBackingStore::new();
    let mut db = marf.as_analysis_db();

    // A principal literal returned from a function should not be castable to a
    // trait
    let err = db
        .execute(|db| {
            load_versioned(db, "math-trait", version, epoch)?;
            load_versioned(db, "impl-math-trait", version, epoch)?;
            load_versioned(db, "downcast-literal-1", version, epoch)
        })
        .unwrap_err();
    if epoch <= StacksEpochId::Epoch2_05 {
        println!("err: {}", err);
        assert!(err.starts_with("TypeError(TraitReferenceType(TraitIdentifier { name: ClarityName(\"math\"), contract_identifier: QualifiedContractIdentifier { issuer: StandardPrincipalData(S1G2081040G2081040G2081040G208105NK8PE5), name: ContractName(\"math-trait\") } }), PrincipalType)"));
    } else {
        assert!(err.starts_with("TypeError(CallableType(Trait(TraitIdentifier { name: ClarityName(\"math\"), contract_identifier: QualifiedContractIdentifier { issuer: StandardPrincipalData(S1G2081040G2081040G2081040G208105NK8PE5), name: ContractName(\"math-trait\") } })), PrincipalType)"));
    }
}

#[apply(test_clarity_versions)]
fn clarity_trait_experiments_downcast_literal_2(
    #[case] version: ClarityVersion,
    #[case] epoch: StacksEpochId,
) {
    let mut marf = MemoryBackingStore::new();
    let mut db = marf.as_analysis_db();

    // A principal returned from a function should not be callable
    let err = db
        .execute(|db| {
            load_versioned(db, "math-trait", version, epoch)?;
            load_versioned(db, "impl-math-trait", version, epoch)?;
            load_versioned(db, "downcast-literal-2", version, epoch)
        })
        .unwrap_err();
    match version {
        ClarityVersion::Clarity2 | ClarityVersion::Clarity3 => {
            assert!(err.starts_with("ExpectedCallableType(PrincipalType)"))
        }
        ClarityVersion::Clarity1 => {
            assert!(err.starts_with("TraitReferenceUnknown(\"principal-value\")"))
        }
    }
}

#[apply(test_clarity_versions)]
fn clarity_trait_experiments_downcast_literal_3(
    #[case] version: ClarityVersion,
    #[case] epoch: StacksEpochId,
) {
    let mut marf = MemoryBackingStore::new();
    let mut db = marf.as_analysis_db();

    // A principal saved in a let binding should not be callable
    let err = db
        .execute(|db| {
            load_versioned(db, "math-trait", version, epoch)?;
            load_versioned(db, "impl-math-trait", version, epoch)?;
            load_versioned(db, "downcast-literal-3", version, epoch)
        })
        .unwrap_err();
    assert!(err.starts_with("TraitReferenceUnknown(\"p\")"));
}

#[apply(test_clarity_versions)]
fn clarity_trait_experiments_downcast_trait_2(
    #[case] version: ClarityVersion,
    #[case] epoch: StacksEpochId,
) {
    let mut marf = MemoryBackingStore::new();
    let mut db = marf.as_analysis_db();

    // Can we use a principal exp where a trait type is expected?
    // Principal can come from constant/var/map/function/keyword
    let err = db
        .execute(|db| {
            load_versioned(db, "math-trait", version, epoch)?;
            load_versioned(db, "impl-math-trait", version, epoch)?;
            load_versioned(db, "downcast-trait-2", version, epoch)
        })
        .unwrap_err();
    if epoch <= StacksEpochId::Epoch2_05 {
        assert!(err.starts_with("TypeError(TraitReferenceType(TraitIdentifier { name: ClarityName(\"math\"), contract_identifier: QualifiedContractIdentifier { issuer: StandardPrincipalData(S1G2081040G2081040G2081040G208105NK8PE5), name: ContractName(\"math-trait\") } }), PrincipalType)"));
    } else {
        assert!(err.starts_with("TypeError(CallableType(Trait(TraitIdentifier { name: ClarityName(\"math\"), contract_identifier: QualifiedContractIdentifier { issuer: StandardPrincipalData(S1G2081040G2081040G2081040G208105NK8PE5), name: ContractName(\"math-trait\") } })), PrincipalType)"));
    }
}

#[apply(test_clarity_versions)]
fn clarity_trait_experiments_downcast_trait_3(
    #[case] version: ClarityVersion,
    #[case] epoch: StacksEpochId,
) {
    let mut marf = MemoryBackingStore::new();
    let mut db = marf.as_analysis_db();

    // Can we use a principal exp where a trait type is expected?
    // Principal can come from constant/var/map/function/keyword
    let err = db
        .execute(|db| {
            load_versioned(db, "math-trait", version, epoch)?;
            load_versioned(db, "downcast-trait-3", version, epoch)
        })
        .unwrap_err();
    if epoch <= StacksEpochId::Epoch2_05 {
        assert!(err.starts_with("TypeError(TraitReferenceType(TraitIdentifier { name: ClarityName(\"math\"), contract_identifier: QualifiedContractIdentifier { issuer: StandardPrincipalData(S1G2081040G2081040G2081040G208105NK8PE5), name: ContractName(\"math-trait\") } }), PrincipalType)"));
    } else {
        assert!(err.starts_with("TypeError(CallableType(Trait(TraitIdentifier { name: ClarityName(\"math\"), contract_identifier: QualifiedContractIdentifier { issuer: StandardPrincipalData(S1G2081040G2081040G2081040G208105NK8PE5), name: ContractName(\"math-trait\") } })), PrincipalType)"));
    }
}

#[apply(test_clarity_versions)]
fn clarity_trait_experiments_downcast_trait_4(
    #[case] version: ClarityVersion,
    #[case] epoch: StacksEpochId,
) {
    let mut marf = MemoryBackingStore::new();
    let mut db = marf.as_analysis_db();

    // Can we use a principal exp where a trait type is expected?
    // Principal can come from constant/var/map/function/keyword
    let err = db
        .execute(|db| {
            load_versioned(db, "math-trait", version, epoch)?;
            load_versioned(db, "downcast-trait-4", version, epoch)
        })
        .unwrap_err();
    if epoch <= StacksEpochId::Epoch2_05 {
        assert!(err.starts_with("TypeError(TraitReferenceType(TraitIdentifier { name: ClarityName(\"math\"), contract_identifier: QualifiedContractIdentifier { issuer: StandardPrincipalData(S1G2081040G2081040G2081040G208105NK8PE5), name: ContractName(\"math-trait\") } }), PrincipalType)"));
    } else {
        assert!(err.starts_with("TypeError(CallableType(Trait(TraitIdentifier { name: ClarityName(\"math\"), contract_identifier: QualifiedContractIdentifier { issuer: StandardPrincipalData(S1G2081040G2081040G2081040G208105NK8PE5), name: ContractName(\"math-trait\") } })), PrincipalType)"));
    }
}

#[apply(test_clarity_versions)]
fn clarity_trait_experiments_downcast_trait_5(
    #[case] version: ClarityVersion,
    #[case] epoch: StacksEpochId,
) {
    let mut marf = MemoryBackingStore::new();
    let mut db = marf.as_analysis_db();

    // Can we use a principal exp where a trait type is expected?
    // Principal can come from constant/var/map/function/keyword
    let err = db
        .execute(|db| {
            load_versioned(db, "math-trait", version, epoch)?;
            load_versioned(db, "downcast-trait-5", version, epoch)
        })
        .unwrap_err();
    if epoch <= StacksEpochId::Epoch2_05 {
        assert!(err.starts_with("TypeError(TraitReferenceType(TraitIdentifier { name: ClarityName(\"math\"), contract_identifier: QualifiedContractIdentifier { issuer: StandardPrincipalData(S1G2081040G2081040G2081040G208105NK8PE5), name: ContractName(\"math-trait\") } }), PrincipalType)"));
    } else {
        assert!(err.starts_with("TypeError(CallableType(Trait(TraitIdentifier { name: ClarityName(\"math\"), contract_identifier: QualifiedContractIdentifier { issuer: StandardPrincipalData(S1G2081040G2081040G2081040G208105NK8PE5), name: ContractName(\"math-trait\") } })), PrincipalType)"));
    }
}

#[apply(test_clarity_versions)]
fn clarity_trait_experiments_identical_trait_cast(
    #[case] version: ClarityVersion,
    #[case] epoch: StacksEpochId,
) {
    let mut marf = MemoryBackingStore::new();
    let mut db = marf.as_analysis_db();

    // Can we cast a trait to a different trait with the same signature?
    let result = db.execute(|db| {
        load_versioned(db, "empty-trait", version, epoch)?;
        load_versioned(db, "empty-trait-copy", version, epoch)?;
        load_versioned(db, "identical-trait-cast", version, epoch)
    });
    match result {
        Ok(_) if version >= ClarityVersion::Clarity2 => (),
        Err(err) if epoch <= StacksEpochId::Epoch2_05 => {
            assert!(err.starts_with("TypeError(TraitReferenceType(TraitIdentifier"))
        }
        Err(err) if version == ClarityVersion::Clarity1 => {
            assert!(err.starts_with("TypeError(CallableType(Trait(TraitIdentifier"))
        }
        res => panic!("expected success, got {:?}", res),
    };
}

#[apply(test_clarity_versions)]
fn clarity_trait_experiments_trait_cast(
    #[case] version: ClarityVersion,
    #[case] epoch: StacksEpochId,
) {
    let mut marf = MemoryBackingStore::new();
    let mut db = marf.as_analysis_db();

    // Can we cast a trait to an compatible trait?
    let result = db.execute(|db| {
        load_versioned(db, "empty-trait", version, epoch)?;
        load_versioned(db, "math-trait", version, epoch)?;
        load_versioned(db, "trait-cast", version, epoch)
    });
    match result {
        Ok(_) if version >= ClarityVersion::Clarity2 => (),
        Err(err) if epoch <= StacksEpochId::Epoch2_05 => {
            assert!(err.starts_with("TypeError(TraitReferenceType(TraitIdentifier"))
        }
        Err(err) if version == ClarityVersion::Clarity1 => {
            assert!(err.starts_with("TypeError(CallableType(Trait(TraitIdentifier"))
        }
        res => panic!("got {:?}", res),
    };
}

#[apply(test_clarity_versions)]
fn clarity_trait_experiments_trait_cast_incompatible(
    #[case] version: ClarityVersion,
    #[case] epoch: StacksEpochId,
) {
    let mut marf = MemoryBackingStore::new();
    let mut db = marf.as_analysis_db();

    // Can we cast a trait to an incompatible trait?
    let err = db
        .execute(|db| {
            load_versioned(db, "empty-trait", version, epoch)?;
            load_versioned(db, "math-trait", version, epoch)?;
            load_versioned(db, "trait-cast-incompatible", version, epoch)
        })
        .unwrap_err();
    match version {
        ClarityVersion::Clarity1 => {
            if epoch <= StacksEpochId::Epoch2_05 {
                assert!(err.starts_with("TypeError(TraitReferenceType(TraitIdentifier"))
            } else {
                assert!(err.starts_with("TypeError(CallableType(Trait(TraitIdentifier"))
            }
        }
        ClarityVersion::Clarity2 | ClarityVersion::Clarity3 => {
            assert!(err.starts_with("IncompatibleTrait"))
        }
    }
}

#[apply(test_clarity_versions)]
fn clarity_trait_experiments_renamed_trait_cast(
    #[case] version: ClarityVersion,
    #[case] epoch: StacksEpochId,
) {
    let mut marf = MemoryBackingStore::new();
    let mut db = marf.as_analysis_db();

    // Can we cast a trait to a renaming of itself?
    let result = db.execute(|db| {
        load_versioned(db, "empty-trait", version, epoch)?;
        load_versioned(db, "renamed-trait-cast", version, epoch)
    });
    match result {
        Ok(_) => (),
        res => panic!("expected success, got {:?}", res),
    };
}

#[apply(test_clarity_versions)]
fn clarity_trait_experiments_readonly_use_trait(
    #[case] version: ClarityVersion,
    #[case] epoch: StacksEpochId,
) {
    let mut marf = MemoryBackingStore::new();
    let mut db = marf.as_analysis_db();

    // Can we pass a trait to a read-only function?
    let result = db.execute(|db| {
        load_versioned(db, "empty-trait", version, epoch)?;
        load_versioned(db, "readonly-use-trait", version, epoch)
    });
    match result {
        Ok(_) => (),
        res => panic!("expected success, got {:?}", res),
    };
}

#[apply(test_clarity_versions)]
fn clarity_trait_experiments_readonly_pass_trait(
    #[case] version: ClarityVersion,
    #[case] epoch: StacksEpochId,
) {
    let mut marf = MemoryBackingStore::new();
    let mut db = marf.as_analysis_db();

    // Can we pass a trait to a read-only function?
    let result = db.execute(|db| {
        load_versioned(db, "empty-trait", version, epoch)?;
        load_versioned(db, "readonly-pass-trait", version, epoch)
    });
    match result {
        Ok(_) => (),
        res => panic!("expected success, got {:?}", res),
    };
}

// TODO: This should be allowed
#[apply(test_clarity_versions)]
fn clarity_trait_experiments_readonly_call_trait(
    #[case] version: ClarityVersion,
    #[case] epoch: StacksEpochId,
) {
    let mut marf = MemoryBackingStore::new();
    let mut db = marf.as_analysis_db();

    // Can we dynamically call a trait in a read-only function?
    let err = db
        .execute(|db| {
            load_versioned(db, "empty-trait", version, epoch)?;
            load_versioned(db, "readonly-call-trait", version, epoch)
        })
        .unwrap_err();
    assert!(err.starts_with("WriteAttemptedInReadOnly"));
}

// TODO: This should be allowed
#[apply(test_clarity_versions)]
fn clarity_trait_experiments_readonly_static_call(
    #[case] version: ClarityVersion,
    #[case] epoch: StacksEpochId,
) {
    let mut marf = MemoryBackingStore::new();
    let mut db = marf.as_analysis_db();

    // Can we call a readonly function in a separate contract from a readonly function?
    let result = db.execute(|db| {
        load_versioned(db, "math-trait", version, epoch)?;
        load_versioned(db, "impl-math-trait", version, epoch)?;
        load_versioned(db, "readonly-static-call", version, epoch)
    });
    match result {
        Ok(_) => (),
        res => panic!("expected success, got {:?}", res),
    };
}

#[apply(test_clarity_versions)]
fn clarity_trait_experiments_readonly_static_call_trait(
    #[case] version: ClarityVersion,
    #[case] epoch: StacksEpochId,
) {
    let mut marf = MemoryBackingStore::new();
    let mut db = marf.as_analysis_db();

    // Can we call a function with traits from a read-only function statically?
    let err = db
        .execute(|db| {
            load_versioned(db, "math-trait", version, epoch)?;
            load_versioned(db, "impl-math-trait", version, epoch)?;
            load_versioned(db, "readonly-static-call-trait", version, epoch)
        })
        .unwrap_err();
    assert!(err.starts_with("WriteAttemptedInReadOnly"));
}

#[apply(test_clarity_versions)]
fn clarity_trait_experiments_dyn_call_trait(
    #[case] version: ClarityVersion,
    #[case] epoch: StacksEpochId,
) {
    let mut marf = MemoryBackingStore::new();
    let mut db = marf.as_analysis_db();

    // Can we dynamically call a contract that fully implements a trait?
    let result = db.execute(|db| {
        load_versioned(db, "math-trait", version, epoch)?;
        load_versioned(db, "use-math-trait", version, epoch)?;
        load_versioned(db, "impl-math-trait", version, epoch)?;
        call_versioned(
            db,
            "use-math-trait",
            "add-call",
            ".impl-math-trait u3 u5",
            version,
            epoch,
        )
    });
    match result {
        Ok(_) => (),
        res => panic!("expected success, got {:?}", res),
    };
}

#[apply(test_clarity_versions)]
fn clarity_trait_experiments_dyn_call_trait_partial(
    #[case] version: ClarityVersion,
    #[case] epoch: StacksEpochId,
) {
    let mut marf = MemoryBackingStore::new();
    let mut db = marf.as_analysis_db();

    // Can we dynamically call a contract that just implements one function from a trait?
    let err = db
        .execute(|db| {
            load_versioned(db, "math-trait", version, epoch)?;
            load_versioned(db, "use-math-trait", version, epoch)?;
            load_versioned(db, "partial-math-trait", version, epoch)?;
            call_versioned(
                db,
                "use-math-trait",
                "add-call",
                ".partial-math-trait u3 u5",
                version,
                epoch,
            )
        })
        .unwrap_err();
    assert!(err.starts_with("BadTraitImplementation(\"math\", \"sub\")"));
}

#[apply(test_clarity_versions)]
fn clarity_trait_experiments_dyn_call_not_implemented(
    #[case] version: ClarityVersion,
    #[case] epoch: StacksEpochId,
) {
    let mut marf = MemoryBackingStore::new();
    let mut db = marf.as_analysis_db();

    // Can we dynamically call a contract that doesn't implement the function call via the trait?
    let err = db
        .execute(|db| {
            load_versioned(db, "math-trait", version, epoch)?;
            load_versioned(db, "use-math-trait", version, epoch)?;
            load_versioned(db, "empty", version, epoch)?;
            call_versioned(
                db,
                "use-math-trait",
                "add-call",
                ".empty u3 u5",
                version,
                epoch,
            )
        })
        .unwrap_err();
    assert!(err.starts_with("BadTraitImplementation(\"math\", \"add\")"));
}

#[apply(test_clarity_versions)]
fn clarity_trait_experiments_call_use_principal(
    #[case] version: ClarityVersion,
    #[case] epoch: StacksEpochId,
) {
    let mut marf = MemoryBackingStore::new();
    let mut db = marf.as_analysis_db();

    // Can we call a contract with takes a principal with a contract identifier that is not bound to a deployed contract?
    let result = db.execute(|db| {
        load_versioned(db, "use-principal", version, epoch)?;
        call_versioned(db, "use-principal", "use", ".made-up", version, epoch)
    });
    match result {
        Ok(_) => (),
        res => panic!("expected success, got {:?}", res),
    };
}

#[apply(test_clarity_versions)]
fn clarity_trait_experiments_call_return_trait(
    #[case] version: ClarityVersion,
    #[case] epoch: StacksEpochId,
) {
    let mut marf = MemoryBackingStore::new();
    let mut db = marf.as_analysis_db();

    // Can we call a contract where a function returns a trait?
    let result = db.execute(|db| {
        load_versioned(db, "math-trait", version, epoch)?;
        load_versioned(db, "impl-math-trait", version, epoch)?;
        load_versioned(db, "return-trait", version, epoch)?;
        call_versioned(
            db,
            "return-trait",
            "add-call-indirect",
            ".impl-math-trait u3 u5",
            version,
            epoch,
        )
    });
    match result {
        Ok(_) => (),
        res => panic!("expected success, got {:?}", res),
    };
}

#[apply(test_clarity_versions)]
fn clarity_trait_experiments_call_full_double_trait(
    #[case] version: ClarityVersion,
    #[case] epoch: StacksEpochId,
) {
    let mut marf = MemoryBackingStore::new();
    let mut db = marf.as_analysis_db();

    // Can we call a contract where a function returns a trait?
    let result = db.execute(|db| {
        load_versioned(db, "double-trait", version, epoch)?;
        load_versioned(db, "impl-double-trait-2", version, epoch)?;
        load_versioned(db, "use-partial-double-trait-2", version, epoch)?;
        call_versioned(
            db,
            "use-partial-double-trait-2",
            "call-double",
            ".impl-double-trait-2",
            version,
            epoch,
        )
    });
    match result {
        Ok(_) if version == ClarityVersion::Clarity1 => (),
        Err(err) if version >= ClarityVersion::Clarity2 => {
            assert!(err.starts_with("DefineTraitDuplicateMethod(\"foo\")"))
        }
        res => panic!("got {:?}", res),
    };
}

#[apply(test_clarity_versions)]
fn clarity_trait_experiments_call_partial_double_trait(
    #[case] version: ClarityVersion,
    #[case] epoch: StacksEpochId,
) {
    let mut marf = MemoryBackingStore::new();
    let mut db = marf.as_analysis_db();

    // Can we call a contract where a function returns a trait?
    let result = db.execute(|db| {
        load_versioned(db, "double-trait", version, epoch)?;
        load_versioned(db, "partial-double-trait-2", version, epoch)?;
        load_versioned(db, "use-partial-double-trait-2", version, epoch)?;
        call_versioned(
            db,
            "use-partial-double-trait-2",
            "call-double",
            ".partial-double-trait-2",
            version,
            epoch,
        )
    });
    match result {
        Ok(_) if version == ClarityVersion::Clarity1 => (),
        Err(err) if version >= ClarityVersion::Clarity2 => {
            assert!(err.starts_with("DefineTraitDuplicateMethod(\"foo\")"))
        }
        res => panic!("got {:?}", res),
    };
}

#[apply(test_clarity_versions)]
fn clarity_trait_experiments_trait_recursion(
    #[case] version: ClarityVersion,
    #[case] epoch: StacksEpochId,
) {
    let mut marf = MemoryBackingStore::new();
    let mut db = marf.as_analysis_db();

    // This example shows how traits can induce the runtime to make a recursive (but terminating) call which is caught by the recursion checker at runtime.
    let result = db.execute(|db| {
        load_versioned(db, "simple-trait", version, epoch)?;
        load_versioned(db, "impl-simple-trait", version, epoch)?;
        load_versioned(db, "impl-simple-trait-2", version, epoch)?;
        call_versioned(
            db,
            "simple-trait",
            "call-simple",
            ".impl-simple-trait-2",
            version,
            epoch,
        )
    });
    match result {
        Ok(_) => (),
        res => panic!("expected success, got {:?}", res),
    };
}

// Additional tests using this framework
#[apply(test_clarity_versions)]
fn clarity_trait_experiments_principals_list_to_traits_list(
    #[case] version: ClarityVersion,
    #[case] epoch: StacksEpochId,
) {
    let mut marf = MemoryBackingStore::new();
    let mut db = marf.as_analysis_db();

    // This example shows how traits can induce the runtime to make a recursive (but terminating) call which is caught by the recursion checker at runtime.
    let result = db.execute(|db| {
        load_versioned(db, "math-trait", version, epoch)?;
        load_versioned(db, "impl-math-trait", version, epoch)?;
        load_versioned(db, "list-of-principals", version, epoch)
    });
    match result {
        Ok(_) if version >= ClarityVersion::Clarity2 => (),
        Err(err) if version == ClarityVersion::Clarity1 => {
            assert!(err.starts_with("TypeError(SequenceType(ListType"))
        }
        res => panic!("got {:?}", res),
    };
}

#[apply(test_clarity_versions)]
fn clarity_trait_experiments_traits_list_to_traits_list(
    #[case] version: ClarityVersion,
    #[case] epoch: StacksEpochId,
) {
    let mut marf = MemoryBackingStore::new();
    let mut db = marf.as_analysis_db();

    // This example shows how traits can induce the runtime to make a recursive (but terminating) call which is caught by the recursion checker at runtime.
    let result = db.execute(|db| {
        load_versioned(db, "math-trait", version, epoch)?;
        load_versioned(db, "impl-math-trait", version, epoch)?;
        load_versioned(db, "list-of-traits", version, epoch)
    });
    match result {
        Ok(_) => (),
        res => panic!("expected success, got {:?}", res),
    };
}

#[apply(test_clarity_versions)]
fn clarity_trait_experiments_mixed_list_to_traits_list(
    #[case] version: ClarityVersion,
    #[case] epoch: StacksEpochId,
) {
    let mut marf = MemoryBackingStore::new();
    let mut db = marf.as_analysis_db();

    // This example shows how traits can induce the runtime to make a recursive (but terminating) call which is caught by the recursion checker at runtime.
    let result = db.execute(|db| {
        load_versioned(db, "math-trait", version, epoch)?;
        load_versioned(db, "impl-math-trait", version, epoch)?;
        load_versioned(db, "mixed-list", version, epoch)
    });
    match result {
        Ok(_) if version >= ClarityVersion::Clarity2 => (),
        Err(err) if epoch <= StacksEpochId::Epoch2_05 => {
            assert!(err.starts_with("TypeError(TraitReferenceType"))
        }
        Err(err) if version == ClarityVersion::Clarity1 => {
            assert!(err.starts_with("TypeError(SequenceType(ListType"))
        }
        res => panic!("got {:?}", res),
    };
}

#[apply(test_clarity_versions)]
fn clarity_trait_experiments_double_trait_method1_v1(
    #[case] version: ClarityVersion,
    #[case] epoch: StacksEpochId,
) {
    let mut marf = MemoryBackingStore::new();
    let mut db = marf.as_analysis_db();

    // Can we define a trait with two methods with the same name and different
    // types and use the first method in Clarity1?
    let err = db
        .execute(|db| {
            load_versioned(
                db,
                "double-trait",
                ClarityVersion::Clarity1,
                StacksEpochId::Epoch21,
            )?;
            load_versioned(
                db,
                "impl-double-trait-2",
                ClarityVersion::Clarity1,
                StacksEpochId::Epoch21,
            )?;
            load_versioned(
                db,
                "use-partial-double-trait-1",
                ClarityVersion::Clarity1,
                StacksEpochId::Epoch21,
            )
        })
        .unwrap_err();
    assert!(err.starts_with("TypeError(BoolType, UIntType)"));
}

#[apply(test_clarity_versions)]
fn clarity_trait_experiments_double_trait_method2_v1(
    #[case] version: ClarityVersion,
    #[case] epoch: StacksEpochId,
) {
    let mut marf = MemoryBackingStore::new();
    let mut db = marf.as_analysis_db();

    // Can we define a trait with two methods with the same name and different
    // types and use it in Clarity1?
    let result = db.execute(|db| {
        load_versioned(
            db,
            "double-trait",
            ClarityVersion::Clarity1,
            StacksEpochId::Epoch21,
        )?;
        load_versioned(
            db,
            "impl-double-trait-2",
            ClarityVersion::Clarity1,
            StacksEpochId::Epoch21,
        )?;
        load_versioned(
            db,
            "use-partial-double-trait-2",
            ClarityVersion::Clarity1,
            StacksEpochId::Epoch21,
        )
    });
    match result {
        Ok(_) => (),
        res => panic!("expected success, got {:?}", res),
    };
}

#[apply(test_clarity_versions)]
fn clarity_trait_experiments_double_trait_method1_v1_v2(
    #[case] version: ClarityVersion,
    #[case] epoch: StacksEpochId,
) {
    let mut marf = MemoryBackingStore::new();
    let mut db = marf.as_analysis_db();

    // Can we define a trait with two methods with the same name and different
    // types and use the first method in Clarity1?
    let err = db
        .execute(|db| {
            load_versioned(
                db,
                "double-trait",
                ClarityVersion::Clarity1,
                StacksEpochId::Epoch21,
            )?;
            load_versioned(
                db,
                "impl-double-trait-2",
                ClarityVersion::Clarity1,
                StacksEpochId::Epoch21,
            )?;
            load_versioned(
                db,
                "use-partial-double-trait-1",
                ClarityVersion::Clarity2,
                StacksEpochId::Epoch21,
            )
        })
        .unwrap_err();
    assert!(err.starts_with("TypeError(BoolType, UIntType)"));
}

#[apply(test_clarity_versions)]
fn clarity_trait_experiments_double_trait_method2_v1_v2(
    #[case] version: ClarityVersion,
    #[case] epoch: StacksEpochId,
) {
    let mut marf = MemoryBackingStore::new();
    let mut db = marf.as_analysis_db();

    // Can we define a trait with two methods with the same name and different
    // types in Clarity1, then use it in Clarity2?
    let result = db.execute(|db| {
        load_versioned(
            db,
            "double-trait",
            ClarityVersion::Clarity1,
            StacksEpochId::Epoch21,
        )?;
        load_versioned(
            db,
            "impl-double-trait-2",
            ClarityVersion::Clarity1,
            StacksEpochId::Epoch21,
        )?;
        load_versioned(
            db,
            "use-partial-double-trait-2",
            ClarityVersion::Clarity2,
            StacksEpochId::Epoch21,
        )
    });
    match result {
        Ok(_) => (),
        res => panic!("expected success, got {:?}", res),
    };
}

#[cfg(test)]
impl From<CheckErrors> for String {
    fn from(o: CheckErrors) -> Self {
        o.to_string()
    }
}

#[apply(test_clarity_versions)]
fn clarity_trait_experiments_cross_epochs(
    #[case] version: ClarityVersion,
    #[case] epoch: StacksEpochId,
) {
    let mut marf = MemoryBackingStore::new();
    let mut db = marf.as_analysis_db();

    // Can we define a trait in epoch 2.05 that uses another trait, then use it in epoch 2.1?
    let result = db.execute(|db| {
        load_versioned(
            db,
            "math-trait",
            ClarityVersion::Clarity1,
            StacksEpochId::Epoch2_05,
        )?;
        load_versioned(
            db,
            "compute",
            ClarityVersion::Clarity1,
            StacksEpochId::Epoch2_05,
        )?;
        load_versioned(
            db,
            "impl-compute",
            ClarityVersion::Clarity1,
            StacksEpochId::Epoch2_05,
        )?;
        load_versioned(
            db,
            "impl-math-trait",
            ClarityVersion::Clarity1,
            StacksEpochId::Epoch2_05,
        )?;
        load_versioned(db, "use-compute", version, epoch)?;
        call_versioned(
            db,
            "use-compute",
            "do-it",
            ".impl-compute .impl-math-trait u1",
            version,
            StacksEpochId::Epoch21,
        )
    });
    match result {
        Ok(_) => (),
        res => panic!("expected success, got {:?}", res),
    };
}
