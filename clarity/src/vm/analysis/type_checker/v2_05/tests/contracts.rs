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

use assert_json_diff::assert_json_eq;
use stacks_common::types::StacksEpochId;
use {assert_json_diff, serde_json};

use crate::vm::analysis::contract_interface_builder::build_contract_interface;
use crate::vm::analysis::errors::CheckErrors;
use crate::vm::analysis::{mem_type_check, type_check};
use crate::vm::ast::parse;
use crate::vm::database::MemoryBackingStore;
use crate::vm::types::QualifiedContractIdentifier;
use crate::vm::ClarityVersion;

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

    let contract_analysis = mem_type_check(
        INTERFACE_TEST_CONTRACT,
        ClarityVersion::Clarity1,
        StacksEpochId::Epoch2_05,
    )
    .unwrap()
    .1;
    let test_contract_json_str = build_contract_interface(&contract_analysis)
        .unwrap()
        .serialize()
        .unwrap();
    let test_contract_json: serde_json::Value =
        serde_json::from_str(&test_contract_json_str).unwrap();

    let test_contract_json_expected: serde_json::Value = serde_json::from_str(r#"{
        "epoch": "Epoch2_05",
        "clarity_version": "Clarity1",
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
        "non_fungible_tokens": []
    }"#).unwrap();

    eprintln!("{}", test_contract_json_str);

    assert_json_eq!(test_contract_json, test_contract_json_expected);
}

#[test]
fn test_names_tokens_contracts() {
    let tokens_contract_id = QualifiedContractIdentifier::local("tokens").unwrap();
    let names_contract_id = QualifiedContractIdentifier::local("names").unwrap();

    let mut tokens_contract = parse(
        &tokens_contract_id,
        SIMPLE_TOKENS,
        ClarityVersion::Clarity1,
        StacksEpochId::Epoch2_05,
    )
    .unwrap();
    let mut names_contract = parse(
        &names_contract_id,
        SIMPLE_NAMES,
        ClarityVersion::Clarity1,
        StacksEpochId::Epoch2_05,
    )
    .unwrap();
    let mut marf = MemoryBackingStore::new();
    let mut db = marf.as_analysis_db();

    db.execute(|db| {
        type_check(
            &tokens_contract_id,
            &mut tokens_contract,
            db,
            true,
            &StacksEpochId::Epoch2_05,
            &ClarityVersion::Clarity1,
        )?;
        type_check(
            &names_contract_id,
            &mut names_contract,
            db,
            true,
            &StacksEpochId::Epoch2_05,
            &ClarityVersion::Clarity1,
        )
    })
    .unwrap();
}

#[test]
fn test_names_tokens_contracts_bad() {
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

    let mut tokens_contract = parse(
        &tokens_contract_id,
        SIMPLE_TOKENS,
        ClarityVersion::Clarity1,
        StacksEpochId::Epoch2_05,
    )
    .unwrap();
    let mut names_contract = parse(
        &names_contract_id,
        &names_contract,
        ClarityVersion::Clarity1,
        StacksEpochId::Epoch2_05,
    )
    .unwrap();
    let mut marf = MemoryBackingStore::new();
    let mut db = marf.as_analysis_db();

    db.execute(|db| {
        db.test_insert_contract_hash(&tokens_contract_id);
        type_check(
            &tokens_contract_id,
            &mut tokens_contract,
            db,
            true,
            &StacksEpochId::Epoch2_05,
            &ClarityVersion::Clarity1,
        )
    })
    .unwrap();

    let err = db
        .execute(|db| {
            type_check(
                &names_contract_id,
                &mut names_contract,
                db,
                true,
                &StacksEpochId::Epoch2_05,
                &ClarityVersion::Clarity1,
            )
        })
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
        let err = mem_type_check(contract, ClarityVersion::Clarity1, StacksEpochId::Epoch2_05)
            .unwrap_err();
        assert!(matches!(err.err, CheckErrors::TypeError(_, _)));
    }

    assert!(matches!(
        mem_type_check(
            unhandled_option,
            ClarityVersion::Clarity1,
            StacksEpochId::Epoch2_05
        )
        .unwrap_err()
        .err,
        CheckErrors::UnionTypeError(_, _)
    ));
}

#[test]
fn test_same_function_name() {
    let ca_id = QualifiedContractIdentifier::local("contract-a").unwrap();
    let cb_id = QualifiedContractIdentifier::local("contract-b").unwrap();

    let contract_b = "(define-read-only (foo-function (a int)) (+ a 1))";

    let contract_a = "(define-read-only (foo-function (a int))
           (contract-call? .contract-b foo-function a))";

    let mut ca = parse(
        &ca_id,
        contract_a,
        ClarityVersion::Clarity1,
        StacksEpochId::Epoch2_05,
    )
    .unwrap();
    let mut cb = parse(
        &cb_id,
        contract_b,
        ClarityVersion::Clarity1,
        StacksEpochId::Epoch2_05,
    )
    .unwrap();
    let mut marf = MemoryBackingStore::new();
    let mut db = marf.as_analysis_db();

    db.execute(|db| {
        type_check(
            &cb_id,
            &mut cb,
            db,
            true,
            &StacksEpochId::Epoch2_05,
            &ClarityVersion::Clarity1,
        )?;
        type_check(
            &ca_id,
            &mut ca,
            db,
            true,
            &StacksEpochId::Epoch2_05,
            &ClarityVersion::Clarity1,
        )
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

    mem_type_check(okay, ClarityVersion::Clarity1, StacksEpochId::Epoch2_05).unwrap();

    for unmatched_return_types in bad_return_types_tests.iter() {
        let err = mem_type_check(
            unmatched_return_types,
            ClarityVersion::Clarity1,
            StacksEpochId::Epoch2_05,
        )
        .unwrap_err();
        eprintln!("unmatched_return_types returned check error: {}", err);
        assert!(matches!(err.err, CheckErrors::ReturnTypesMustMatch(_, _)));
    }

    let err = mem_type_check(
        bad_default_type,
        ClarityVersion::Clarity1,
        StacksEpochId::Epoch2_05,
    )
    .unwrap_err();
    eprintln!("bad_default_types returned check error: {}", err);
    assert!(matches!(err.err, CheckErrors::DefaultTypesMustMatch(_, _)));

    let err = mem_type_check(
        notype_response_type,
        ClarityVersion::Clarity1,
        StacksEpochId::Epoch2_05,
    )
    .unwrap_err();
    eprintln!("notype_response_type returned check error: {}", err);
    assert!(matches!(
        err.err,
        CheckErrors::CouldNotDetermineResponseErrType
    ));

    let err = mem_type_check(
        notype_response_type_2,
        ClarityVersion::Clarity1,
        StacksEpochId::Epoch2_05,
    )
    .unwrap_err();
    eprintln!("notype_response_type_2 returned check error: {}", err);
    assert!(matches!(
        err.err,
        CheckErrors::CouldNotDetermineResponseOkType
    ));
}
