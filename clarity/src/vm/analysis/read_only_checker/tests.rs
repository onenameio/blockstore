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

use crate::vm::analysis::type_checker::v2_1::tests::mem_type_check;
use crate::vm::analysis::{type_check, CheckErrors};
use crate::vm::ast::parse;
use crate::vm::database::MemoryBackingStore;
use crate::vm::tests::test_clarity_versions;
use crate::vm::types::QualifiedContractIdentifier;
use crate::vm::ClarityVersion;

#[test]
fn test_argument_count_violations() {
    let examples = [
        (
            "(define-private (foo-bar)
           (at-block))",
            CheckErrors::IncorrectArgumentCount(2, 0),
        ),
        (
            "(define-private (foo-bar) (map-get?))",
            CheckErrors::IncorrectArgumentCount(2, 0),
        ),
    ];

    for (contract, expected) in examples.iter() {
        let err = mem_type_check(contract).unwrap_err();
        assert_eq!(&err.err, expected)
    }
}

#[test]
fn test_at_block_violations() {
    let examples = [
        "(define-data-var foo int 1)
         (define-private (foo-bar)
           (at-block (sha256 0)
             (var-set foo 0)))",
        // make sure that short-circuit evaluation isn't happening.
        // i.e., once (foo-bar) is known to be writing, `(at-block ..)`
        //  should trigger an error.
        "(define-data-var foo int 1)
         (define-private (foo-bar)
           (+ (begin (var-set foo 2) (var-get foo))
              (begin (at-block (sha256 0) (var-set foo 0)) (var-get foo))))",
        "(define-data-var foo int 1)
         (+ (begin (var-set foo 2) (var-get foo))
            (begin (at-block (sha256 0) (var-set foo 0)) (var-get foo)))",
        "(define-data-var foo int 1)
         (define-fungible-token bar (begin (at-block (sha256 0) (var-set foo 0)) 1))",
    ];

    for contract in examples.iter() {
        let err = mem_type_check(contract).unwrap_err();
        eprintln!("{}", err);
        assert_eq!(err.err, CheckErrors::AtBlockClosureMustBeReadOnly)
    }
}

#[test]
fn test_simple_read_only_violations() {
    // note -- these examples have _type errors_ in addition to read-only errors,
    //    but the read only error should end up taking precedence
    let bad_contracts = [
        "(define-map tokens { account: principal } { balance: int })
         (define-read-only (not-reading-only)
            (let ((balance (map-set tokens (tuple (account tx-sender))
                                              (tuple (balance 10)))))
                 (+ 1 2)))",
        "(define-map tokens { account: principal } { balance: int })
         (define-read-only (not-reading-only)
            (or (map-insert tokens (tuple (account tx-sender))
                                   { balance: 10, }) false))",
        "(define-map tokens { account: principal } { balance: int })
         (define-read-only (not-reading-only)
            (tuple (result (map-delete tokens (tuple (account tx-sender))))))",
        "(define-map tokens { account: principal } { balance: int })
         (define-private (func1) (map-set tokens (tuple (account tx-sender)) (tuple (balance 10))))
         (define-read-only (not-reading-only)
            (map func1 (list 1 2 3)))",
        "(define-map tokens { account: principal } { balance: int })
         (define-private (func1) (map-set tokens (tuple (account tx-sender)) (tuple (balance 10))))
         (define-read-only (not-reading-only)
            (map + (list 1 (map-set tokens (tuple (account tx-sender)) (tuple (balance 10))) 3)))",
        "(define-map tokens { account: principal } { balance: int })
         (define-private (update-balance-and-get-tx-sender)
            (begin
              (map-set tokens (tuple (account tx-sender)) (tuple (balance 10)))
              tx-sender))
         (define-read-only (get-token-balance)
            (map-get? tokens { account: (update-balance-and-get-tx-sender) }))",
        "(define-map tokens { account: principal } { balance: int })
         (define-private (update-balance-and-get-tx-sender)
            (begin
              (map-set tokens (tuple (account tx-sender)) (tuple (balance 10)))
              (tuple (account tx-sender))))
         (define-read-only (get-token-balance)
            (map-get? tokens (update-balance-and-get-tx-sender)))",
        "(define-map tokens { account: principal } { balance: int })
         (define-private (update-balance-and-get-tx-sender)
            (begin
              (map-set tokens (tuple (account tx-sender)) (tuple (balance 10)))
              tx-sender))
         (define-read-only (get-token-balance)
            (map-get? tokens { account: (update-balance-and-get-tx-sender) }))",
        "(define-map tokens { account: principal } { balance: int })
         (define-read-only (not-reading-only)
            (let ((x 1))
              (map-set tokens (tuple (account tx-sender)) (tuple (balance 10)))
              x))",
        "(define-map tokens { account: principal } { balance: int })
         (define-private (func1) (map-set tokens (tuple (account tx-sender)) (tuple (balance 10))))
         (define-read-only (not-reading-only)
            (fold func1 (list 1 2 3) 1))",
        "(define-map tokens { account: principal } { balance: int })
         (define-read-only (not-reading-only)
            (asserts! (map-insert tokens (tuple (account tx-sender))
                                             (tuple (balance 10))) false))",
        "(define-map tokens { account: principal } { balance: int })
         (define-private (func1) (begin (map-set tokens (tuple (account tx-sender)) (tuple (balance 10))) (list 1 2)))
         (define-read-only (not-reading-only)
            (len (func1)))",
        "(define-map tokens { account: principal } { balance: int })
         (define-private (func1) (begin (map-set tokens (tuple (account tx-sender)) (tuple (balance 10))) (list 1 2)))
         (define-read-only (not-reading-only)
            (append (func1) 3))",
        "(define-map tokens { account: principal } { balance: int })
         (define-private (func1) (begin (map-set tokens (tuple (account tx-sender)) (tuple (balance 10))) (list 1 2)))
         (define-read-only (not-reading-only)
            (concat (func1) (func1)))",
        "(define-map tokens { account: principal } { balance: int })
         (define-private (func1) (begin (map-set tokens (tuple (account tx-sender)) (tuple (balance 10))) (list 1 2)))
         (define-read-only (not-reading-only)
            (replace-at? (func1) u0 3))",
        "(define-map tokens { account: principal } { balance: int })
         (define-private (func1) (begin (map-set tokens (tuple (account tx-sender)) (tuple (balance 10))) (list 1 2)))
         (define-read-only (not-reading-only)
            (as-max-len? (func1) 3))",
        "(define-read-only (not-reading-only)
            (stx-burn? u10 tx-sender))",
        "(define-read-only (not-reading-only)
            (stx-transfer? u10 tx-sender tx-sender))",
    ];

    for contract in bad_contracts.iter() {
        let err = mem_type_check(contract).unwrap_err();
        assert_eq!(err.err, CheckErrors::WriteAttemptedInReadOnly)
    }
}

#[test]
fn test_nested_writing_closure() {
    let bad_contracts = [
        "(define-data-var cursor int 0)
        (define-public (bad-at-block-function)
            (begin
                (var-set cursor
                    (at-block 0x0101010101010101010101010101010101010101010101010101010101010101
                        ;; should be a read only error, caught in analysis, but it isn't                     
                        (begin (var-set cursor 1) 2)))
                (ok 1)))"
    ];

    for contract in bad_contracts.iter() {
        let err = mem_type_check(contract).unwrap_err();
        assert_eq!(err.err, CheckErrors::AtBlockClosureMustBeReadOnly)
    }
}

#[apply(test_clarity_versions)]
fn test_contract_call_read_only_violations(
    #[case] version: ClarityVersion,
    #[case] epoch: StacksEpochId,
) {
    let contract1 = "(define-map tokens { account: principal } { balance: int })
         (define-read-only (get-token-balance)
            (get balance (map-get? tokens (tuple (account tx-sender))) ))
         (define-public (mint)
            (begin
              (map-set tokens (tuple (account tx-sender))
                                              (tuple (balance 10)))
              (ok 1)))";
    let bad_caller = "(define-read-only (not-reading-only)
            (contract-call? .contract1 mint))";
    let ok_caller = "(define-read-only (is-reading-only)
            (is-eq 0 (unwrap! (contract-call? .contract1 get-token-balance) false)))";

    let contract_1_id = QualifiedContractIdentifier::local("contract1").unwrap();
    let contract_bad_caller_id = QualifiedContractIdentifier::local("bad_caller").unwrap();
    let contract_ok_caller_id = QualifiedContractIdentifier::local("ok_caller").unwrap();

    let mut contract1 = parse(&contract_1_id, contract1, version, epoch).unwrap();
    let mut bad_caller = parse(&contract_bad_caller_id, bad_caller, version, epoch).unwrap();
    let mut ok_caller = parse(&contract_ok_caller_id, ok_caller, version, epoch).unwrap();

    let mut marf = MemoryBackingStore::new();

    let mut db = marf.as_analysis_db();
    db.execute(|db| {
        db.test_insert_contract_hash(&contract_1_id);
        type_check(&contract_1_id, &mut contract1, db, true, &epoch, &version)
    })
    .unwrap();

    let err = db
        .execute(|db| {
            type_check(
                &contract_bad_caller_id,
                &mut bad_caller,
                db,
                true,
                &epoch,
                &version,
            )
        })
        .unwrap_err();
    assert_eq!(err.err, CheckErrors::WriteAttemptedInReadOnly);

    db.execute(|db| {
        type_check(
            &contract_ok_caller_id,
            &mut ok_caller,
            db,
            false,
            &epoch,
            &version,
        )
    })
    .unwrap();
}
