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

use crate::vm::analysis::errors::CheckErrors;
use crate::vm::analysis::{type_check, CheckError};
use crate::vm::ast::errors::ParseErrors;
use crate::vm::ast::{build_ast, parse};
use crate::vm::database::MemoryBackingStore;
use crate::vm::tests::test_clarity_versions;
use crate::vm::types::{QualifiedContractIdentifier, TypeSignature};
use crate::vm::ClarityVersion;

#[apply(test_clarity_versions)]
fn test_dynamic_dispatch_by_defining_trait(
    #[case] version: ClarityVersion,
    #[case] epoch: StacksEpochId,
) {
    let dispatching_contract_src = "(define-trait trait-1 (
            (get-1 (uint) (response uint uint))))
        (define-public (wrapped-get-1 (contract <trait-1>))
            (contract-call? contract get-1 u0))";
    let target_contract_src = "(define-public (get-1 (x uint)) (ok u1))";

    let dispatching_contract_id =
        QualifiedContractIdentifier::local("dispatching-contract").unwrap();
    let target_contract_id = QualifiedContractIdentifier::local("target-contract").unwrap();

    let mut dispatching_contract = parse(
        &dispatching_contract_id,
        dispatching_contract_src,
        version,
        epoch,
    )
    .unwrap();
    let mut target_contract =
        parse(&target_contract_id, target_contract_src, version, epoch).unwrap();
    let mut marf = MemoryBackingStore::new();
    let mut db = marf.as_analysis_db();

    db.execute(|db| {
        type_check(
            &dispatching_contract_id,
            &mut dispatching_contract,
            db,
            true,
            &epoch,
            &version,
        )?;
        type_check(
            &target_contract_id,
            &mut target_contract,
            db,
            true,
            &epoch,
            &version,
        )
    })
    .unwrap();
}

#[apply(test_clarity_versions)]
fn test_incomplete_impl_trait_1(#[case] version: ClarityVersion, #[case] epoch: StacksEpochId) {
    let contract_defining_trait = "(define-trait trait-1 (
            (get-1 (uint) (response uint uint))
            (get-2 (uint) (response uint uint))
            (get-3 (uint) (response uint uint))))";
    let impl_contract = "(impl-trait .defun.trait-1)
        (define-public (get-1 (x uint)) (ok u1))";
    let def_contract_id = QualifiedContractIdentifier::local("defun").unwrap();
    let impl_contract_id = QualifiedContractIdentifier::local("implem").unwrap();
    let mut c1 = parse(&def_contract_id, contract_defining_trait, version, epoch).unwrap();
    let mut c3 = parse(&impl_contract_id, impl_contract, version, epoch).unwrap();
    let mut marf = MemoryBackingStore::new();
    let mut db = marf.as_analysis_db();
    let err = db
        .execute(|db| {
            type_check(&def_contract_id, &mut c1, db, true, &epoch, &version).unwrap();
            type_check(&impl_contract_id, &mut c3, db, true, &epoch, &version)
        })
        .unwrap_err();
    match err.err {
        CheckErrors::BadTraitImplementation(_, _) => {}
        _ => panic!("{:?}", err),
    }
}

#[apply(test_clarity_versions)]
fn test_incomplete_impl_trait_2(#[case] version: ClarityVersion, #[case] epoch: StacksEpochId) {
    let contract_defining_trait = "(define-trait trait-1 (
            (get-1 (uint) (response uint uint))
            (get-2 (uint) (response uint uint))
            (get-3 (uint) (response uint uint))))";
    let impl_contract = "(impl-trait .defun.trait-1)
        (define-public (get-1 (x uint)) (ok u1))
        (define-public (get-2 (x uint)) (ok u1))";
    let def_contract_id = QualifiedContractIdentifier::local("defun").unwrap();
    let impl_contract_id = QualifiedContractIdentifier::local("implem").unwrap();
    let mut c1 = parse(&def_contract_id, contract_defining_trait, version, epoch).unwrap();
    let mut c3 = parse(&impl_contract_id, impl_contract, version, epoch).unwrap();
    let mut marf = MemoryBackingStore::new();
    let mut db = marf.as_analysis_db();
    let err = db
        .execute(|db| {
            type_check(&def_contract_id, &mut c1, db, true, &epoch, &version).unwrap();
            type_check(&impl_contract_id, &mut c3, db, true, &epoch, &version)
        })
        .unwrap_err();
    match err.err {
        CheckErrors::BadTraitImplementation(_, _) => {}
        _ => panic!("{:?}", err),
    }
}

#[apply(test_clarity_versions)]
fn test_impl_trait_arg_admission_1(#[case] version: ClarityVersion, #[case] epoch: StacksEpochId) {
    let contract_defining_trait = "(define-trait trait-1 (
            (get-1 ((list 10 uint)) (response uint uint))))";
    let impl_contract = "(impl-trait .defun.trait-1)
        (define-public (get-1 (x (list 5 uint))) (ok u1))";
    let def_contract_id = QualifiedContractIdentifier::local("defun").unwrap();
    let impl_contract_id = QualifiedContractIdentifier::local("implem").unwrap();
    let mut c1 = parse(&def_contract_id, contract_defining_trait, version, epoch).unwrap();
    let mut c3 = parse(&impl_contract_id, impl_contract, version, epoch).unwrap();
    let mut marf = MemoryBackingStore::new();
    let mut db = marf.as_analysis_db();
    let err = db
        .execute(|db| {
            type_check(&def_contract_id, &mut c1, db, true, &epoch, &version).unwrap();
            type_check(&impl_contract_id, &mut c3, db, true, &epoch, &version)
        })
        .unwrap_err();
    match err.err {
        CheckErrors::BadTraitImplementation(_, _) => {}
        _ => panic!("{:?}", err),
    }
}

#[apply(test_clarity_versions)]
fn test_impl_trait_arg_admission_2(#[case] version: ClarityVersion, #[case] epoch: StacksEpochId) {
    let contract_defining_trait = "(define-trait trait-1 (
            (get-1 ((list 5 uint)) (response uint uint))))";
    let impl_contract = "(impl-trait .defun.trait-1)
        (define-public (get-1 (x (list 15 uint))) (ok u1))";
    let def_contract_id = QualifiedContractIdentifier::local("defun").unwrap();
    let impl_contract_id = QualifiedContractIdentifier::local("implem").unwrap();
    let mut c1 = parse(&def_contract_id, contract_defining_trait, version, epoch).unwrap();
    let mut c3 = parse(&impl_contract_id, impl_contract, version, epoch).unwrap();
    let mut marf = MemoryBackingStore::new();
    let mut db = marf.as_analysis_db();
    db.execute(|db| {
        type_check(&def_contract_id, &mut c1, db, true, &epoch, &version).unwrap();
        type_check(&impl_contract_id, &mut c3, db, true, &epoch, &version)
    })
    .unwrap();
}

#[apply(test_clarity_versions)]
fn test_impl_trait_arg_admission_3(#[case] version: ClarityVersion, #[case] epoch: StacksEpochId) {
    let contract_defining_trait = "(define-trait trait-1 (
            (get-1 ((list 5 uint)) (response uint uint))))";
    let impl_contract = "(impl-trait .defun.trait-1)
        (define-public (get-1 (x (list 5 uint))) (ok u1))";
    let def_contract_id = QualifiedContractIdentifier::local("defun").unwrap();
    let impl_contract_id = QualifiedContractIdentifier::local("implem").unwrap();
    let mut c1 = parse(&def_contract_id, contract_defining_trait, version, epoch).unwrap();
    let mut c3 = parse(&impl_contract_id, impl_contract, version, epoch).unwrap();
    let mut marf = MemoryBackingStore::new();
    let mut db = marf.as_analysis_db();
    db.execute(|db| {
        type_check(&def_contract_id, &mut c1, db, true, &epoch, &version).unwrap();
        type_check(&impl_contract_id, &mut c3, db, true, &epoch, &version)
    })
    .unwrap();
}

#[apply(test_clarity_versions)]
fn test_complete_impl_trait(#[case] version: ClarityVersion, #[case] epoch: StacksEpochId) {
    let contract_defining_trait = "(define-trait trait-1 (
            (get-1 (uint) (response uint uint))
            (get-2 (uint) (response uint uint))
            (get-3 (uint) (response uint uint))))";
    let impl_contract = "(impl-trait .defun.trait-1)
        (define-public (get-1 (x uint)) (ok u1))
        (define-public (get-2 (x uint)) (ok u1))
        (define-public (get-3 (x uint)) (ok u1))";
    let def_contract_id = QualifiedContractIdentifier::local("defun").unwrap();
    let impl_contract_id = QualifiedContractIdentifier::local("implem").unwrap();
    let mut c1 = parse(&def_contract_id, contract_defining_trait, version, epoch).unwrap();
    let mut c3 = parse(&impl_contract_id, impl_contract, version, epoch).unwrap();
    let mut marf = MemoryBackingStore::new();
    let mut db = marf.as_analysis_db();
    db.execute(|db| {
        type_check(&def_contract_id, &mut c1, db, true, &epoch, &version).unwrap();
        type_check(&impl_contract_id, &mut c3, db, true, &epoch, &version)
    })
    .unwrap();
}

#[apply(test_clarity_versions)]
fn test_complete_impl_trait_mixing_readonly(
    #[case] version: ClarityVersion,
    #[case] epoch: StacksEpochId,
) {
    let contract_defining_trait = "(define-trait trait-1 (
            (get-1 (uint) (response uint uint))
            (get-2 (uint) (response uint uint))
            (get-3 (uint) (response uint uint))))";
    let impl_contract = "(impl-trait .defun.trait-1)
        (define-public (get-1 (x uint)) (ok u1))
        (define-read-only (get-2 (x uint)) (ok u1))
        (define-read-only (get-3 (x uint)) (ok u1))";
    let def_contract_id = QualifiedContractIdentifier::local("defun").unwrap();
    let impl_contract_id = QualifiedContractIdentifier::local("implem").unwrap();
    let mut c1 = parse(&def_contract_id, contract_defining_trait, version, epoch).unwrap();
    let mut c3 = parse(&impl_contract_id, impl_contract, version, epoch).unwrap();
    let mut marf = MemoryBackingStore::new();
    let mut db = marf.as_analysis_db();
    db.execute(|db| {
        type_check(&def_contract_id, &mut c1, db, true, &epoch, &version).unwrap();
        type_check(&impl_contract_id, &mut c3, db, true, &epoch, &version)
    })
    .unwrap();
}

#[apply(test_clarity_versions)]
fn test_get_trait_reference_from_tuple(
    #[case] version: ClarityVersion,
    #[case] epoch: StacksEpochId,
) {
    let dispatching_contract_src = "(define-trait trait-1 (
            (get-1 (uint) (response uint uint))))
        (define-public (wrapped-get-1 (wrapped-contract (tuple (contract <trait-1>))))
            (contract-call? (get contract wrapped-contract) get-1 u0))";
    let target_contract_src = "(define-public (get-1 (x uint)) (ok u1))";

    let dispatching_contract_id =
        QualifiedContractIdentifier::local("dispatching-contract").unwrap();
    let target_contract_id = QualifiedContractIdentifier::local("target-contract").unwrap();

    let mut dispatching_contract = parse(
        &dispatching_contract_id,
        dispatching_contract_src,
        version,
        epoch,
    )
    .unwrap();
    let mut target_contract =
        parse(&target_contract_id, target_contract_src, version, epoch).unwrap();
    let mut marf = MemoryBackingStore::new();
    let mut db = marf.as_analysis_db();

    let err = db
        .execute(|db| {
            type_check(
                &dispatching_contract_id,
                &mut dispatching_contract,
                db,
                true,
                &epoch,
                &version,
            )?;
            type_check(
                &target_contract_id,
                &mut target_contract,
                db,
                true,
                &epoch,
                &version,
            )
        })
        .unwrap_err();
    match err.err {
        CheckErrors::ContractCallExpectName => {}
        _ => panic!("{:?}", err),
    }
}

#[apply(test_clarity_versions)]
fn test_dynamic_dispatch_by_defining_and_impl_trait(
    #[case] version: ClarityVersion,
    #[case] epoch: StacksEpochId,
) {
    let dispatching_contract_src = "(define-trait trait-1 (
            (get-1 (uint) (response uint uint))))
        (impl-trait .dispatching-contract.trait-1)
        (define-public (wrapped-get-1 (contract <trait-1>))
            (contract-call? contract get-1 u0))
        (define-public (get-1 (x uint)) (ok u1))";

    let dispatching_contract_id =
        QualifiedContractIdentifier::local("dispatching-contract").unwrap();

    let mut dispatching_contract = parse(
        &dispatching_contract_id,
        dispatching_contract_src,
        version,
        epoch,
    )
    .unwrap();
    let mut marf = MemoryBackingStore::new();
    let mut db = marf.as_analysis_db();

    let err = db
        .execute(|db| {
            type_check(
                &dispatching_contract_id,
                &mut dispatching_contract,
                db,
                true,
                &epoch,
                &version,
            )
        })
        .unwrap_err();
    match err.err {
        CheckErrors::TraitReferenceUnknown(_) => {}
        _ => panic!("{:?}", err),
    }
}

#[apply(test_clarity_versions)]
fn test_define_map_storing_trait_references(
    #[case] version: ClarityVersion,
    #[case] epoch: StacksEpochId,
) {
    let dispatching_contract_src = "(define-trait trait-1 (
            (get-1 (uint) (response uint uint))))
        (define-map kv-store { key: uint } { value: <trait-1> })";

    let dispatching_contract_id =
        QualifiedContractIdentifier::local("dispatching-contract").unwrap();

    let err = build_ast(
        &dispatching_contract_id,
        dispatching_contract_src,
        &mut (),
        version,
        epoch,
    )
    .unwrap_err();

    match err.err {
        ParseErrors::TraitReferenceNotAllowed => {}
        _ => panic!("{:?}", err),
    }
}

#[apply(test_clarity_versions)]
fn test_cycle_in_traits_1_contract(#[case] version: ClarityVersion, #[case] epoch: StacksEpochId) {
    let dispatching_contract_src = "(define-trait trait-1 (
            (get-1 (<trait-2>) (response uint uint))))
        (define-trait trait-2 (
            (get-2 (<trait-1>) (response uint uint))))";

    let dispatching_contract_id =
        QualifiedContractIdentifier::local("dispatching-contract").unwrap();

    let err = build_ast(
        &dispatching_contract_id,
        dispatching_contract_src,
        &mut (),
        version,
        epoch,
    )
    .unwrap_err();
    match err.err {
        ParseErrors::CircularReference(_) => {}
        _ => panic!("{:?}", err),
    }
}

#[apply(test_clarity_versions)]
fn test_cycle_in_traits_2_contracts(#[case] version: ClarityVersion, #[case] epoch: StacksEpochId) {
    let dispatching_contract_src = "(use-trait trait-2 .target-contract.trait-2)
        (define-trait trait-1 (
            (get-1 (<trait-2>) (response uint uint))))";
    let target_contract_src = "(use-trait trait-1 .dispatching-contract.trait-1)
        (define-trait trait-2 (
            (get-2 (<trait-1>) (response uint uint))))";

    let dispatching_contract_id =
        QualifiedContractIdentifier::local("dispatching-contract").unwrap();
    let target_contract_id = QualifiedContractIdentifier::local("target-contract").unwrap();

    let mut dispatching_contract = parse(
        &dispatching_contract_id,
        dispatching_contract_src,
        version,
        epoch,
    )
    .unwrap();
    let mut target_contract =
        parse(&target_contract_id, target_contract_src, version, epoch).unwrap();
    let mut marf = MemoryBackingStore::new();
    let mut db = marf.as_analysis_db();

    let err = db
        .execute(|db| {
            type_check(
                &dispatching_contract_id,
                &mut dispatching_contract,
                db,
                true,
                &epoch,
                &version,
            )?;
            type_check(
                &target_contract_id,
                &mut target_contract,
                db,
                true,
                &epoch,
                &version,
            )
        })
        .unwrap_err();
    match err.err {
        CheckErrors::NoSuchContract(_) => {}
        _ => panic!("{:?}", err),
    }
}

#[apply(test_clarity_versions)]
fn test_dynamic_dispatch_unknown_method(
    #[case] version: ClarityVersion,
    #[case] epoch: StacksEpochId,
) {
    let dispatching_contract_src = "(define-trait trait-1 (
            (get-1 (uint) (response uint uint))))
        (define-public (wrapped-get-1 (contract <trait-1>))
            (contract-call? contract get-2 u0))";
    let target_contract_src = "(define-public (get-1 (x uint)) (ok u1))";

    let dispatching_contract_id =
        QualifiedContractIdentifier::local("dispatching-contract").unwrap();
    let target_contract_id = QualifiedContractIdentifier::local("target-contract").unwrap();

    let mut dispatching_contract = parse(
        &dispatching_contract_id,
        dispatching_contract_src,
        version,
        epoch,
    )
    .unwrap();
    let mut target_contract =
        parse(&target_contract_id, target_contract_src, version, epoch).unwrap();
    let mut marf = MemoryBackingStore::new();
    let mut db = marf.as_analysis_db();

    let err = db
        .execute(|db| {
            type_check(
                &dispatching_contract_id,
                &mut dispatching_contract,
                db,
                true,
                &epoch,
                &version,
            )?;
            type_check(
                &target_contract_id,
                &mut target_contract,
                db,
                true,
                &epoch,
                &version,
            )
        })
        .unwrap_err();
    match err.err {
        CheckErrors::TraitMethodUnknown(_, _) => {}
        _ => panic!("{:?}", err),
    }
}

#[apply(test_clarity_versions)]
fn test_nested_literal_implicitly_compliant(
    #[case] version: ClarityVersion,
    #[case] epoch: StacksEpochId,
) {
    let dispatching_contract_src = "(define-trait trait-1 (
            (get-1 (uint) (response uint uint))))
        (define-public (wrapped-get-1 (contract <trait-1>))
            (contract-call? contract get-1 u0))";
    let nested_target_contract_src = "(define-public (get-1 (x uint)) (ok u1))";
    let target_contract_src =
        "(define-public (get-1 (x uint)) (contract-call? .dispatching-contract wrapped-get-1 .nested-target-contract))";

    let dispatching_contract_id =
        QualifiedContractIdentifier::local("dispatching-contract").unwrap();
    let target_contract_id = QualifiedContractIdentifier::local("target-contract").unwrap();
    let nested_target_contract_id =
        QualifiedContractIdentifier::local("nested-target-contract").unwrap();

    let mut dispatching_contract = parse(
        &dispatching_contract_id,
        dispatching_contract_src,
        version,
        epoch,
    )
    .unwrap();
    let mut target_contract =
        parse(&target_contract_id, target_contract_src, version, epoch).unwrap();
    let mut nested_target_contract = parse(
        &nested_target_contract_id,
        nested_target_contract_src,
        version,
        epoch,
    )
    .unwrap();

    let mut marf = MemoryBackingStore::new();
    let mut db = marf.as_analysis_db();

    db.execute(|db| {
        type_check(
            &dispatching_contract_id,
            &mut dispatching_contract,
            db,
            true,
            &epoch,
            &version,
        )?;
        type_check(
            &nested_target_contract_id,
            &mut nested_target_contract,
            db,
            true,
            &epoch,
            &version,
        )?;
        type_check(
            &target_contract_id,
            &mut target_contract,
            db,
            true,
            &epoch,
            &version,
        )
    })
    .unwrap();
}

#[apply(test_clarity_versions)]
fn test_passing_trait_reference_instances(
    #[case] version: ClarityVersion,
    #[case] epoch: StacksEpochId,
) {
    let dispatching_contract_src = "(define-trait trait-1 (
            (get-1 (uint) (response uint uint))))
        (define-public (wrapped-get-1 (contract <trait-1>))
            (internal-get-1 contract))
        (define-public (internal-get-1 (contract <trait-1>))
            (ok u1))";

    let dispatching_contract_id =
        QualifiedContractIdentifier::local("dispatching-contract").unwrap();

    let mut dispatching_contract = parse(
        &dispatching_contract_id,
        dispatching_contract_src,
        version,
        epoch,
    )
    .unwrap();
    let mut marf = MemoryBackingStore::new();
    let mut db = marf.as_analysis_db();

    db.execute(|db| {
        type_check(
            &dispatching_contract_id,
            &mut dispatching_contract,
            db,
            true,
            &epoch,
            &version,
        )
    })
    .unwrap();
}

#[apply(test_clarity_versions)]
fn test_passing_nested_trait_reference_instances(
    #[case] version: ClarityVersion,
    #[case] epoch: StacksEpochId,
) {
    let dispatching_contract_src = "(define-trait trait-1 (
            (get-1 (uint) (response uint uint))))
        (define-public (wrapped-get-1 (value bool) (contract <trait-1>))
            (let ((amount u0))
              (internal-get-1 contract)))
        (define-public (internal-get-1 (contract <trait-1>))
            (ok u1))";

    let dispatching_contract_id =
        QualifiedContractIdentifier::local("dispatching-contract").unwrap();

    let mut dispatching_contract = parse(
        &dispatching_contract_id,
        dispatching_contract_src,
        version,
        epoch,
    )
    .unwrap();
    let mut marf = MemoryBackingStore::new();
    let mut db = marf.as_analysis_db();

    db.execute(|db| {
        type_check(
            &dispatching_contract_id,
            &mut dispatching_contract,
            db,
            true,
            &epoch,
            &version,
        )
    })
    .unwrap();
}

#[apply(test_clarity_versions)]
fn test_dynamic_dispatch_collision_trait(
    #[case] version: ClarityVersion,
    #[case] epoch: StacksEpochId,
) {
    let contract_defining_trait_src = "(define-trait trait-1 (
            (get-1 (uint) (response uint uint))))";
    let dispatching_contract_src = "(use-trait trait-1 .contract-defining-trait.trait-1)
        (define-trait trait-1 (
            (get-1 (uint) (response uint uint))))
        (define-public (wrapped-get-1 (contract <trait-1>))
            (contract-call? contract get-1 u0))";

    let contract_defining_trait_id =
        QualifiedContractIdentifier::local("contract-defining-trait").unwrap();
    let dispatching_contract_id =
        QualifiedContractIdentifier::local("dispatching-contract").unwrap();

    let _contract_defining_trait = parse(
        &contract_defining_trait_id,
        contract_defining_trait_src,
        version,
        epoch,
    )
    .unwrap();
    let err = build_ast(
        &dispatching_contract_id,
        dispatching_contract_src,
        &mut (),
        version,
        epoch,
    )
    .unwrap_err();
    match err.err {
        ParseErrors::NameAlreadyUsed(_) => {}
        _ => panic!("{:?}", err),
    }
}

#[apply(test_clarity_versions)]
fn test_dynamic_dispatch_collision_defined_trait(
    #[case] version: ClarityVersion,
    #[case] epoch: StacksEpochId,
) {
    let dispatching_contract_src = "(define-trait trait-1 (
            (get-1 (uint) (response uint uint))))
        (define-trait trait-1 (
            (get-1 (int) (response uint uint))))
        (define-public (wrapped-get-1 (contract <trait-1>))
            (contract-call? contract get-1 u0))";

    let dispatching_contract_id =
        QualifiedContractIdentifier::local("dispatching-contract").unwrap();

    let err = build_ast(
        &dispatching_contract_id,
        dispatching_contract_src,
        &mut (),
        version,
        epoch,
    )
    .unwrap_err();
    match err.err {
        ParseErrors::NameAlreadyUsed(_) => {}
        _ => panic!("{:?}", err),
    }
}

#[apply(test_clarity_versions)]
fn test_dynamic_dispatch_collision_imported_trait(
    #[case] version: ClarityVersion,
    #[case] epoch: StacksEpochId,
) {
    let contract_defining_trait_src = "(define-trait trait-1 (
            (get-1 (uint) (response uint uint))))
         (define-trait trait-2 (
            (get-1 (uint) (response uint uint))))";
    let dispatching_contract_src = "(use-trait trait-1 .contract-defining-trait.trait-1)
        (use-trait trait-1 .contract-defining-trait.trait-2)
        (define-public (wrapped-get-1 (contract <trait-1>))
            (contract-call? contract get-1 u0))";

    let contract_defining_trait_id =
        QualifiedContractIdentifier::local("contract-defining-trait").unwrap();
    let dispatching_contract_id =
        QualifiedContractIdentifier::local("dispatching-contract").unwrap();

    let _contract_defining_trait = parse(
        &contract_defining_trait_id,
        contract_defining_trait_src,
        version,
        epoch,
    )
    .unwrap();
    let err = build_ast(
        &dispatching_contract_id,
        dispatching_contract_src,
        &mut (),
        version,
        epoch,
    )
    .unwrap_err();
    match err.err {
        ParseErrors::NameAlreadyUsed(_) => {}
        _ => panic!("{:?}", err),
    }
}

#[apply(test_clarity_versions)]
fn test_dynamic_dispatch_importing_non_existant_trait(
    #[case] version: ClarityVersion,
    #[case] epoch: StacksEpochId,
) {
    let contract_defining_trait_src = "(define-trait trait-1 (
            (get-1 (uint) (response uint uint))))";
    let dispatching_contract_src = "(use-trait trait-1 .contract-defining-trait.trait-2)
        (define-public (wrapped-get-1 (contract <trait-1>))
            (contract-call? contract get-1 u0))";
    let target_contract_src = "(impl-trait .contract-defining-trait.trait-2)
        (define-public (get-1 (x uint)) (ok u1))";

    let contract_defining_trait_id =
        QualifiedContractIdentifier::local("contract-defining-trait").unwrap();
    let dispatching_contract_id =
        QualifiedContractIdentifier::local("dispatching-contract").unwrap();
    let target_contract_id = QualifiedContractIdentifier::local("target-contract").unwrap();

    let mut contract_defining_trait = parse(
        &contract_defining_trait_id,
        contract_defining_trait_src,
        version,
        epoch,
    )
    .unwrap();
    let mut dispatching_contract = parse(
        &dispatching_contract_id,
        dispatching_contract_src,
        version,
        epoch,
    )
    .unwrap();
    let mut target_contract =
        parse(&target_contract_id, target_contract_src, version, epoch).unwrap();
    let mut marf = MemoryBackingStore::new();
    let mut db = marf.as_analysis_db();

    let err = db
        .execute(|db| {
            type_check(
                &contract_defining_trait_id,
                &mut contract_defining_trait,
                db,
                true,
                &epoch,
                &version,
            )?;
            type_check(
                &dispatching_contract_id,
                &mut dispatching_contract,
                db,
                true,
                &epoch,
                &version,
            )?;
            type_check(
                &target_contract_id,
                &mut target_contract,
                db,
                true,
                &epoch,
                &version,
            )
        })
        .unwrap_err();
    match err.err {
        CheckErrors::TraitReferenceUnknown(_) => {}
        _ => panic!("{:?}", err),
    }
}

#[apply(test_clarity_versions)]
fn test_dynamic_dispatch_importing_trait(
    #[case] version: ClarityVersion,
    #[case] epoch: StacksEpochId,
) {
    let contract_defining_trait_src = "(define-trait trait-1 (
            (get-1 (uint) (response uint uint))))";
    let dispatching_contract_src = "(use-trait trait-1 .contract-defining-trait.trait-1)
        (define-public (wrapped-get-1 (contract <trait-1>))
            (contract-call? contract get-1 u0))";
    let target_contract_src = "(impl-trait .contract-defining-trait.trait-1)
        (define-public (get-1 (x uint)) (ok u1))";

    let contract_defining_trait_id =
        QualifiedContractIdentifier::local("contract-defining-trait").unwrap();
    let dispatching_contract_id =
        QualifiedContractIdentifier::local("dispatching-contract").unwrap();
    let target_contract_id = QualifiedContractIdentifier::local("target-contract").unwrap();

    let mut contract_defining_trait = parse(
        &contract_defining_trait_id,
        contract_defining_trait_src,
        version,
        epoch,
    )
    .unwrap();
    let mut dispatching_contract = parse(
        &dispatching_contract_id,
        dispatching_contract_src,
        version,
        epoch,
    )
    .unwrap();
    let mut target_contract =
        parse(&target_contract_id, target_contract_src, version, epoch).unwrap();
    let mut marf = MemoryBackingStore::new();
    let mut db = marf.as_analysis_db();

    db.execute(|db| {
        type_check(
            &contract_defining_trait_id,
            &mut contract_defining_trait,
            db,
            true,
            &epoch,
            &version,
        )?;
        type_check(
            &dispatching_contract_id,
            &mut dispatching_contract,
            db,
            true,
            &epoch,
            &version,
        )?;
        type_check(
            &target_contract_id,
            &mut target_contract,
            db,
            true,
            &epoch,
            &version,
        )
    })
    .unwrap();
}

#[apply(test_clarity_versions)]
fn test_dynamic_dispatch_including_nested_trait(
    #[case] version: ClarityVersion,
    #[case] epoch: StacksEpochId,
) {
    let contract_defining_nested_trait_src = "(define-trait trait-a (
        (get-a (uint) (response uint uint))))";
    let contract_defining_trait_src = "(use-trait trait-Z .contract-defining-nested-trait.trait-a)
        (define-trait trait-1 (
            (get-1 (<trait-Z>) (response uint uint))))";
    let dispatching_contract_src = "(use-trait trait-Y .contract-defining-nested-trait.trait-a)
         (use-trait trait-X .contract-defining-trait.trait-1)
         (define-public (wrapped-get-1 (contract <trait-X>) (nested-contract <trait-Y>))
            (contract-call? contract get-1 nested-contract))";
    let target_contract_src = "(use-trait trait-X .contract-defining-nested-trait.trait-a)
        (define-public (get-1 (nested-contract <trait-X>))
            (contract-call? nested-contract get-a u0))";
    let target_nested_contract_src = "(define-public (get-a (x uint)) (ok u99))";

    let contract_defining_trait_id =
        QualifiedContractIdentifier::local("contract-defining-trait").unwrap();
    let dispatching_contract_id =
        QualifiedContractIdentifier::local("dispatching-contract").unwrap();
    let target_contract_id = QualifiedContractIdentifier::local("target-contract").unwrap();
    let contract_defining_nested_trait_id =
        QualifiedContractIdentifier::local("contract-defining-nested-trait").unwrap();
    let target_nested_contract_id =
        QualifiedContractIdentifier::local("target-nested-contract").unwrap();

    let mut contract_defining_trait = parse(
        &contract_defining_trait_id,
        contract_defining_trait_src,
        version,
        epoch,
    )
    .unwrap();
    let mut dispatching_contract = parse(
        &dispatching_contract_id,
        dispatching_contract_src,
        version,
        epoch,
    )
    .unwrap();
    let mut target_contract =
        parse(&target_contract_id, target_contract_src, version, epoch).unwrap();
    let mut contract_defining_nested_trait = parse(
        &contract_defining_nested_trait_id,
        contract_defining_nested_trait_src,
        version,
        epoch,
    )
    .unwrap();
    let mut target_nested_contract = parse(
        &target_nested_contract_id,
        target_nested_contract_src,
        version,
        epoch,
    )
    .unwrap();
    let mut marf = MemoryBackingStore::new();
    let mut db = marf.as_analysis_db();

    db.execute(|db| {
        type_check(
            &contract_defining_nested_trait_id,
            &mut contract_defining_nested_trait,
            db,
            true,
            &epoch,
            &version,
        )?;
        type_check(
            &contract_defining_trait_id,
            &mut contract_defining_trait,
            db,
            true,
            &epoch,
            &version,
        )?;
        type_check(
            &dispatching_contract_id,
            &mut dispatching_contract,
            db,
            true,
            &epoch,
            &version,
        )?;
        type_check(
            &target_contract_id,
            &mut target_contract,
            db,
            true,
            &epoch,
            &version,
        )?;
        type_check(
            &target_nested_contract_id,
            &mut target_nested_contract,
            db,
            true,
            &epoch,
            &version,
        )
    })
    .unwrap();
}

#[apply(test_clarity_versions)]
fn test_dynamic_dispatch_including_wrong_nested_trait(
    #[case] version: ClarityVersion,
    #[case] epoch: StacksEpochId,
) {
    let contract_defining_nested_trait_src = "(define-trait trait-a (
        (get-a (uint) (response uint uint))))";
    let contract_defining_trait_src = "(use-trait trait-a .contract-defining-nested-trait.trait-a)
        (define-trait trait-1 (
            (get-1 (<trait-a>) (response uint uint))))";
    let dispatching_contract_src = "(use-trait trait-1 .contract-defining-trait.trait-1)
         (use-trait trait-a .contract-defining-trait.trait-a)
         (define-public (wrapped-get-1 (contract <trait-1>) (nested-contract <trait-1>))
            (contract-call? contract get-1 nested-contract))";
    let target_contract_src = "(use-trait trait-a .contract-defining-nested-trait.trait-a)
        (define-public (get-1 (nested-contract <trait-a>))
            (contract-call? nested-contract get-a u0))";
    let target_nested_contract_src = "(define-public (get-a (x uint)) (ok u99))";

    let contract_defining_trait_id =
        QualifiedContractIdentifier::local("contract-defining-trait").unwrap();
    let dispatching_contract_id =
        QualifiedContractIdentifier::local("dispatching-contract").unwrap();
    let target_contract_id = QualifiedContractIdentifier::local("target-contract").unwrap();
    let contract_defining_nested_trait_id =
        QualifiedContractIdentifier::local("contract-defining-nested-trait").unwrap();
    let target_nested_contract_id =
        QualifiedContractIdentifier::local("target-nested-contract").unwrap();

    let mut contract_defining_trait = parse(
        &contract_defining_trait_id,
        contract_defining_trait_src,
        version,
        epoch,
    )
    .unwrap();
    let mut dispatching_contract = parse(
        &dispatching_contract_id,
        dispatching_contract_src,
        version,
        epoch,
    )
    .unwrap();
    let mut target_contract =
        parse(&target_contract_id, target_contract_src, version, epoch).unwrap();
    let mut contract_defining_nested_trait = parse(
        &contract_defining_nested_trait_id,
        contract_defining_nested_trait_src,
        version,
        epoch,
    )
    .unwrap();
    let mut target_nested_contract = parse(
        &target_nested_contract_id,
        target_nested_contract_src,
        version,
        epoch,
    )
    .unwrap();
    let mut marf = MemoryBackingStore::new();
    let mut db = marf.as_analysis_db();

    let err = db
        .execute(|db| {
            type_check(
                &contract_defining_nested_trait_id,
                &mut contract_defining_nested_trait,
                db,
                true,
                &epoch,
                &version,
            )?;
            type_check(
                &contract_defining_trait_id,
                &mut contract_defining_trait,
                db,
                true,
                &epoch,
                &version,
            )?;
            type_check(
                &dispatching_contract_id,
                &mut dispatching_contract,
                db,
                true,
                &epoch,
                &version,
            )?;
            type_check(
                &target_contract_id,
                &mut target_contract,
                db,
                true,
                &epoch,
                &version,
            )?;
            type_check(
                &target_nested_contract_id,
                &mut target_nested_contract,
                db,
                true,
                &epoch,
                &version,
            )
        })
        .unwrap_err();

    match err.err {
        CheckErrors::TypeError(
            TypeSignature::TraitReferenceType(_),
            TypeSignature::TraitReferenceType(_),
        ) if epoch < StacksEpochId::Epoch21 => {}
        CheckErrors::TypeError(TypeSignature::CallableType(_), TypeSignature::CallableType(_))
            if epoch >= StacksEpochId::Epoch21 && version < ClarityVersion::Clarity2 => {}
        CheckErrors::TraitReferenceUnknown(name) => assert_eq!(name.as_str(), "trait-a"),
        _ => panic!("{:?}", err),
    }
}

#[apply(test_clarity_versions)]
fn test_dynamic_dispatch_mismatched_args(
    #[case] version: ClarityVersion,
    #[case] epoch: StacksEpochId,
) {
    let dispatching_contract_src = "(define-trait trait-1 (
            (get-1 (int) (response uint uint))))
        (define-public (wrapped-get-1 (contract <trait-1>))
            (contract-call? contract get-1 u0))";
    let target_contract_src = "(impl-trait .dispatching-contract.trait-1)
        (define-public (get-1 (x uint)) (ok u1))";

    let dispatching_contract_id =
        QualifiedContractIdentifier::local("dispatching-contract").unwrap();
    let target_contract_id = QualifiedContractIdentifier::local("target-contract").unwrap();

    let mut dispatching_contract = parse(
        &dispatching_contract_id,
        dispatching_contract_src,
        version,
        epoch,
    )
    .unwrap();
    let mut target_contract =
        parse(&target_contract_id, target_contract_src, version, epoch).unwrap();
    let mut marf = MemoryBackingStore::new();
    let mut db = marf.as_analysis_db();

    let err = db
        .execute(|db| {
            type_check(
                &dispatching_contract_id,
                &mut dispatching_contract,
                db,
                true,
                &epoch,
                &version,
            )?;
            type_check(
                &target_contract_id,
                &mut target_contract,
                db,
                true,
                &epoch,
                &version,
            )
        })
        .unwrap_err();
    match err.err {
        CheckErrors::TypeError(_, _) => {}
        _ => panic!("{:?}", err),
    }
}

#[apply(test_clarity_versions)]
fn test_dynamic_dispatch_mismatched_returns(
    #[case] version: ClarityVersion,
    #[case] epoch: StacksEpochId,
) {
    let dispatching_contract_src = "(define-trait trait-1 (
            (get-1 (uint) (response uint uint))))
        (define-public (wrapped-get-1 (contract <trait-1>))
            (contract-call? contract get-1 u0))";
    let target_contract_src = "(impl-trait .dispatching-contract.trait-1)
        (define-public (get-1 (x uint)) (ok \"buffer\"))";

    let dispatching_contract_id =
        QualifiedContractIdentifier::local("dispatching-contract").unwrap();
    let target_contract_id = QualifiedContractIdentifier::local("target-contract").unwrap();

    let mut dispatching_contract = parse(
        &dispatching_contract_id,
        dispatching_contract_src,
        version,
        epoch,
    )
    .unwrap();
    let mut target_contract =
        parse(&target_contract_id, target_contract_src, version, epoch).unwrap();
    let mut marf = MemoryBackingStore::new();
    let mut db = marf.as_analysis_db();

    let err = db
        .execute(|db| {
            type_check(
                &dispatching_contract_id,
                &mut dispatching_contract,
                db,
                true,
                &epoch,
                &version,
            )?;
            type_check(
                &target_contract_id,
                &mut target_contract,
                db,
                true,
                &epoch,
                &version,
            )
        })
        .unwrap_err();
    match err.err {
        CheckErrors::BadTraitImplementation(_, _) => {}
        _ => panic!("{:?}", err),
    }
}

#[apply(test_clarity_versions)]
fn test_bad_call_with_trait(#[case] version: ClarityVersion, #[case] epoch: StacksEpochId) {
    let contract_defining_trait = "(define-trait trait-1 (
            (get-1 (uint) (response uint uint))))";
    let dispatching_contract = "(use-trait trait-1 .defun.trait-1)
        (define-public (wrapped-get-1 (contract <trait-1>))
            (contract-call? contract get-1 u0))";
    let impl_contract = "(impl-trait .defun.trait-1)
        (define-public (get-1 (x uint)) (ok u1))";
    let caller_contract = // Should error.
        "(define-public (foo-bar (p principal))
           (contract-call? .dispatch wrapped-get-1 p))";
    let def_contract_id = QualifiedContractIdentifier::local("defun").unwrap();
    let disp_contract_id = QualifiedContractIdentifier::local("dispatch").unwrap();
    let impl_contract_id = QualifiedContractIdentifier::local("implem").unwrap();
    let call_contract_id = QualifiedContractIdentifier::local("call").unwrap();
    let mut c1 = parse(&def_contract_id, contract_defining_trait, version, epoch).unwrap();
    let mut c2 = parse(&disp_contract_id, dispatching_contract, version, epoch).unwrap();
    let mut c3 = parse(&impl_contract_id, impl_contract, version, epoch).unwrap();
    let mut c4 = parse(&call_contract_id, caller_contract, version, epoch).unwrap();
    let mut marf = MemoryBackingStore::new();
    let mut db = marf.as_analysis_db();
    let err = db
        .execute(|db| {
            type_check(&def_contract_id, &mut c1, db, true, &epoch, &version).unwrap();
            type_check(&disp_contract_id, &mut c2, db, true, &epoch, &version).unwrap();
            type_check(&impl_contract_id, &mut c3, db, true, &epoch, &version).unwrap();
            type_check(&call_contract_id, &mut c4, db, true, &epoch, &version)
        })
        .unwrap_err();
    match err.err {
        CheckErrors::TypeError(_, _) => {}
        _ => panic!("{:?}", err),
    }
}

#[apply(test_clarity_versions)]
fn test_good_call_with_trait(#[case] version: ClarityVersion, #[case] epoch: StacksEpochId) {
    let contract_defining_trait = "(define-trait trait-1 (
            (get-1 (uint) (response uint uint))))";
    let dispatching_contract = "(use-trait trait-1 .defun.trait-1)
        (define-public (wrapped-get-1 (contract <trait-1>))
            (contract-call? contract get-1 u0))";
    let impl_contract = "(impl-trait .defun.trait-1)
        (define-public (get-1 (x uint)) (ok u1))";
    let caller_contract = "(define-public (foo-bar)
           (contract-call? .dispatch wrapped-get-1 .implem))";
    let def_contract_id = QualifiedContractIdentifier::local("defun").unwrap();
    let disp_contract_id = QualifiedContractIdentifier::local("dispatch").unwrap();
    let impl_contract_id = QualifiedContractIdentifier::local("implem").unwrap();
    let call_contract_id = QualifiedContractIdentifier::local("call").unwrap();
    let mut c1 = parse(&def_contract_id, contract_defining_trait, version, epoch).unwrap();
    let mut c2 = parse(&disp_contract_id, dispatching_contract, version, epoch).unwrap();
    let mut c3 = parse(&impl_contract_id, impl_contract, version, epoch).unwrap();
    let mut c4 = parse(&call_contract_id, caller_contract, version, epoch).unwrap();
    let mut marf = MemoryBackingStore::new();
    let mut db = marf.as_analysis_db();

    println!("c4: {:?}", c4);

    db.execute(|db| {
        type_check(&def_contract_id, &mut c1, db, true, &epoch, &version).unwrap();
        type_check(&disp_contract_id, &mut c2, db, true, &epoch, &version).unwrap();
        type_check(&impl_contract_id, &mut c3, db, true, &epoch, &version).unwrap();
        type_check(&call_contract_id, &mut c4, db, true, &epoch, &version)
    })
    .unwrap();
}

#[apply(test_clarity_versions)]
fn test_good_call_2_with_trait(#[case] version: ClarityVersion, #[case] epoch: StacksEpochId) {
    let contract_defining_trait = "(define-trait trait-1 (
            (get-1 (uint) (response uint uint))))";
    let dispatching_contract = "(use-trait trait-2 .defun.trait-1)
        (define-public (wrapped-get-1 (contract <trait-2>))
            (contract-call? contract get-1 u0))";
    let impl_contract = "(impl-trait .defun.trait-1)
        (define-public (get-1 (x uint)) (ok u1))";
    let caller_contract = "(use-trait trait-2 .defun.trait-1)
         (define-public (foo-bar (contract <trait-2>))
           (contract-call? .dispatch wrapped-get-1 contract))";
    let def_contract_id = QualifiedContractIdentifier::local("defun").unwrap();
    let disp_contract_id = QualifiedContractIdentifier::local("dispatch").unwrap();
    let impl_contract_id = QualifiedContractIdentifier::local("implem").unwrap();
    let call_contract_id = QualifiedContractIdentifier::local("call").unwrap();
    let mut c1 = parse(&def_contract_id, contract_defining_trait, version, epoch).unwrap();
    let mut c2 = parse(&disp_contract_id, dispatching_contract, version, epoch).unwrap();
    let mut c3 = parse(&impl_contract_id, impl_contract, version, epoch).unwrap();
    let mut c4 = parse(&call_contract_id, caller_contract, version, epoch).unwrap();
    let mut marf = MemoryBackingStore::new();
    let mut db = marf.as_analysis_db();

    println!("c4: {:?}", c4);

    db.execute(|db| {
        type_check(&def_contract_id, &mut c1, db, true, &epoch, &version).unwrap();
        type_check(&disp_contract_id, &mut c2, db, true, &epoch, &version).unwrap();
        type_check(&impl_contract_id, &mut c3, db, true, &epoch, &version).unwrap();
        type_check(&call_contract_id, &mut c4, db, true, &epoch, &version)
    })
    .unwrap();
}

#[apply(test_clarity_versions)]
fn test_dynamic_dispatch_pass_literal_principal_as_trait_in_user_defined_functions(
    #[case] version: ClarityVersion,
    #[case] epoch: StacksEpochId,
) {
    let contract_defining_trait_src = "(define-trait trait-1 (
            (get-1 (uint) (response uint uint))))";
    let dispatching_contract_src = "(use-trait trait-1 .contract-defining-trait.trait-1)
        (define-public (wrapped-get-1 (contract <trait-1>))
            (contract-call? contract get-1 u0))
        (print (wrapped-get-1 .target-contract))";
    let target_contract_src = "(impl-trait .contract-defining-trait.trait-1)
        (define-public (get-1 (x uint)) (ok u1))";

    let contract_defining_trait_id =
        QualifiedContractIdentifier::local("contract-defining-trait").unwrap();
    let dispatching_contract_id =
        QualifiedContractIdentifier::local("dispatching-contract").unwrap();
    let target_contract_id = QualifiedContractIdentifier::local("target-contract").unwrap();

    let mut contract_defining_trait = parse(
        &contract_defining_trait_id,
        contract_defining_trait_src,
        version,
        epoch,
    )
    .unwrap();
    let mut dispatching_contract = parse(
        &dispatching_contract_id,
        dispatching_contract_src,
        version,
        epoch,
    )
    .unwrap();
    let mut target_contract =
        parse(&target_contract_id, target_contract_src, version, epoch).unwrap();
    let mut marf = MemoryBackingStore::new();
    let mut db = marf.as_analysis_db();

    db.execute(|db| {
        type_check(
            &contract_defining_trait_id,
            &mut contract_defining_trait,
            db,
            true,
            &epoch,
            &version,
        )?;
        type_check(
            &target_contract_id,
            &mut target_contract,
            db,
            true,
            &epoch,
            &version,
        )?;
        type_check(
            &dispatching_contract_id,
            &mut dispatching_contract,
            db,
            true,
            &epoch,
            &version,
        )
    })
    .unwrap();
}

#[apply(test_clarity_versions)]
fn test_dynamic_dispatch_pass_bound_principal_as_trait_in_user_defined_functions(
    #[case] version: ClarityVersion,
    #[case] epoch: StacksEpochId,
) {
    let contract_defining_trait_src = "(define-trait trait-1 (
            (get-1 (uint) (response uint uint))))";
    let dispatching_contract_src = "(use-trait trait-1 .contract-defining-trait.trait-1)
        (define-public (wrapped-get-1 (contract <trait-1>))
            (contract-call? contract get-1 u0))
        (let ((p .target-contract))
            (print (wrapped-get-1 p)))";
    let target_contract_src = "(impl-trait .contract-defining-trait.trait-1)
        (define-public (get-1 (x uint)) (ok u1))";

    let contract_defining_trait_id =
        QualifiedContractIdentifier::local("contract-defining-trait").unwrap();
    let dispatching_contract_id =
        QualifiedContractIdentifier::local("dispatching-contract").unwrap();
    let target_contract_id = QualifiedContractIdentifier::local("target-contract").unwrap();

    let mut contract_defining_trait = parse(
        &contract_defining_trait_id,
        contract_defining_trait_src,
        version,
        epoch,
    )
    .unwrap();
    let mut dispatching_contract = parse(
        &dispatching_contract_id,
        dispatching_contract_src,
        version,
        epoch,
    )
    .unwrap();
    let mut target_contract =
        parse(&target_contract_id, target_contract_src, version, epoch).unwrap();
    let mut marf = MemoryBackingStore::new();
    let mut db = marf.as_analysis_db();

    let result = db.execute(|db| {
        type_check(
            &contract_defining_trait_id,
            &mut contract_defining_trait,
            db,
            true,
            &epoch,
            &version,
        )?;
        type_check(
            &target_contract_id,
            &mut target_contract,
            db,
            true,
            &epoch,
            &version,
        )?;
        type_check(
            &dispatching_contract_id,
            &mut dispatching_contract,
            db,
            true,
            &epoch,
            &version,
        )
    });
    match result {
        Err(err) if version == ClarityVersion::Clarity1 => {
            match err.err {
                CheckErrors::TypeError(_, _) => {}
                _ => panic!("{:?}", err),
            };
        }
        Ok(_) if version >= ClarityVersion::Clarity2 => (),
        _ => panic!("got {:?}", result),
    }
}

#[apply(test_clarity_versions)]
fn test_contract_of_good(#[case] version: ClarityVersion, #[case] epoch: StacksEpochId) {
    let contract_defining_trait = "(define-trait trait-1 (
            (get-1 (uint) (response uint uint))))";
    let dispatching_contract = "(use-trait trait-2 .defun.trait-1)
        (define-public (wrapped-get-1 (contract <trait-2>))
            (ok (contract-of contract)))";
    let def_contract_id = QualifiedContractIdentifier::local("defun").unwrap();
    let disp_contract_id = QualifiedContractIdentifier::local("dispatch").unwrap();
    let mut c1 = parse(&def_contract_id, contract_defining_trait, version, epoch).unwrap();
    let mut c2 = parse(&disp_contract_id, dispatching_contract, version, epoch).unwrap();
    let mut marf = MemoryBackingStore::new();
    let mut db = marf.as_analysis_db();

    db.execute(|db| {
        type_check(&def_contract_id, &mut c1, db, true, &epoch, &version).unwrap();
        type_check(&disp_contract_id, &mut c2, db, true, &epoch, &version)
    })
    .unwrap();
}

#[apply(test_clarity_versions)]
fn test_contract_of_wrong_type(#[case] version: ClarityVersion, #[case] epoch: StacksEpochId) {
    let contract_defining_trait = "(define-trait trait-1 (
            (get-1 (uint) (response uint uint))))";
    let dispatching_contract_principal = "(use-trait trait-2 .defun.trait-1)
        (define-public (wrapped-get-1 (contract principal))
            (ok (contract-of contract)))";
    let dispatching_contract_int = "(use-trait trait-2 .defun.trait-1)
        (define-public (wrapped-get-1 (contract int))
            (ok (contract-of contract)))";
    let dispatching_contract_uint = "(use-trait trait-2 .defun.trait-1)
        (define-public (wrapped-get-1 (contract uint))
            (ok (contract-of contract)))";
    let dispatching_contract_bool = "(use-trait trait-2 .defun.trait-1)
        (define-public (wrapped-get-1 (contract bool))
            (ok (contract-of contract)))";
    let dispatching_contract_list = "(use-trait trait-2 .defun.trait-1)
        (define-public (wrapped-get-1 (contract (list 10 uint)))
            (ok (contract-of contract)))";
    let dispatching_contract_buff = "(use-trait trait-2 .defun.trait-1)
        (define-public (wrapped-get-1 (contract (buff 10)))
            (ok (contract-of contract)))";
    let dispatching_contract_tuple = "(use-trait trait-2 .defun.trait-1)
        (define-public (wrapped-get-1 (contract (tuple (index uint) (value int))))
            (ok (contract-of contract)))";
    let def_contract_id = QualifiedContractIdentifier::local("defun").unwrap();
    let disp_contract_id = QualifiedContractIdentifier::local("dispatch").unwrap();
    let mut c_trait = parse(&def_contract_id, contract_defining_trait, version, epoch).unwrap();
    let mut c_principal = parse(
        &disp_contract_id,
        dispatching_contract_principal,
        version,
        epoch,
    )
    .unwrap();
    let mut c_int = parse(&disp_contract_id, dispatching_contract_int, version, epoch).unwrap();
    let c_uint = parse(&disp_contract_id, dispatching_contract_uint, version, epoch).unwrap();
    let c_bool = parse(&disp_contract_id, dispatching_contract_bool, version, epoch).unwrap();
    let c_list = parse(&disp_contract_id, dispatching_contract_list, version, epoch).unwrap();
    let c_buff = parse(&disp_contract_id, dispatching_contract_buff, version, epoch).unwrap();
    let c_tuple = parse(
        &disp_contract_id,
        dispatching_contract_tuple,
        version,
        epoch,
    )
    .unwrap();
    let mut marf = MemoryBackingStore::new();
    let mut db = marf.as_analysis_db();

    let err_principal = db
        .execute(|db| {
            type_check(&def_contract_id, &mut c_trait, db, true, &epoch, &version).unwrap();
            type_check(
                &disp_contract_id,
                &mut c_principal,
                db,
                true,
                &epoch,
                &version,
            )
        })
        .unwrap_err();
    match err_principal.err {
        CheckErrors::TraitReferenceUnknown(_) => {}
        _ => panic!("{:?}", err_principal),
    }
    let err_int = db
        .execute(|db| {
            type_check(&def_contract_id, &mut c_trait, db, true, &epoch, &version).unwrap();
            type_check(&disp_contract_id, &mut c_int, db, true, &epoch, &version)
        })
        .unwrap_err();
    match err_int.err {
        CheckErrors::TraitReferenceUnknown(_) => {}
        _ => panic!("{:?}", err_int),
    }
    let err_uint = db
        .execute(|db| {
            type_check(&def_contract_id, &mut c_trait, db, true, &epoch, &version).unwrap();
            type_check(&disp_contract_id, &mut c_int, db, true, &epoch, &version)
        })
        .unwrap_err();
    match err_uint.err {
        CheckErrors::TraitReferenceUnknown(_) => {}
        _ => panic!("{:?}", err_uint),
    }
    let err_bool = db
        .execute(|db| {
            type_check(&def_contract_id, &mut c_trait, db, true, &epoch, &version).unwrap();
            type_check(&disp_contract_id, &mut c_int, db, true, &epoch, &version)
        })
        .unwrap_err();
    match err_bool.err {
        CheckErrors::TraitReferenceUnknown(_) => {}
        _ => panic!("{:?}", err_bool),
    }
    let err_list = db
        .execute(|db| {
            type_check(&def_contract_id, &mut c_trait, db, true, &epoch, &version).unwrap();
            type_check(&disp_contract_id, &mut c_int, db, true, &epoch, &version)
        })
        .unwrap_err();
    match err_list.err {
        CheckErrors::TraitReferenceUnknown(_) => {}
        _ => panic!("{:?}", err_list),
    }
    let err_buff = db
        .execute(|db| {
            type_check(&def_contract_id, &mut c_trait, db, true, &epoch, &version).unwrap();
            type_check(&disp_contract_id, &mut c_int, db, true, &epoch, &version)
        })
        .unwrap_err();
    match err_buff.err {
        CheckErrors::TraitReferenceUnknown(_) => {}
        _ => panic!("{:?}", err_buff),
    }
    let err_tuple = db
        .execute(|db| {
            type_check(&def_contract_id, &mut c_trait, db, true, &epoch, &version).unwrap();
            type_check(&disp_contract_id, &mut c_int, db, true, &epoch, &version)
        })
        .unwrap_err();
    match err_tuple.err {
        CheckErrors::TraitReferenceUnknown(_) => {}
        _ => panic!("{:?}", err_tuple),
    }
}

#[apply(test_clarity_versions)]
fn test_return_trait_with_contract_of(
    #[case] version: ClarityVersion,
    #[case] epoch: StacksEpochId,
) {
    let dispatching_contract_src = "(define-trait trait-1 (
            (get-1 (uint) (response uint uint))))
        (define-public (wrapped-get-1 (contract <trait-1>))
            (begin
                (unwrap-panic (contract-call? contract get-1 u0))
                (ok (contract-of contract))))";
    let target_contract_src = "(define-public (get-1 (x uint)) (ok u1))";

    let dispatching_contract_id =
        QualifiedContractIdentifier::local("dispatching-contract").unwrap();
    let target_contract_id = QualifiedContractIdentifier::local("target-contract").unwrap();

    let mut dispatching_contract = parse(
        &dispatching_contract_id,
        dispatching_contract_src,
        version,
        epoch,
    )
    .unwrap();
    let mut target_contract =
        parse(&target_contract_id, target_contract_src, version, epoch).unwrap();
    let mut marf = MemoryBackingStore::new();
    let mut db = marf.as_analysis_db();

    db.execute(|db| {
        type_check(
            &dispatching_contract_id,
            &mut dispatching_contract,
            db,
            true,
            &epoch,
            &version,
        )?;
        type_check(
            &target_contract_id,
            &mut target_contract,
            db,
            true,
            &epoch,
            &version,
        )
    })
    .unwrap();
}

#[apply(test_clarity_versions)]
fn test_return_trait_with_contract_of_wrapped_in_begin(
    #[case] version: ClarityVersion,
    #[case] epoch: StacksEpochId,
) {
    let dispatching_contract_src = "(define-trait trait-1 (
            (get-1 (uint) (response uint uint))))
        (define-public (wrapped-get-1 (contract <trait-1>))
            (begin
                (unwrap-panic (contract-call? contract get-1 u0))
                (ok (contract-of contract))))";
    let target_contract_src = "(define-public (get-1 (x uint)) (ok u1))";

    let dispatching_contract_id =
        QualifiedContractIdentifier::local("dispatching-contract").unwrap();
    let target_contract_id = QualifiedContractIdentifier::local("target-contract").unwrap();

    let mut dispatching_contract = parse(
        &dispatching_contract_id,
        dispatching_contract_src,
        version,
        epoch,
    )
    .unwrap();
    let mut target_contract =
        parse(&target_contract_id, target_contract_src, version, epoch).unwrap();
    let mut marf = MemoryBackingStore::new();
    let mut db = marf.as_analysis_db();

    db.execute(|db| {
        type_check(
            &dispatching_contract_id,
            &mut dispatching_contract,
            db,
            true,
            &epoch,
            &version,
        )?;
        type_check(
            &target_contract_id,
            &mut target_contract,
            db,
            true,
            &epoch,
            &version,
        )
    })
    .unwrap();
}

#[apply(test_clarity_versions)]
fn test_return_trait_with_contract_of_wrapped_in_let(
    #[case] version: ClarityVersion,
    #[case] epoch: StacksEpochId,
) {
    let dispatching_contract_src = "(define-trait trait-1 (
            (get-1 (uint) (response uint uint))))
        (define-public (wrapped-get-1 (contract <trait-1>))
            (let ((val u0))
                (unwrap-panic (contract-call? contract get-1 val))
                (ok (contract-of contract))))";
    let target_contract_src = "(define-public (get-1 (x uint)) (ok u1))";

    let dispatching_contract_id =
        QualifiedContractIdentifier::local("dispatching-contract").unwrap();
    let target_contract_id = QualifiedContractIdentifier::local("target-contract").unwrap();

    let mut dispatching_contract = parse(
        &dispatching_contract_id,
        dispatching_contract_src,
        version,
        epoch,
    )
    .unwrap();
    let mut target_contract =
        parse(&target_contract_id, target_contract_src, version, epoch).unwrap();
    let mut marf = MemoryBackingStore::new();
    let mut db = marf.as_analysis_db();

    db.execute(|db| {
        type_check(
            &dispatching_contract_id,
            &mut dispatching_contract,
            db,
            true,
            &epoch,
            &version,
        )?;
        type_check(
            &target_contract_id,
            &mut target_contract,
            db,
            true,
            &epoch,
            &version,
        )
    })
    .unwrap();
}

#[apply(test_clarity_versions)]
fn test_trait_contract_not_found(#[case] version: ClarityVersion, #[case] epoch: StacksEpochId) {
    let trait_contract_src = "(define-trait my-trait
        ((hello (int) (response uint uint)))
    )
    (define-private (pass-trait (a <my-trait>))
        (print a)
    )
    (define-public (call-it)
        (ok (pass-trait .impl-contract))
    )";
    let impl_contract_src = "(define-public (hello (a int))
    (ok u0)
)";

    let trait_contract_id = QualifiedContractIdentifier::local("trait-contract").unwrap();
    let impl_contract_id = QualifiedContractIdentifier::local("impl-contract").unwrap();

    let mut impl_contract = parse(&impl_contract_id, impl_contract_src, version, epoch).unwrap();
    let mut trait_contract = parse(&trait_contract_id, trait_contract_src, version, epoch).unwrap();
    let mut marf = MemoryBackingStore::new();
    let mut db = marf.as_analysis_db();

    // Referring to a trait from the current contract is supported in Clarity2,
    // but not in Clarity1.
    match db.execute(|db| {
        type_check(
            &impl_contract_id,
            &mut impl_contract,
            db,
            true,
            &epoch,
            &version,
        )?;
        type_check(
            &trait_contract_id,
            &mut trait_contract,
            db,
            true,
            &epoch,
            &version,
        )
    }) {
        Err(CheckError {
            err: CheckErrors::NoSuchContract(contract),
            expressions: _,
            diagnostic: _,
        }) if version < ClarityVersion::Clarity2 => assert!(contract.ends_with(".trait-contract")),
        Ok(_) if version >= ClarityVersion::Clarity2 => (),
        res => panic!("{}: {:?}", version, res),
    }
}
