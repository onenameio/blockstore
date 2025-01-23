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

use crate::vm::analysis::errors::CheckErrors;
use crate::vm::ast::parse;
use crate::vm::database::MemoryBackingStore;
use crate::vm::tooling::mem_type_check;
use crate::vm::types::{
    QualifiedContractIdentifier, SequenceSubtype, StringSubtype, TypeSignature,
};
use crate::vm::ClarityVersion;

fn string_ascii_type(size: u32) -> TypeSignature {
    TypeSignature::SequenceType(SequenceSubtype::StringType(StringSubtype::ASCII(
        size.try_into().unwrap(),
    )))
}

const FIRST_CLASS_TOKENS: &str = "(define-fungible-token stackaroos)
         (define-non-fungible-token stacka-nfts (string-ascii 10))
         (nft-get-owner? stacka-nfts \"1234567890\" )
         (define-read-only (my-ft-get-balance (account principal))
            (ft-get-balance stackaroos account))
         (define-read-only (my-ft-get-supply)
            (ft-get-supply stackaroos))
         (define-public (my-token-transfer (to principal) (amount uint))
            (ft-transfer? stackaroos amount tx-sender to))
         (define-public (faucet)
           (let ((original-sender tx-sender))
             (as-contract (ft-transfer? stackaroos u1 tx-sender original-sender))))
         (define-public (burn)
           (ft-burn? stackaroos u1 tx-sender))
         (define-public (mint-after (block-to-release uint))
           (if (>= block-height block-to-release)
               (faucet)
               (err u8)))
         (begin (unwrap-panic (ft-mint? stackaroos u10000 'SZ2J6ZY48GV1EZ5V2V5RB9MP66SW86PYKKQ9H6DPR))
                (unwrap-panic (ft-mint? stackaroos u200 'SM2J6ZY48GV1EZ5V2V5RB9MP66SW86PYKKQVX8X0G))
                (unwrap-panic (ft-mint? stackaroos u4 .tokens)))";

const ASSET_NAMES: &str = "(define-constant burn-address 'SP000000000000000000002Q6VF78)
         (define-private (price-function (name uint))
           (if (< name u100000) u1000 u100))

         (define-non-fungible-token names uint)
         (define-map preorder-map
           { name-hash: (buff 20) }
           { buyer: principal, paid: uint })

         (define-public (preorder
                        (name-hash (buff 20))
                        (name-price uint))
           (let ((xfer-result (contract-call? .tokens my-token-transfer
                                burn-address name-price)))
            (unwrap! xfer-result (err false))
            (if (map-insert preorder-map
                  (tuple (name-hash name-hash))
                  (tuple (paid name-price) (buyer tx-sender)))
                (ok true)
                (err false))))

         (define-public (register
                        (recipient-principal principal)
                        (name uint)
                        (salt uint))
           (let ((preorder-entry
                   ;; preorder entry must exist!
                   (unwrap! (map-get? preorder-map
                                  (tuple (name-hash (hash160 (xor name salt))))) (err u5)))
                 (name-entry
                   (nft-get-owner? names name)))
             (if (and
                  (is-none name-entry)
                  ;; preorder must have paid enough
                  (<= (price-function name)
                      (get paid preorder-entry))
                  ;; preorder must have been the current principal
                  (is-eq tx-sender
                       (get buyer preorder-entry)))
                  (if (and
                    (is-ok (nft-mint? names name recipient-principal))
                    (map-delete preorder-map
                      (tuple (name-hash (hash160 (xor name salt))))))
                    (ok u0)
                    (err u3))
                  (err u4))))
          (define-public (revoke (name uint))
            (nft-burn? names name tx-sender))
         ";

#[test]
fn test_names_tokens_contracts() {
    use crate::vm::analysis::type_check;

    let tokens_contract_id = QualifiedContractIdentifier::local("tokens").unwrap();
    let names_contract_id = QualifiedContractIdentifier::local("names").unwrap();

    let mut tokens_contract = parse(
        &tokens_contract_id,
        FIRST_CLASS_TOKENS,
        ClarityVersion::Clarity1,
        StacksEpochId::Epoch2_05,
    )
    .unwrap();
    let mut names_contract = parse(
        &names_contract_id,
        ASSET_NAMES,
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
fn test_bad_asset_usage() {
    let bad_scripts = [
        "(ft-get-balance stackoos tx-sender)",
        "(ft-get-balance u1234 tx-sender)",
        "(ft-get-balance 1234 tx-sender)",
        "(ft-get-balance stackaroos u100)",
        "(ft-get-balance stackaroos 100)",
        "(nft-get-owner? u1234 \"abc\")",
        "(nft-get-owner? stackoos \"abc\")",
        "(nft-get-owner? stacka-nfts u1234 )",
        "(nft-get-owner? stacka-nfts \"123456789012345\" )",
        "(nft-mint? u1234 \"abc\" tx-sender)",
        "(nft-mint? stackoos \"abc\" tx-sender)",
        "(nft-mint? stacka-nfts u1234 tx-sender)",
        "(nft-mint? stacka-nfts \"123456789012345\" tx-sender)",
        "(nft-mint? stacka-nfts \"abc\" u2)",
        "(ft-mint? stackoos u1 tx-sender)",
        "(ft-mint? u1234 u1 tx-sender)",
        "(ft-mint? stackaroos u2 u100)",
        "(ft-mint? stackaroos true tx-sender)",
        "(nft-transfer? u1234 \"a\" tx-sender tx-sender)",
        "(nft-transfer? stackoos    \"a\" tx-sender tx-sender)",
        "(nft-transfer? stacka-nfts \"a\" u2 tx-sender)",
        "(nft-transfer? stacka-nfts \"a\" tx-sender u2)",
        "(nft-transfer? stacka-nfts u2 tx-sender tx-sender)",
        "(nft-burn? u1234 \"a\" tx-sender)",
        "(nft-burn? stacka-nfts u2 tx-sender)",
        "(nft-burn? stacka-nfts \"a\" u2)",
        "(ft-transfer? stackoos u1 tx-sender tx-sender)",
        "(ft-transfer? u1234 u1 tx-sender tx-sender)",
        "(ft-transfer? stackaroos u2 u100 tx-sender)",
        "(ft-transfer? stackaroos true tx-sender tx-sender)",
        "(ft-transfer? stackaroos u2 tx-sender u100)",
        "(define-fungible-token stackaroos true)",
        "(define-non-fungible-token stackaroos integer)",
        "(ft-mint? stackaroos 100 tx-sender)",
        "(ft-transfer? stackaroos 1 tx-sender tx-sender)",
        "(ft-get-supply stackoos)",
        "(ft-burn? stackoos u1 tx-sender)",
        "(ft-burn? stackaroos 1 tx-sender)",
        "(ft-burn? stackaroos u1 123432343)",
    ];

    let expected = [
        CheckErrors::NoSuchFT("stackoos".to_string()),
        CheckErrors::BadTokenName,
        CheckErrors::BadTokenName,
        CheckErrors::TypeError(TypeSignature::PrincipalType, TypeSignature::UIntType),
        CheckErrors::TypeError(TypeSignature::PrincipalType, TypeSignature::IntType),
        CheckErrors::BadTokenName,
        CheckErrors::NoSuchNFT("stackoos".to_string()),
        CheckErrors::TypeError(string_ascii_type(10), TypeSignature::UIntType),
        CheckErrors::TypeError(string_ascii_type(10), string_ascii_type(15)),
        CheckErrors::BadTokenName,
        CheckErrors::NoSuchNFT("stackoos".to_string()),
        CheckErrors::TypeError(string_ascii_type(10), TypeSignature::UIntType),
        CheckErrors::TypeError(string_ascii_type(10), string_ascii_type(15)),
        CheckErrors::TypeError(TypeSignature::PrincipalType, TypeSignature::UIntType),
        CheckErrors::NoSuchFT("stackoos".to_string()),
        CheckErrors::BadTokenName,
        CheckErrors::TypeError(TypeSignature::PrincipalType, TypeSignature::UIntType),
        CheckErrors::TypeError(TypeSignature::UIntType, TypeSignature::BoolType),
        CheckErrors::BadTokenName,
        CheckErrors::NoSuchNFT("stackoos".to_string()),
        CheckErrors::TypeError(TypeSignature::PrincipalType, TypeSignature::UIntType),
        CheckErrors::TypeError(TypeSignature::PrincipalType, TypeSignature::UIntType),
        CheckErrors::TypeError(string_ascii_type(10), TypeSignature::UIntType),
        CheckErrors::BadTokenName,
        CheckErrors::TypeError(string_ascii_type(10), TypeSignature::UIntType),
        CheckErrors::TypeError(TypeSignature::PrincipalType, TypeSignature::UIntType),
        CheckErrors::NoSuchFT("stackoos".to_string()),
        CheckErrors::BadTokenName,
        CheckErrors::TypeError(TypeSignature::PrincipalType, TypeSignature::UIntType),
        CheckErrors::TypeError(TypeSignature::UIntType, TypeSignature::BoolType),
        CheckErrors::TypeError(TypeSignature::PrincipalType, TypeSignature::UIntType),
        CheckErrors::TypeError(TypeSignature::UIntType, TypeSignature::BoolType),
        CheckErrors::DefineNFTBadSignature,
        CheckErrors::TypeError(TypeSignature::UIntType, TypeSignature::IntType),
        CheckErrors::TypeError(TypeSignature::UIntType, TypeSignature::IntType),
        CheckErrors::NoSuchFT("stackoos".to_string()),
        CheckErrors::NoSuchFT("stackoos".to_string()),
        CheckErrors::TypeError(TypeSignature::UIntType, TypeSignature::IntType),
        CheckErrors::TypeError(TypeSignature::PrincipalType, TypeSignature::IntType),
    ];

    for (script, expected_err) in bad_scripts.iter().zip(expected.iter()) {
        let tokens_contract = format!("{}\n{}", FIRST_CLASS_TOKENS, script);
        let actual_err = mem_type_check(
            &tokens_contract,
            ClarityVersion::Clarity1,
            StacksEpochId::Epoch2_05,
        )
        .unwrap_err();
        println!("{}", script);
        assert_eq!(&actual_err.err, expected_err);
    }
}
