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

use clarity::vm::ast::ASTRules;
use clarity::vm::contexts::OwnedEnvironment;
use clarity::vm::costs::ExecutionCost;
use clarity::vm::database::MemoryBackingStore;
use clarity::vm::events::*;
use clarity::vm::tests::{
    execute, test_only_mainnet_to_chain_id, TEST_BURN_STATE_DB, TEST_HEADER_DB,
};
use clarity::vm::types::{AssetIdentifier, BuffData, QualifiedContractIdentifier, Value};
use clarity::vm::{ClarityVersion, ContractContext};
use stacks_common::types::chainstate::StacksBlockId;
use stacks_common::types::StacksEpochId;

use crate::chainstate::stacks::index::ClarityMarfTrieId;
use crate::chainstate::stacks::StacksBlockHeader;
use crate::clarity_vm::clarity::ClarityInstance;
use crate::clarity_vm::database::marf::MarfedKV;
use crate::core::{FIRST_BURNCHAIN_CONSENSUS_HASH, FIRST_STACKS_BLOCK_HASH};

fn helper_execute(contract: &str, method: &str) -> (Value, Vec<StacksTransactionEvent>) {
    helper_execute_epoch(contract, method, None, StacksEpochId::Epoch21, false)
}

fn helper_execute_epoch(
    contract: &str,
    method: &str,
    set_epoch: Option<StacksEpochId>,
    epoch: StacksEpochId,
    use_mainnet: bool,
) -> (Value, Vec<StacksTransactionEvent>) {
    let contract_id = QualifiedContractIdentifier::local("contract").unwrap();
    let address = "'SZ2J6ZY48GV1EZ5V2V5RB9MP66SW86PYKKQ9H6DPR";
    let sender = execute(address).expect_principal().unwrap();

    let marf_kv = MarfedKV::temporary();
    let chain_id = test_only_mainnet_to_chain_id(use_mainnet);
    let mut clarity_instance = ClarityInstance::new(use_mainnet, chain_id, marf_kv);
    let mut genesis = clarity_instance.begin_test_genesis_block(
        &StacksBlockId::sentinel(),
        &StacksBlockHeader::make_index_block_hash(
            &FIRST_BURNCHAIN_CONSENSUS_HASH,
            &FIRST_STACKS_BLOCK_HASH,
        ),
        &TEST_HEADER_DB,
        &TEST_BURN_STATE_DB,
    );
    if epoch > StacksEpochId::Epoch20 {
        genesis.initialize_epoch_2_05().unwrap();
    }
    if epoch > StacksEpochId::Epoch2_05 {
        genesis.initialize_epoch_2_1().unwrap();
    }

    if let Some(epoch) = set_epoch {
        genesis.as_transaction(|tx_conn| {
            // bump the epoch in the Clarity DB
            tx_conn
                .with_clarity_db(|db| {
                    db.set_clarity_epoch_version(epoch).unwrap();
                    Ok(())
                })
                .unwrap();
        });
    }

    genesis.commit_block();

    let mut marf_kv = clarity_instance.destroy();

    let mut store = marf_kv.begin(
        &StacksBlockHeader::make_index_block_hash(
            &FIRST_BURNCHAIN_CONSENSUS_HASH,
            &FIRST_STACKS_BLOCK_HASH,
        ),
        &StacksBlockId([1; 32]),
    );

    let mut owned_env = OwnedEnvironment::new_max_limit(
        store.as_clarity_db(&TEST_HEADER_DB, &TEST_BURN_STATE_DB),
        epoch,
        use_mainnet,
    );
    let placeholder_context = ContractContext::new(
        QualifiedContractIdentifier::transient(),
        ClarityVersion::default_for_epoch(epoch),
    );

    {
        let mut env = owned_env.get_exec_environment(None, None, &placeholder_context);
        env.initialize_contract(contract_id.clone(), contract, ASTRules::PrecheckSize)
            .unwrap();
    }

    owned_env.stx_faucet(&sender, 10);

    let (value, _, events) = owned_env
        .execute_transaction(sender, None, contract_id, method, &[])
        .unwrap();
    (value, events)
}

#[test]
fn test_emit_print_ok() {
    let contract = "(define-public (emit-event-ok)
            (begin
                (print \"Hello world\")
                (ok u1)))";

    let (value, mut events) = helper_execute(contract, "emit-event-ok");
    assert_eq!(value, Value::okay(Value::UInt(1)).unwrap());
    assert_eq!(events.len(), 1);
    match events.pop() {
        Some(StacksTransactionEvent::SmartContractEvent(data)) => {
            let contract_id = QualifiedContractIdentifier::local("contract").unwrap();
            assert_eq!(data.key, (contract_id, "print".to_string()));
            assert_eq!(data.value, execute("\"Hello world\""));
        }
        _ => panic!("assertion failed"),
    };
}

#[test]
fn test_emit_print_nok() {
    let contract = "(define-public (emit-event-nok)
            (begin
                (print \"Hello world\")
                (err u1)))";

    let (value, events) = helper_execute(contract, "emit-event-nok");
    assert_eq!(value, Value::error(Value::UInt(1)).unwrap());
    assert_eq!(events.len(), 0);
}

#[test]
fn test_emit_stx_transfer_ok() {
    let contract = r#"(define-constant sender 'SZ2J6ZY48GV1EZ5V2V5RB9MP66SW86PYKKQ9H6DPR)
        (define-constant recipient 'SM2J6ZY48GV1EZ5V2V5RB9MP66SW86PYKKQVX8X0G)
        (define-fungible-token token)
        (define-public (emit-event-ok)
            (begin
                (unwrap-panic (stx-transfer? u10 sender recipient))
                (ok u1)))"#;

    let (value, mut events) = helper_execute(contract, "emit-event-ok");
    assert_eq!(value, Value::okay(Value::UInt(1)).unwrap());
    assert_eq!(events.len(), 1);
    match events.pop() {
        Some(StacksTransactionEvent::STXEvent(STXEventType::STXTransferEvent(data))) => {
            assert_eq!(data.amount, 10u128);
            assert_eq!(
                Value::Principal(data.sender),
                execute("'SZ2J6ZY48GV1EZ5V2V5RB9MP66SW86PYKKQ9H6DPR")
            );
            assert_eq!(
                Value::Principal(data.recipient),
                execute("'SM2J6ZY48GV1EZ5V2V5RB9MP66SW86PYKKQVX8X0G")
            );
            assert_eq!(data.memo, BuffData { data: vec![] });
        }
        _ => panic!("assertion failed"),
    };
}

#[test]
fn test_emit_stx_transfer_memo_ok() {
    let contract = r#"(define-constant sender 'SZ2J6ZY48GV1EZ5V2V5RB9MP66SW86PYKKQ9H6DPR)
        (define-constant recipient 'SM2J6ZY48GV1EZ5V2V5RB9MP66SW86PYKKQVX8X0G)
        (define-fungible-token token)
        (define-public (emit-event-ok)
            (begin
                (unwrap-panic (stx-transfer-memo? u10 sender recipient 0x010203))
                (ok u1)))"#;

    let (value, mut events) = helper_execute_epoch(
        contract,
        "emit-event-ok",
        Some(StacksEpochId::Epoch21),
        StacksEpochId::Epoch21,
        false,
    );
    assert_eq!(value, Value::okay(Value::UInt(1)).unwrap());
    assert_eq!(events.len(), 1);
    match events.pop() {
        Some(StacksTransactionEvent::STXEvent(STXEventType::STXTransferEvent(data))) => {
            assert_eq!(data.amount, 10u128);
            assert_eq!(
                Value::Principal(data.sender),
                execute("'SZ2J6ZY48GV1EZ5V2V5RB9MP66SW86PYKKQ9H6DPR")
            );
            assert_eq!(
                Value::Principal(data.recipient),
                execute("'SM2J6ZY48GV1EZ5V2V5RB9MP66SW86PYKKQVX8X0G")
            );
            assert_eq!(
                data.memo,
                BuffData {
                    data: vec![1, 2, 3]
                }
            );
        }
        _ => panic!("assertion failed"),
    };
}

#[test]
fn test_emit_stx_transfer_nok() {
    let contract = r#"(define-constant sender 'SZ2J6ZY48GV1EZ5V2V5RB9MP66SW86PYKKQ9H6DPR)
        (define-constant recipient 'SM2J6ZY48GV1EZ5V2V5RB9MP66SW86PYKKQVX8X0G)
        (define-fungible-token token)
        (define-public (emit-event-nok)
            (begin
                (unwrap-panic (stx-transfer? u10 sender recipient))
                (err u1)))"#;

    let (value, events) = helper_execute(contract, "emit-event-nok");
    assert_eq!(value, Value::error(Value::UInt(1)).unwrap());
    assert_eq!(events.len(), 0);
}

#[test]
fn test_emit_stx_burn_ok() {
    let contract = "(define-constant sender 'SZ2J6ZY48GV1EZ5V2V5RB9MP66SW86PYKKQ9H6DPR)
        (define-fungible-token token)
        (define-public (emit-event-ok)
            (begin
                (unwrap-panic (stx-burn? u10 sender))
                (ok u1)))";

    let (value, mut events) = helper_execute(contract, "emit-event-ok");
    assert_eq!(value, Value::okay(Value::UInt(1)).unwrap());
    assert_eq!(events.len(), 1);
    match events.pop() {
        Some(StacksTransactionEvent::STXEvent(STXEventType::STXBurnEvent(data))) => {
            assert_eq!(data.amount, 10u128);
            assert_eq!(
                Value::Principal(data.sender),
                execute("'SZ2J6ZY48GV1EZ5V2V5RB9MP66SW86PYKKQ9H6DPR")
            );
        }
        _ => panic!("assertion failed"),
    };
}

#[test]
fn test_emit_stx_burn_nok() {
    let contract = "(define-constant sender 'SZ2J6ZY48GV1EZ5V2V5RB9MP66SW86PYKKQ9H6DPR)
        (define-fungible-token token)
        (define-public (emit-event-nok)
            (begin
                (unwrap-panic (stx-burn? u10 sender))
                (err u1)))";

    let (value, events) = helper_execute(contract, "emit-event-nok");
    assert_eq!(value, Value::error(Value::UInt(1)).unwrap());
    assert_eq!(events.len(), 0);
}

#[test]
fn test_emit_nested_print_nok() {
    let contract = "(define-public (emit-event-nok)
            (begin
                (print \"bar\")
                (err u1)))
        (define-public (emit-event-ok)
            (begin
                (emit-event-nok)
                (print \"foo\")
                (ok u1)))";

    let (value, events) = helper_execute(contract, "emit-event-ok");
    assert_eq!(value, Value::okay(Value::UInt(1)).unwrap());
    assert_eq!(events.len(), 1);
}

#[test]
fn test_emit_ft_transfer_ok() {
    let contract = "(define-constant sender 'SZ2J6ZY48GV1EZ5V2V5RB9MP66SW86PYKKQ9H6DPR)
        (define-constant recipient 'SM2J6ZY48GV1EZ5V2V5RB9MP66SW86PYKKQVX8X0G)
        (define-fungible-token token)
        (define-public (emit-event-ok)
            (begin
                (unwrap-panic (ft-transfer? token u10 sender recipient))
                (ok u1)))
        (begin (ft-mint? token u10 sender))";

    let (value, mut events) = helper_execute(contract, "emit-event-ok");
    assert_eq!(value, Value::okay(Value::UInt(1)).unwrap());
    assert_eq!(events.len(), 1);
    match events.pop() {
        Some(StacksTransactionEvent::FTEvent(FTEventType::FTTransferEvent(data))) => {
            let contract_identifier = QualifiedContractIdentifier::local("contract").unwrap();
            let asset_identifier = AssetIdentifier {
                contract_identifier,
                asset_name: "token".into(),
            };
            assert_eq!(data.asset_identifier, asset_identifier);
            assert_eq!(data.amount, 10u128);
            assert_eq!(
                Value::Principal(data.sender),
                execute("'SZ2J6ZY48GV1EZ5V2V5RB9MP66SW86PYKKQ9H6DPR")
            );
            assert_eq!(
                Value::Principal(data.recipient),
                execute("'SM2J6ZY48GV1EZ5V2V5RB9MP66SW86PYKKQVX8X0G")
            );
        }
        _ => panic!("assertion failed"),
    };
}

#[test]
fn test_emit_ft_transfer_nok() {
    let contract = "(define-constant sender 'SZ2J6ZY48GV1EZ5V2V5RB9MP66SW86PYKKQ9H6DPR)
        (define-constant recipient 'SM2J6ZY48GV1EZ5V2V5RB9MP66SW86PYKKQVX8X0G)
        (define-fungible-token token)
        (define-public (emit-event-nok)
            (begin
                (unwrap-panic (ft-transfer? token u10 sender recipient))
                (err u1)))
        (begin (ft-mint? token u10 sender))";

    let (value, events) = helper_execute(contract, "emit-event-nok");
    assert_eq!(value, Value::error(Value::UInt(1)).unwrap());
    assert_eq!(events.len(), 0);
}

#[test]
fn test_emit_ft_mint_ok() {
    let contract = "(define-constant recipient 'SZ2J6ZY48GV1EZ5V2V5RB9MP66SW86PYKKQ9H6DPR)
        (define-fungible-token token)
        (define-public (emit-event-ok)
            (begin
                (unwrap-panic (ft-mint? token u10 recipient))
                (ok u1)))";

    let (value, mut events) = helper_execute(contract, "emit-event-ok");
    assert_eq!(value, Value::okay(Value::UInt(1)).unwrap());
    assert_eq!(events.len(), 1);
    match events.pop() {
        Some(StacksTransactionEvent::FTEvent(FTEventType::FTMintEvent(data))) => {
            let contract_identifier = QualifiedContractIdentifier::local("contract").unwrap();
            let asset_identifier = AssetIdentifier {
                contract_identifier,
                asset_name: "token".into(),
            };
            assert_eq!(data.asset_identifier, asset_identifier);
            assert_eq!(data.amount, 10u128);
            assert_eq!(
                Value::Principal(data.recipient),
                execute("'SZ2J6ZY48GV1EZ5V2V5RB9MP66SW86PYKKQ9H6DPR")
            );
        }
        _ => panic!("assertion failed"),
    };
}

#[test]
fn test_emit_ft_mint_nok() {
    let contract = "(define-constant recipient 'SZ2J6ZY48GV1EZ5V2V5RB9MP66SW86PYKKQ9H6DPR)
        (define-fungible-token token)
        (define-public (emit-event-nok)
            (begin
                (unwrap-panic (ft-mint? token u10 recipient))
                (err u1)))";

    let (value, events) = helper_execute(contract, "emit-event-nok");
    assert_eq!(value, Value::error(Value::UInt(1)).unwrap());
    assert_eq!(events.len(), 0);
}

#[test]
fn test_emit_nft_transfer_ok() {
    let contract = "(define-constant sender 'SZ2J6ZY48GV1EZ5V2V5RB9MP66SW86PYKKQ9H6DPR)
        (define-constant recipient 'SM2J6ZY48GV1EZ5V2V5RB9MP66SW86PYKKQVX8X0G)
        (define-non-fungible-token token uint)
        (define-public (emit-event-ok)
            (begin
                (unwrap-panic (nft-transfer? token u1 sender recipient))
                (ok u1)))
        (begin (nft-mint? token u1 sender))";

    let (value, mut events) = helper_execute(contract, "emit-event-ok");
    assert_eq!(value, Value::okay(Value::UInt(1)).unwrap());
    assert_eq!(events.len(), 1);
    match events.pop() {
        Some(StacksTransactionEvent::NFTEvent(NFTEventType::NFTTransferEvent(data))) => {
            let contract_identifier = QualifiedContractIdentifier::local("contract").unwrap();
            let asset_identifier = AssetIdentifier {
                contract_identifier,
                asset_name: "token".into(),
            };
            assert_eq!(data.asset_identifier, asset_identifier);
            assert_eq!(data.value, execute("u1"));
            assert_eq!(
                Value::Principal(data.sender),
                execute("'SZ2J6ZY48GV1EZ5V2V5RB9MP66SW86PYKKQ9H6DPR")
            );
            assert_eq!(
                Value::Principal(data.recipient),
                execute("'SM2J6ZY48GV1EZ5V2V5RB9MP66SW86PYKKQVX8X0G")
            );
        }
        _ => panic!("assertion failed"),
    };
}

#[test]
fn test_emit_nft_transfer_nok() {
    let contract = "(define-constant sender 'SZ2J6ZY48GV1EZ5V2V5RB9MP66SW86PYKKQ9H6DPR)
        (define-constant recipient 'SM2J6ZY48GV1EZ5V2V5RB9MP66SW86PYKKQVX8X0G)
        (define-non-fungible-token token uint)
        (define-public (emit-event-nok)
            (begin
                (unwrap-panic (nft-transfer? token u1 sender recipient))
                (err u1)))
        (begin (nft-mint? token u1 sender))";

    let (value, events) = helper_execute(contract, "emit-event-nok");
    assert_eq!(value, Value::error(Value::UInt(1)).unwrap());
    assert_eq!(events.len(), 0);
}

#[test]
fn test_emit_nft_mint_ok() {
    let contract = "(define-constant recipient 'SZ2J6ZY48GV1EZ5V2V5RB9MP66SW86PYKKQ9H6DPR)
        (define-non-fungible-token token uint)
        (define-public (emit-event-ok)
            (begin
                (unwrap-panic (nft-mint? token u1 recipient))
                (ok u1)))";

    let (value, mut events) = helper_execute(contract, "emit-event-ok");
    assert_eq!(value, Value::okay(Value::UInt(1)).unwrap());
    assert_eq!(events.len(), 1);
    match events.pop() {
        Some(StacksTransactionEvent::NFTEvent(NFTEventType::NFTMintEvent(data))) => {
            let contract_identifier = QualifiedContractIdentifier::local("contract").unwrap();
            let asset_identifier = AssetIdentifier {
                contract_identifier,
                asset_name: "token".into(),
            };
            assert_eq!(data.asset_identifier, asset_identifier);
            assert_eq!(data.value, execute("u1"));
            assert_eq!(
                Value::Principal(data.recipient),
                execute("'SZ2J6ZY48GV1EZ5V2V5RB9MP66SW86PYKKQ9H6DPR")
            );
        }
        _ => panic!("assertion failed"),
    };
}

#[test]
fn test_emit_nft_mint_nok() {
    let contract = "(define-constant recipient 'SZ2J6ZY48GV1EZ5V2V5RB9MP66SW86PYKKQ9H6DPR)
        (define-non-fungible-token token uint)
        (define-public (emit-event-nok)
            (begin
                (unwrap-panic (nft-mint? token u1 recipient))
                (err u1)))";

    let (value, events) = helper_execute(contract, "emit-event-nok");
    assert_eq!(value, Value::error(Value::UInt(1)).unwrap());
    assert_eq!(events.len(), 0);
}
