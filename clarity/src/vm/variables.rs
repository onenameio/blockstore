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

use super::errors::InterpreterError;
use crate::vm::contexts::{Environment, LocalContext};
use crate::vm::costs::cost_functions::ClarityCostFunction;
use crate::vm::costs::runtime_cost;
use crate::vm::errors::{InterpreterResult as Result, RuntimeErrorType};
use crate::vm::types::Value;
use crate::vm::ClarityVersion;

define_versioned_named_enum_with_max!(NativeVariables(ClarityVersion) {
    ContractCaller("contract-caller", ClarityVersion::Clarity1, None),
    TxSender("tx-sender", ClarityVersion::Clarity1, None),
    BlockHeight("block-height", ClarityVersion::Clarity1, Some(ClarityVersion::Clarity2)),
    BurnBlockHeight("burn-block-height", ClarityVersion::Clarity1, None),
    NativeNone("none", ClarityVersion::Clarity1, None),
    NativeTrue("true", ClarityVersion::Clarity1, None),
    NativeFalse("false", ClarityVersion::Clarity1, None),
    TotalLiquidMicroSTX("stx-liquid-supply", ClarityVersion::Clarity1, None),
    Regtest("is-in-regtest", ClarityVersion::Clarity1, None),
    TxSponsor("tx-sponsor?", ClarityVersion::Clarity2, None),
    Mainnet("is-in-mainnet", ClarityVersion::Clarity2, None),
    ChainId("chain-id", ClarityVersion::Clarity2, None),
    StacksBlockHeight("stacks-block-height", ClarityVersion::Clarity3, None),
    TenureHeight("tenure-height", ClarityVersion::Clarity3, None),
});

pub fn is_reserved_name(name: &str, version: &ClarityVersion) -> bool {
    NativeVariables::lookup_by_name_at_version(name, version).is_some()
}

pub fn lookup_reserved_variable(
    name: &str,
    _context: &LocalContext,
    env: &mut Environment,
) -> Result<Option<Value>> {
    if let Some(variable) =
        NativeVariables::lookup_by_name_at_version(name, env.contract_context.get_clarity_version())
    {
        match variable {
            NativeVariables::TxSender => {
                let sender = env
                    .sender
                    .clone()
                    .ok_or(RuntimeErrorType::NoSenderInContext)?;
                Ok(Some(Value::Principal(sender)))
            }
            NativeVariables::ContractCaller => {
                let caller = env
                    .caller
                    .clone()
                    .ok_or(RuntimeErrorType::NoCallerInContext)?;
                Ok(Some(Value::Principal(caller)))
            }
            NativeVariables::TxSponsor => {
                let sponsor = match env.sponsor.clone() {
                    None => Value::none(),
                    Some(p) => Value::some(Value::Principal(p)).map_err(|_| {
                        InterpreterError::Expect(
                            "ERROR: principal should be a valid Clarity object".into(),
                        )
                    })?,
                };
                Ok(Some(sponsor))
            }
            NativeVariables::BlockHeight => {
                runtime_cost(ClarityCostFunction::FetchVar, env, 1)?;
                // In epoch 2.x, the `block-height` keyword returns the Stacks block height.
                // For Clarity 1 and Clarity 2 contracts executing in epoch 3, `block-height`
                // is equal to the tenure height instead of the Stacks block height. This change
                // is made to maintain a similar pace at which this value increments (e.g. for use
                // as an expiration). In Clarity 3, `block-height` is removed to avoid confusion.
                // It is replaced with two new keywords: `stacks-block-height` and `tenure-height`.
                if env.global_context.epoch_id < StacksEpochId::Epoch30 {
                    let block_height = env.global_context.database.get_current_block_height();
                    Ok(Some(Value::UInt(block_height as u128)))
                } else {
                    let tenure_height = env.global_context.database.get_tenure_height()?;
                    Ok(Some(Value::UInt(tenure_height as u128)))
                }
            }
            NativeVariables::BurnBlockHeight => {
                runtime_cost(ClarityCostFunction::FetchVar, env, 1)?;
                let burn_block_height = env
                    .global_context
                    .database
                    .get_current_burnchain_block_height()?;
                Ok(Some(Value::UInt(u128::from(burn_block_height))))
            }
            NativeVariables::NativeNone => Ok(Some(Value::none())),
            NativeVariables::NativeTrue => Ok(Some(Value::Bool(true))),
            NativeVariables::NativeFalse => Ok(Some(Value::Bool(false))),
            NativeVariables::TotalLiquidMicroSTX => {
                runtime_cost(ClarityCostFunction::FetchVar, env, 1)?;
                let liq = env.global_context.database.get_total_liquid_ustx()?;
                Ok(Some(Value::UInt(liq)))
            }
            NativeVariables::Regtest => {
                let reg = env.global_context.database.is_in_regtest();
                Ok(Some(Value::Bool(reg)))
            }
            NativeVariables::Mainnet => {
                let mainnet = env.global_context.mainnet;
                Ok(Some(Value::Bool(mainnet)))
            }
            NativeVariables::ChainId => {
                let chain_id = env.global_context.chain_id;
                Ok(Some(Value::UInt(chain_id.into())))
            }
            NativeVariables::StacksBlockHeight => {
                runtime_cost(ClarityCostFunction::FetchVar, env, 1)?;
                let block_height = env.global_context.database.get_current_block_height();
                Ok(Some(Value::UInt(block_height as u128)))
            }
            NativeVariables::TenureHeight => {
                runtime_cost(ClarityCostFunction::FetchVar, env, 1)?;
                let tenure_height = env.global_context.database.get_tenure_height()?;
                Ok(Some(Value::UInt(tenure_height as u128)))
            }
        }
    } else {
        Ok(None)
    }
}
