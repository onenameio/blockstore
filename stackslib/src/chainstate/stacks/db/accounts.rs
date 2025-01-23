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

use std::collections::HashMap;

use clarity::types::chainstate::TenureBlockId;
use clarity::vm::database::clarity_store::*;
use clarity::vm::database::*;
use clarity::vm::types::*;
use rusqlite::types::ToSql;
use rusqlite::{params, Row};
use stacks_common::types::chainstate::{StacksAddress, StacksBlockId};

use crate::burnchains::Address;
use crate::chainstate::stacks::db::blocks::*;
use crate::chainstate::stacks::db::*;
use crate::chainstate::stacks::{Error, *};
use crate::clarity::vm::types::StacksAddressExtensions;
use crate::clarity_vm::clarity::{ClarityConnection, ClarityTransactionConnection};
use crate::core::StacksEpochId;
use crate::util_lib::db::{Error as db_error, *};

/// A record of a coin reward for a miner.  There will be at most two of these for a miner: one for
/// the coinbase + block-txs + confirmed-mblock-txs, and one for the produced-mblock-txs.  The
/// latter reward only stores the produced-mblock-txs, and is only ever stored if the microblocks
/// are ever confirmed.
#[derive(Debug, Clone, PartialEq)]
pub struct MinerReward {
    /// address of the miner that produced the block
    pub address: StacksAddress,
    /// address of the entity that receives the block reward.
    /// Ignored pre-2.1
    pub recipient: PrincipalData,
    /// block coinbase
    pub coinbase: u128,
    /// block transaction fees
    pub tx_fees_anchored: u128,
    /// microblock transaction fees from transactions *mined* by this miner
    pub tx_fees_streamed_produced: u128,
    /// microblock transaction fees from transactions *confirmed* by this miner
    pub tx_fees_streamed_confirmed: u128,
    /// virtual transaction index in the block where these rewards get applied.  the miner's reward
    /// is applied first (so vtxindex == 0) and user-burn supports would be applied after (so
    /// vtxindex > 0).
    pub vtxindex: u32,
}

impl FromRow<MinerPaymentSchedule> for MinerPaymentSchedule {
    fn from_row(row: &Row) -> Result<MinerPaymentSchedule, db_error> {
        let address = StacksAddress::from_column(row, "address")?;
        let recipient_str: Option<String> = row.get_unwrap("recipient");
        let recipient = recipient_str
            .map(|s| PrincipalData::parse(&s).expect("FATAL: could not parse recipient principal"))
            .unwrap_or(address.to_account_principal());
        let block_hash = BlockHeaderHash::from_column(row, "block_hash")?;
        let consensus_hash = ConsensusHash::from_column(row, "consensus_hash")?;
        let parent_block_hash = BlockHeaderHash::from_column(row, "parent_block_hash")?;
        let parent_consensus_hash = ConsensusHash::from_column(row, "parent_consensus_hash")?;

        let coinbase_text: String = row.get_unwrap("coinbase");
        let db_tx_fees_anchored_text: String = row.get_unwrap("tx_fees_anchored");
        let db_tx_fees_streamed_text: String = row.get_unwrap("tx_fees_streamed");
        let burnchain_commit_burn = u64::from_column(row, "burnchain_commit_burn")?;
        let burnchain_sortition_burn = u64::from_column(row, "burnchain_sortition_burn")?;
        let miner: bool = row.get_unwrap("miner");
        let stacks_block_height = u64::from_column(row, "stacks_block_height")?;
        let vtxindex: u32 = row.get_unwrap("vtxindex");

        let schedule_type: HeaderTypeNames =
            row.get("schedule_type").unwrap_or(HeaderTypeNames::Epoch2);

        let coinbase = coinbase_text
            .parse::<u128>()
            .map_err(|_e| db_error::ParseError)?;
        let db_tx_fees_anchored = db_tx_fees_anchored_text
            .parse::<u128>()
            .map_err(|_e| db_error::ParseError)?;
        let db_tx_fees_streamed = db_tx_fees_streamed_text
            .parse::<u128>()
            .map_err(|_e| db_error::ParseError)?;

        let tx_fees = match schedule_type {
            HeaderTypeNames::Nakamoto => MinerPaymentTxFees::Nakamoto {
                parent_fees: db_tx_fees_anchored,
            },
            HeaderTypeNames::Epoch2 => MinerPaymentTxFees::Epoch2 {
                anchored: db_tx_fees_anchored,
                streamed: db_tx_fees_streamed,
            },
        };

        let payment_data = MinerPaymentSchedule {
            address,
            recipient,
            block_hash,
            consensus_hash,
            parent_block_hash,
            parent_consensus_hash,
            coinbase,
            tx_fees,
            burnchain_commit_burn,
            burnchain_sortition_burn,
            miner,
            stacks_block_height,
            vtxindex,
        };
        Ok(payment_data)
    }
}

impl FromRow<MinerReward> for MinerReward {
    fn from_row(row: &Row) -> Result<MinerReward, db_error> {
        let address = StacksAddress::from_column(row, "address")?;
        let recipient_str: Option<String> = row.get_unwrap("recipient");
        let recipient = recipient_str
            .map(|s| PrincipalData::parse(&s).expect("FATAL: could not parse recipient principal"))
            .unwrap_or(address.to_account_principal());
        let vtxindex: u32 = row.get_unwrap("vtxindex");
        let coinbase_text: String = row.get_unwrap("coinbase");
        let tx_fees_anchored_text: String = row.get_unwrap("tx_fees_anchored");
        let tx_fees_streamed_confirmed_text: String = row.get_unwrap("tx_fees_streamed_confirmed");
        let tx_fees_streamed_produced_text: String = row.get_unwrap("tx_fees_streamed_produced");

        let coinbase = coinbase_text
            .parse::<u128>()
            .map_err(|_e| db_error::ParseError)?;
        let tx_fees_anchored = tx_fees_anchored_text
            .parse::<u128>()
            .map_err(|_e| db_error::ParseError)?;
        let tx_fees_streamed_confirmed = tx_fees_streamed_confirmed_text
            .parse::<u128>()
            .map_err(|_e| db_error::ParseError)?;
        let tx_fees_streamed_produced = tx_fees_streamed_produced_text
            .parse::<u128>()
            .map_err(|_e| db_error::ParseError)?;

        Ok(MinerReward {
            address,
            recipient,
            coinbase,
            tx_fees_anchored,
            tx_fees_streamed_produced,
            tx_fees_streamed_confirmed,
            vtxindex,
        })
    }
}

impl MinerReward {
    pub fn total(&self) -> u128 {
        self.coinbase
            + self.tx_fees_anchored
            + self.tx_fees_streamed_produced
            + self.tx_fees_streamed_confirmed
    }

    pub fn is_child(&self) -> bool {
        self.coinbase > 0 && self.tx_fees_streamed_produced == 0
    }

    pub fn is_parent(&self) -> bool {
        self.coinbase == 0
    }

    pub fn try_add_parent(&self, other: &MinerReward) -> Option<MinerReward> {
        if !other.is_parent() {
            return None;
        }
        if !self.is_child() {
            return None;
        }
        Some(MinerReward {
            address: self.address.clone(),
            recipient: self.recipient.clone(),
            coinbase: self.coinbase,
            tx_fees_anchored: self.tx_fees_anchored,
            tx_fees_streamed_produced: other.tx_fees_streamed_produced,
            tx_fees_streamed_confirmed: self.tx_fees_streamed_confirmed,
            vtxindex: self.vtxindex,
        })
    }

    pub fn genesis(mainnet: bool) -> MinerReward {
        MinerReward {
            address: StacksAddress::burn_address(mainnet),
            recipient: StacksAddress::burn_address(mainnet).to_account_principal(),
            coinbase: 0,
            tx_fees_anchored: 0,
            tx_fees_streamed_produced: 0,
            tx_fees_streamed_confirmed: 0,
            vtxindex: 0,
        }
    }
}

impl MinerPaymentSchedule {
    /// If this is a MinerPaymentSchedule for a miner who _confirmed_ a microblock stream, then
    /// this calculates the percentage of that stream this miner is entitled to
    pub fn streamed_tx_fees_confirmed(&self) -> u128 {
        let tx_fees_streamed = match self.tx_fees {
            MinerPaymentTxFees::Epoch2 { streamed, .. } => streamed,
            MinerPaymentTxFees::Nakamoto { .. } => 0,
        };
        (tx_fees_streamed * 3) / 5
    }

    /// If this is a MinerPaymentSchedule for a miner who _produced_ a microblock stream, then
    /// this calculates the percentage of that stream this miner is entitled to
    pub fn streamed_tx_fees_produced(&self) -> u128 {
        let tx_fees_streamed = match self.tx_fees {
            MinerPaymentTxFees::Epoch2 { streamed, .. } => streamed,
            MinerPaymentTxFees::Nakamoto { .. } => 0,
        };
        (tx_fees_streamed * 2) / 5
    }

    /// Empty miner payment schedule -- i.e. for the genesis block
    pub fn genesis(mainnet: bool) -> MinerPaymentSchedule {
        MinerPaymentSchedule {
            address: StacksAddress::burn_address(mainnet),
            recipient: StacksAddress::burn_address(mainnet).to_account_principal(),
            block_hash: FIRST_STACKS_BLOCK_HASH.clone(),
            consensus_hash: FIRST_BURNCHAIN_CONSENSUS_HASH.clone(),
            parent_block_hash: FIRST_STACKS_BLOCK_HASH.clone(),
            parent_consensus_hash: FIRST_BURNCHAIN_CONSENSUS_HASH.clone(),
            coinbase: 0,
            tx_fees: MinerPaymentTxFees::Epoch2 {
                anchored: 0,
                streamed: 0,
            },
            burnchain_commit_burn: 0,
            burnchain_sortition_burn: 0,
            miner: true,
            stacks_block_height: 0,
            vtxindex: 0,
        }
    }
}

impl StacksChainState {
    pub fn get_account<T: ClarityConnection>(
        clarity_tx: &mut T,
        principal: &PrincipalData,
    ) -> StacksAccount {
        clarity_tx
            .with_clarity_db_readonly(|ref mut db| {
                let stx_balance = db.get_account_stx_balance(principal)?;
                let nonce = db.get_account_nonce(principal)?;
                Ok(StacksAccount {
                    principal: principal.clone(),
                    stx_balance,
                    nonce,
                })
            })
            .map_err(Error::ClarityError)
            .unwrap_or_else(|e| {
                error!(
                    "FATAL: Failed to query account for {:?}: {:?}",
                    principal, &e
                );
                panic!();
            })
    }

    pub fn get_nonce<T: ClarityConnection>(clarity_tx: &mut T, principal: &PrincipalData) -> u64 {
        clarity_tx
            .with_clarity_db_readonly(|ref mut db| db.get_account_nonce(principal))
            .map_err(|x| Error::ClarityError(x.into()))
            .unwrap_or_else(|e| {
                error!(
                    "FATAL: Failed to query account nonce for {:?}: {:?}",
                    principal, &e
                );
                panic!();
            })
    }

    pub fn get_account_ft(
        clarity_tx: &mut ClarityTx,
        contract_id: &QualifiedContractIdentifier,
        token_name: &str,
        principal: &PrincipalData,
    ) -> Result<u128, Error> {
        clarity_tx
            .connection()
            .with_clarity_db_readonly(|ref mut db| {
                let ft_balance = db.get_ft_balance(contract_id, token_name, principal, None)?;
                Ok(ft_balance)
            })
            .map_err(Error::ClarityError)
    }

    pub fn get_account_nft(
        clarity_tx: &mut ClarityTx,
        contract_id: &QualifiedContractIdentifier,
        token_name: &str,
        token_value: &Value,
    ) -> Result<PrincipalData, Error> {
        clarity_tx
            .connection()
            .with_clarity_db_readonly(|ref mut db| {
                let expected_asset_type = db.get_nft_key_type(contract_id, token_name)?;
                let nft_owner =
                    db.get_nft_owner(contract_id, token_name, token_value, &expected_asset_type)?;
                Ok(nft_owner)
            })
            .map_err(Error::ClarityError)
    }

    /// Called each time a transaction is invoked from this principal, to e.g.
    /// debit the STX-denominated tx fee or transfer/burn STX.
    /// Will consolidate unlocked STX.
    /// DOES NOT UPDATE THE NONCE
    pub fn account_debit(
        clarity_tx: &mut ClarityTransactionConnection,
        principal: &PrincipalData,
        amount: u64,
    ) {
        clarity_tx
            .with_clarity_db(|ref mut db| {
                let mut snapshot = db.get_stx_balance_snapshot(principal)?;

                // last line of defense: if we don't have sufficient funds, panic.
                // This should be checked by the block validation logic.
                if !snapshot.can_transfer(amount as u128)? {
                    panic!(
                        "Tried to debit {} from account {} (which only has {})",
                        amount,
                        principal,
                        snapshot.get_available_balance()?
                    );
                }

                snapshot.debit(amount as u128)?;
                snapshot.save()?;
                Ok(())
            })
            .unwrap_or_else(|e| {
                error!(
                    "FATAL: failed to debit account {:?} for {} uSTX: {:?}",
                    principal, amount, &e
                );
                panic!();
            })
    }

    /// Called each time a transaction sends STX to this principal.
    /// No nonce update is needed, since the transfer action is not taken by the principal.
    pub fn account_credit(
        clarity_tx: &mut ClarityTransactionConnection,
        principal: &PrincipalData,
        amount: u64,
    ) {
        clarity_tx
            .with_clarity_db(|ref mut db| {
                let mut snapshot = db.get_stx_balance_snapshot(principal)?;
                snapshot.credit(amount as u128)?;

                let new_balance = snapshot.get_available_balance()?;
                snapshot.save()?;

                info!("{} credited: {} uSTX", principal, new_balance);
                Ok(())
            })
            .unwrap_or_else(|e| {
                error!(
                    "FATAL: failed to credit account {:?} for {} uSTX: {:?}",
                    principal, amount, &e
                );
                panic!();
            })
    }

    /// Called during the genesis / boot sequence.
    pub fn account_genesis_credit(
        clarity_tx: &mut ClarityTransactionConnection,
        principal: &PrincipalData,
        amount: u128,
    ) {
        clarity_tx
            .with_clarity_db(|ref mut db| {
                let mut snapshot = db.get_stx_balance_snapshot_genesis(principal)?;
                snapshot.credit(amount)?;
                snapshot.save()?;
                Ok(())
            })
            .unwrap_or_else(|e| {
                error!(
                    "FATAL: failed to credit genesis account {:?} for {} uSTX: {:?}",
                    principal, amount, &e
                );
                panic!();
            })
    }

    /// Increment an account's nonce
    pub fn update_account_nonce(
        clarity_tx: &mut ClarityTransactionConnection,
        principal: &PrincipalData,
        cur_nonce: u64,
    ) {
        clarity_tx
            .with_clarity_db(|ref mut db| {
                let next_nonce = cur_nonce.checked_add(1).unwrap_or_else(|| {
                    error!("OUT OF NONCES");
                    panic!();
                });

                db.set_account_nonce(&principal, next_nonce)?;
                Ok(())
            })
            .unwrap_or_else(|e| {
                error!(
                    "FATAL: failed to update account nonce for account {:?} from {}: {:?}",
                    principal, cur_nonce, &e
                );
                panic!();
            })
    }

    /// Schedule a miner payment in the future.
    /// Schedules payments out to both miners and users that support them.
    pub fn insert_miner_payment_schedule(
        tx: &mut DBTx,
        block_reward: &MinerPaymentSchedule,
    ) -> Result<(), Error> {
        assert!(block_reward.burnchain_commit_burn < i64::MAX as u64);
        assert!(block_reward.burnchain_sortition_burn < i64::MAX as u64);
        assert!(block_reward.stacks_block_height < i64::MAX as u64);

        let index_block_hash =
            StacksBlockId::new(&block_reward.consensus_hash, &block_reward.block_hash);

        let (payment_type, db_tx_fees_anchored, db_tx_fees_streamed) = match block_reward.tx_fees {
            MinerPaymentTxFees::Epoch2 { anchored, streamed } => {
                (HeaderTypeNames::Epoch2, anchored, streamed)
            }
            MinerPaymentTxFees::Nakamoto { parent_fees } => {
                (HeaderTypeNames::Nakamoto, parent_fees, 0)
            }
        };

        let args = params![
            block_reward.address.to_string(),
            block_reward.recipient.to_string(),
            block_reward.block_hash,
            block_reward.consensus_hash,
            block_reward.parent_block_hash,
            block_reward.parent_consensus_hash,
            block_reward.coinbase.to_string(),
            db_tx_fees_anchored.to_string(),
            db_tx_fees_streamed.to_string(),
            u64_to_sql(block_reward.burnchain_commit_burn)?,
            u64_to_sql(block_reward.burnchain_sortition_burn)?,
            u64_to_sql(block_reward.stacks_block_height)?,
            true,
            0i64,
            index_block_hash,
            payment_type,
            "0".to_string(),
        ];

        tx.execute(
            "INSERT INTO payments (
                        address,
                        recipient,
                        block_hash,
                        consensus_hash,
                        parent_block_hash,
                        parent_consensus_hash,
                        coinbase,
                        tx_fees_anchored,
                        tx_fees_streamed,
                        burnchain_commit_burn,
                        burnchain_sortition_burn,
                        stacks_block_height,
                        miner,
                        vtxindex,
                        index_block_hash,
                        schedule_type,
                        stx_burns
                    )
                    VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14,?15,?16,?17)",
            args,
        )
        .map_err(|e| Error::DBError(db_error::SqliteError(e)))?;

        Ok(())
    }

    /// Store a matured miner reward for subsequent query in Clarity, without doing any validation
    fn inner_insert_matured_miner_reward(
        tx: &mut DBTx<'_>,
        parent_block_id: &StacksBlockId,
        child_block_id: &StacksBlockId,
        reward: &MinerReward,
    ) -> Result<(), Error> {
        // the only time it's okay to re-insert the same reward is if there are two Stacks forks
        // trying to store the same matured rewards for a common ancestor block.
        let cur_rewards = StacksChainState::inner_get_matured_miner_payments(
            tx,
            &(*parent_block_id).into(),
            &(*child_block_id).into(),
        )?;
        if !cur_rewards.is_empty() {
            let mut present = false;
            for rw in cur_rewards.iter() {
                if (rw.is_parent() && reward.is_parent()) || (rw.is_child() && reward.is_child()) {
                    // must insert a parent or a child at most once
                    assert_eq!(rw, reward, "FATAL: tried to insert multiple distinct matured parent block reward records");
                    present = true;
                }
            }

            if present {
                return Ok(());
            }
        }

        // not present
        let sql = "INSERT INTO matured_rewards (
            address,
            recipient,
            vtxindex,
            coinbase,
            tx_fees_anchored,
            tx_fees_streamed_confirmed,
            tx_fees_streamed_produced,
            parent_index_block_hash,
            child_index_block_hash
        ) VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9)";

        let args = params![
            reward.address.to_string(),
            reward.recipient.to_string(),
            reward.vtxindex,
            reward.coinbase.to_string(),
            reward.tx_fees_anchored.to_string(),
            reward.tx_fees_streamed_confirmed.to_string(),
            reward.tx_fees_streamed_produced.to_string(),
            parent_block_id,
            child_block_id,
        ];

        tx.execute(sql, args)
            .map_err(|e| Error::DBError(db_error::SqliteError(e)))?;

        Ok(())
    }

    /// Store a parent block's matured reward.  This is the share of the streamed tx fees produced
    /// by the miner who mined this block, and nothing else.
    pub fn insert_matured_parent_miner_reward(
        tx: &mut DBTx<'_>,
        parent_block_id: &StacksBlockId,
        child_block_id: &StacksBlockId,
        parent_reward: &MinerReward,
    ) -> Result<(), Error> {
        test_debug!(
            "Insert matured parent miner reward for {}-{}: {:?}",
            parent_block_id,
            child_block_id,
            parent_reward
        );
        assert!(
            parent_reward.is_parent(),
            "FATAL: tried to insert a non-parent reward as the parent reward"
        );
        assert_eq!(
            parent_reward.vtxindex, 0,
            "FATAL: tried to insert a user reward as a miner reward"
        );
        StacksChainState::inner_insert_matured_miner_reward(
            tx,
            parent_block_id,
            child_block_id,
            parent_reward,
        )
    }

    /// Store a child block's matured miner reward.  This is the block's coinbase, anchored tx fees, and
    /// share of the confirmed streamed tx fees
    pub fn insert_matured_child_miner_reward(
        tx: &mut DBTx<'_>,
        parent_block_id: &StacksBlockId,
        child_block_id: &StacksBlockId,
        child_reward: &MinerReward,
    ) -> Result<(), Error> {
        test_debug!(
            "Insert matured child miner reward for {}-{}: {:?}",
            parent_block_id,
            child_block_id,
            child_reward
        );
        assert!(
            child_reward.is_child(),
            "FATAL: tried to insert a non-child reward as the child reward"
        );
        assert_eq!(
            child_reward.vtxindex, 0,
            "FATAL: tried to insert a user reward as a miner reward"
        );
        StacksChainState::inner_insert_matured_miner_reward(
            tx,
            parent_block_id,
            child_block_id,
            child_reward,
        )
    }

    /// Store a child block's matured user burn-support reward.  This is the share of the
    /// block's coinbase, anchored tx fees, and share of the confirmed streamed tx fees that go to
    /// the user burn-support sender
    pub fn insert_matured_child_user_reward(
        tx: &mut DBTx<'_>,
        parent_block_id: &StacksBlockId,
        child_block_id: &StacksBlockId,
        child_reward: &MinerReward,
    ) -> Result<(), Error> {
        assert!(
            child_reward.is_child(),
            "FATAL: tried to insert a non-child reward as the child reward"
        );
        assert!(
            child_reward.vtxindex > 0,
            "FATAL: tried to insert a miner reward as a user reward"
        );
        StacksChainState::inner_insert_matured_miner_reward(
            tx,
            parent_block_id,
            child_block_id,
            child_reward,
        )
    }

    fn inner_get_matured_miner_payments(
        conn: &DBConn,
        parent_block_id: &TenureBlockId,
        child_block_id: &TenureBlockId,
    ) -> Result<Vec<MinerReward>, Error> {
        let sql = "SELECT * FROM matured_rewards WHERE parent_index_block_hash = ?1 AND child_index_block_hash = ?2 AND vtxindex = 0";
        let args = params![parent_block_id.0, child_block_id.0];
        let ret: Vec<MinerReward> = query_rows(conn, sql, args).map_err(Error::DBError)?;
        Ok(ret)
    }

    /// Get the matured miner reward for a block's miner.
    /// You'd be querying for the `child_block_id`'s reward.
    pub fn get_matured_miner_payment(
        conn: &DBConn,
        parent_block_id: &TenureBlockId,
        child_block_id: &TenureBlockId,
    ) -> Result<Option<MinerReward>, Error> {
        let config = StacksChainState::load_db_config(conn)?;
        let ret = StacksChainState::inner_get_matured_miner_payments(
            conn,
            parent_block_id,
            child_block_id,
        )?;
        if ret.len() == 2 {
            let reward = if ret[0].is_child() {
                ret[0]
                    .try_add_parent(&ret[1])
                    .expect("FATAL: got two child rewards")
            } else if ret[1].is_child() {
                ret[1]
                    .try_add_parent(&ret[0])
                    .expect("FATAL: got two child rewards")
            } else {
                panic!("FATAL: got two parent rewards");
            };
            Ok(Some(reward))
        } else if child_block_id.0
            == StacksBlockHeader::make_index_block_hash(
                &FIRST_BURNCHAIN_CONSENSUS_HASH,
                &FIRST_STACKS_BLOCK_HASH,
            )
        {
            Ok(Some(MinerReward::genesis(config.mainnet)))
        } else {
            Ok(None)
        }
    }

    /// Find the reported poison-microblock data for this block
    /// Returns None if there are no forks.
    pub fn get_poison_microblock_report<T: ClarityConnection>(
        clarity_tx: &mut T,
        height: u64,
    ) -> Result<Option<(StacksAddress, u16)>, Error> {
        let principal_seq_opt = clarity_tx
            .with_clarity_db_readonly(|ref mut db| db.get_microblock_poison_report(height as u32))
            .map_err(|e| Error::ClarityError(e.into()))?;

        Ok(principal_seq_opt.map(|(principal, seq)| (principal.into(), seq)))
    }

    /// Get the scheduled miner rewards at a particular index hash
    pub fn get_scheduled_block_rewards_at_block(
        conn: &DBConn,
        index_block_hash: &StacksBlockId,
    ) -> Result<Vec<MinerPaymentSchedule>, Error> {
        let qry =
            "SELECT * FROM payments WHERE index_block_hash = ?1 ORDER BY vtxindex ASC".to_string();
        let args = params![index_block_hash];
        let rows =
            query_rows::<MinerPaymentSchedule, _>(conn, &qry, args).map_err(Error::DBError)?;
        test_debug!("{} rewards in {}", rows.len(), index_block_hash);
        Ok(rows)
    }

    /// Get the scheduled miner rewards in a particular Stacks fork at a particular height.
    pub fn get_scheduled_block_rewards_in_fork_at_height(
        tx: &mut StacksDBTx<'_>,
        tip: &StacksHeaderInfo,
        block_height: u64,
    ) -> Result<Vec<MinerPaymentSchedule>, Error> {
        let ancestor_info = match StacksChainState::get_tip_ancestor(tx, tip, block_height)? {
            Some(info) => info,
            None => {
                test_debug!("No ancestor at height {}", block_height);
                return Ok(vec![]);
            }
        };

        let qry = "SELECT * FROM payments WHERE block_hash = ?1 AND consensus_hash = ?2 ORDER BY vtxindex ASC".to_string();
        let args = params![
            ancestor_info.anchored_header.block_hash(),
            ancestor_info.consensus_hash,
        ];
        let rows = query_rows::<MinerPaymentSchedule, _>(tx, &qry, args).map_err(Error::DBError)?;
        test_debug!(
            "{} rewards in {}/{}",
            rows.len(),
            &ancestor_info.consensus_hash,
            &ancestor_info.anchored_header.block_hash()
        );
        Ok(rows)
    }

    /// Get the scheduled miner rewards in a particular Stacks fork at a particular height.
    pub fn get_scheduled_block_rewards(
        tx: &mut StacksDBTx,
        tip: &StacksHeaderInfo,
    ) -> Result<Vec<MinerPaymentSchedule>, Error> {
        if tip.stacks_block_height < MINER_REWARD_MATURITY {
            return Ok(vec![]);
        }

        let block_height = tip.stacks_block_height - MINER_REWARD_MATURITY;
        StacksChainState::get_scheduled_block_rewards_in_fork_at_height(tx, tip, block_height)
    }

    /// Get the miner info at a particular burn/stacks block
    pub fn get_miner_info(
        conn: &DBConn,
        consensus_hash: &ConsensusHash,
        stacks_block_hash: &BlockHeaderHash,
    ) -> Result<Option<MinerPaymentSchedule>, Error> {
        let qry =
            "SELECT * FROM payments WHERE consensus_hash = ?1 AND block_hash = ?2 AND miner = 1"
                .to_string();
        let args = params![consensus_hash, stacks_block_hash,];
        let mut rows =
            query_rows::<MinerPaymentSchedule, _>(conn, &qry, args).map_err(Error::DBError)?;
        let len = rows.len();
        match len {
            0 => {
                test_debug!(
                    "No miner information for {}/{}",
                    consensus_hash,
                    stacks_block_hash
                );
                Ok(None)
            }
            1 => Ok(rows.pop()),
            _ => {
                panic!(
                    "Multiple miners for {}/{}",
                    consensus_hash, stacks_block_hash
                );
            }
        }
    }

    /// What's the commission for reporting a poison microblock stream?
    fn poison_microblock_commission(coinbase: u128) -> u128 {
        (coinbase * POISON_MICROBLOCK_COMMISSION_FRACTION) / 100
    }

    /// Calculate a block mining participant's coinbase reward, given the block's miner and list of
    /// user-burn-supporters.
    ///
    /// If poison_reporter_opt is not None, then the returned MinerReward will reward the _poison reporter_,
    /// not the miner, for reporting the microblock stream fork.
    fn calculate_miner_reward(
        mainnet: bool,
        parent_block_epoch: StacksEpochId,
        participant: &MinerPaymentSchedule,
        miner: &MinerPaymentSchedule,
        users: &[MinerPaymentSchedule],
        parent: &MinerPaymentSchedule,
        poison_reporter_opt: Option<&StacksAddress>,
    ) -> (MinerReward, MinerReward) {
        ////////////////////// coinbase reward total /////////////////////////////////
        let (this_burn_total, other_burn_total) = {
            if participant.miner {
                // we're calculating the miner's reward
                let mut total_user: u128 = 0;
                for user_support in users.iter() {
                    total_user = total_user
                        .checked_add(user_support.burnchain_commit_burn as u128)
                        .expect("FATAL: user support burn overflow");
                }
                (participant.burnchain_commit_burn as u128, total_user)
            } else {
                // we're calculating a user burn support's reward
                let mut this_user: u128 = 0;
                let mut total_other: u128 = miner.burnchain_commit_burn as u128;
                for user_support in users.iter() {
                    if user_support.address != participant.address {
                        total_other = total_other
                            .checked_add(user_support.burnchain_commit_burn as u128)
                            .expect("FATAL: user support burn overflow");
                    } else {
                        this_user = user_support.burnchain_commit_burn as u128;
                    }
                }
                (this_user, total_other)
            }
        };

        let burn_total = other_burn_total
            .checked_add(this_burn_total)
            .expect("FATAL: combined burns exceed u128");

        test_debug!(
            "{}: Coinbase reward = {} * ({}/{})",
            participant.address.to_string(),
            participant.coinbase,
            this_burn_total,
            burn_total
        );

        // in the case of shadow blocks, there will be zero burns.
        // the coinbase is still generated, but it's rendered unspendable
        let (this_burn_total, burn_total) = if burn_total == 0 {
            (1, 1)
        } else {
            (this_burn_total, burn_total)
        };

        // each participant gets a share of the coinbase proportional to the fraction it burned out
        // of all participants' burns.
        let coinbase_reward = participant
            .coinbase
            .checked_mul(this_burn_total)
            .expect("FATAL: STX coinbase reward overflow")
            / burn_total;

        // process poison -- someone can steal a fraction of the total coinbase if they can present
        // evidence that the miner forked the microblock stream.  The remainder of the coinbase is
        // destroyed if this happens.
        let (child_address, child_recipient, coinbase_reward, punished) =
            if let Some(reporter_address) = poison_reporter_opt {
                if participant.miner {
                    // the poison-reporter, not the miner, gets a (fraction of the) reward
                    debug!(
                        "{:?} will recieve poison-microblock commission {}",
                        &reporter_address.to_string(),
                        StacksChainState::poison_microblock_commission(coinbase_reward)
                    );
                    (
                        reporter_address.clone(),
                        reporter_address.to_account_principal(),
                        StacksChainState::poison_microblock_commission(coinbase_reward),
                        true,
                    )
                } else {
                    // users that helped a miner that reported a poison-microblock get nothing
                    (
                        StacksAddress::burn_address(mainnet),
                        StacksAddress::burn_address(mainnet).to_account_principal(),
                        0,
                        false,
                    )
                }
            } else {
                // no poison microblock reported
                (
                    participant.address,
                    participant.recipient.clone(),
                    coinbase_reward,
                    false,
                )
            };

        let (tx_fees_anchored, parent_tx_fees_streamed_produced, tx_fees_streamed_confirmed) =
            if participant.miner {
                // only award tx fees to the miner, and only if the miner was not punished.
                // parent gets its produced tx fees regardless of punishment.

                match participant.tx_fees {
                    MinerPaymentTxFees::Epoch2 {
                        anchored,
                        streamed: _,
                    } => {
                        // if the payment type is Epoch2, then reward fees according to old Epoch2 rules
                        let anchored_fees = if !punished { anchored } else { 0 };
                        let parent_streamed_fees = if parent_block_epoch < StacksEpochId::Epoch21 {
                            // this is wrong, per #3140.  It should be
                            // `participant.streamed_tx_fees_produced()`, since
                            // `participant.tx_fees_streamed` contains the sum of the microblock
                            // transaction fees that `participant` confirmed (and thus `participant`'s
                            // parent produced).  But we're stuck with it for earlier epochs.
                            parent.streamed_tx_fees_produced()
                        } else {
                            participant.streamed_tx_fees_produced()
                        };
                        let streamed_confirmed_fees = if !punished {
                            participant.streamed_tx_fees_confirmed()
                        } else {
                            0
                        };
                        (anchored_fees, parent_streamed_fees, streamed_confirmed_fees)
                    }
                    MinerPaymentTxFees::Nakamoto { parent_fees } => {
                        // in nakamoto, tx fees in the payment schedule correspond to the
                        //  tx fees of the *parent tenure* (because the full tenure is only known
                        //  once the next tenure change occurs).
                        (0, parent_fees, 0)
                    }
                }
            } else {
                // users get no tx fees
                (0, 0, 0)
            };

        debug!(
            "{} -> {}: {} coinbase (punished? {}), {} anchored fees, {} streamed fees confirmed; {} has produced {} fees",
            &child_address,
            &child_recipient,
            coinbase_reward,
            punished,
            tx_fees_anchored,
            tx_fees_streamed_confirmed,
            &parent.address.to_string(),
            parent_tx_fees_streamed_produced,
        );

        let parent_miner_reward = MinerReward {
            address: parent.address.clone(),
            recipient: parent.recipient.clone(),
            coinbase: 0,
            tx_fees_anchored: 0,
            tx_fees_streamed_produced: parent_tx_fees_streamed_produced,
            tx_fees_streamed_confirmed: 0,
            vtxindex: parent.vtxindex,
        };

        let miner_reward = MinerReward {
            address: child_address,
            recipient: child_recipient,
            coinbase: coinbase_reward,
            tx_fees_anchored,
            tx_fees_streamed_produced: 0,
            tx_fees_streamed_confirmed,
            vtxindex: participant.vtxindex,
        };

        (parent_miner_reward, miner_reward)
    }

    /// Find the latest miner reward to mature, assuming that there are mature rewards.
    /// Returns a list of payments to make to each address -- miners and user-support burners -- as
    /// well as an info struct about where the rewards took place on the chain.
    pub fn find_mature_miner_rewards(
        clarity_tx: &mut ClarityTx,
        sortdb_conn: &Connection,
        tip_stacks_height: u64,
        mut latest_matured_miners: Vec<MinerPaymentSchedule>,
        parent_miner: MinerPaymentSchedule,
    ) -> Result<Option<(MinerReward, Vec<MinerReward>, MinerReward, MinerRewardInfo)>, Error> {
        let mainnet = clarity_tx.config.mainnet;
        if tip_stacks_height <= MINER_REWARD_MATURITY {
            // no mature rewards exist
            return Ok(None);
        }

        let reward_height = tip_stacks_height - MINER_REWARD_MATURITY;

        assert!(!latest_matured_miners.is_empty());
        assert!(latest_matured_miners[0].vtxindex == 0);
        assert!(latest_matured_miners[0].miner);

        let users = latest_matured_miners.split_off(1);
        let miner = latest_matured_miners
            .pop()
            .expect("BUG: no matured miners despite prior check");

        let reward_info = MinerRewardInfo {
            from_stacks_block_hash: miner.block_hash.clone(),
            from_block_consensus_hash: miner.consensus_hash.clone(),
            from_parent_stacks_block_hash: parent_miner.block_hash.clone(),
            from_parent_block_consensus_hash: parent_miner.consensus_hash.clone(),
        };

        // what epoch was the parent miner's block evaluated in?
        let parent_evaluated_snapshot =
            SortitionDB::get_block_snapshot_consensus(sortdb_conn, &parent_miner.consensus_hash)?
                .expect("FATAL: no snapshot for evaluated block");

        let parent_evaluated_epoch =
            SortitionDB::get_stacks_epoch(sortdb_conn, parent_evaluated_snapshot.block_height)?
                .expect("FATAL: no epoch for evaluated block");

        // was this block penalized for mining a forked microblock stream?
        // If so, find the principal that detected the poison, and reward them instead.
        let poison_recipient_opt =
            StacksChainState::get_poison_microblock_report(clarity_tx, reward_height)?
                .map(|(reporter, _)| reporter);

        if let Some(ref _poison_reporter) = poison_recipient_opt.as_ref() {
            test_debug!(
                "Poison-microblock reporter {} at height {}",
                &_poison_reporter.to_string(),
                reward_height
            );
        } else {
            test_debug!("No poison-microblock report at height {}", reward_height);
        }

        // calculate miner reward
        let (parent_miner_reward, miner_reward) = StacksChainState::calculate_miner_reward(
            mainnet,
            parent_evaluated_epoch.epoch_id,
            &miner,
            &miner,
            &users,
            &parent_miner,
            poison_recipient_opt.as_ref(),
        );

        // calculate reward for each user-support-burn
        let mut user_rewards = vec![];
        for user_reward in users.iter() {
            let (parent_reward, reward) = StacksChainState::calculate_miner_reward(
                mainnet,
                parent_evaluated_epoch.epoch_id,
                user_reward,
                &miner,
                &users,
                &parent_miner,
                poison_recipient_opt.as_ref(),
            );
            assert_eq!(parent_reward.total(), 0);
            user_rewards.push(reward);
        }

        Ok(Some((
            miner_reward,
            user_rewards,
            parent_miner_reward,
            reward_info,
        )))
    }
}

#[cfg(test)]
mod test {
    use clarity::vm::costs::ExecutionCost;
    use clarity::vm::types::StacksAddressExtensions;
    use stacks_common::types::chainstate::BurnchainHeaderHash;
    use stacks_common::util::hash::*;

    use super::*;
    use crate::burnchains::*;
    use crate::chainstate::burn::*;
    use crate::chainstate::stacks::db::test::*;
    use crate::chainstate::stacks::index::*;
    use crate::chainstate::stacks::{Error, *};
    use crate::core::StacksEpochId;

    fn make_dummy_miner_payment_schedule(
        addr: &StacksAddress,
        coinbase: u128,
        tx_fees_anchored: u128,
        tx_fees_streamed: u128,
        commit_burn: u64,
        sortition_burn: u64,
    ) -> MinerPaymentSchedule {
        MinerPaymentSchedule {
            address: addr.clone(),
            recipient: addr.clone().to_account_principal(),
            block_hash: FIRST_STACKS_BLOCK_HASH.clone(),
            consensus_hash: FIRST_BURNCHAIN_CONSENSUS_HASH.clone(),
            parent_block_hash: FIRST_STACKS_BLOCK_HASH.clone(),
            parent_consensus_hash: FIRST_BURNCHAIN_CONSENSUS_HASH.clone(),
            coinbase,
            tx_fees: MinerPaymentTxFees::Epoch2 {
                anchored: tx_fees_anchored,
                streamed: tx_fees_streamed,
            },
            burnchain_commit_burn: commit_burn,
            burnchain_sortition_burn: sortition_burn,
            miner: true,
            stacks_block_height: 0,
            vtxindex: 0,
        }
    }

    fn make_dummy_user_payment_schedule(
        addr: &StacksAddress,
        coinbase: u128,
        tx_fees_anchored: u128,
        tx_fees_streamed: u128,
        commit_burn: u64,
        sortition_burn: u64,
        vtxindex: u32,
    ) -> MinerPaymentSchedule {
        let mut sched = make_dummy_miner_payment_schedule(
            addr,
            coinbase,
            tx_fees_anchored,
            tx_fees_streamed,
            commit_burn,
            sortition_burn,
        );
        sched.miner = false;
        sched.vtxindex = vtxindex;
        sched
    }

    fn advance_tip(
        chainstate: &mut StacksChainState,
        parent_header_info: &StacksHeaderInfo,
        block_reward: &mut MinerPaymentSchedule,
    ) -> StacksHeaderInfo {
        let mut new_tip = parent_header_info.clone();

        let mut anchored_header = new_tip.anchored_header.as_stacks_epoch2().unwrap().clone();
        anchored_header.parent_block = parent_header_info.anchored_header.block_hash();
        anchored_header.microblock_pubkey_hash =
            Hash160::from_data(&anchored_header.microblock_pubkey_hash.0);
        anchored_header.total_work.work = anchored_header.total_work.work + 1;
        new_tip.anchored_header = anchored_header.into();
        new_tip.microblock_tail = None;
        new_tip.stacks_block_height = parent_header_info.stacks_block_height + 1;
        new_tip.consensus_hash = ConsensusHash(
            Hash160::from_data(
                &Sha512Trunc256Sum::from_data(&parent_header_info.consensus_hash.0).0,
            )
            .0,
        );
        new_tip.burn_header_hash = BurnchainHeaderHash(
            Sha512Trunc256Sum::from_data(&parent_header_info.consensus_hash.0).0,
        );
        new_tip.burn_header_height = parent_header_info.burn_header_height + 1;

        block_reward.parent_consensus_hash = parent_header_info.consensus_hash.clone();
        block_reward.parent_block_hash = parent_header_info.anchored_header.block_hash().clone();
        block_reward.block_hash = new_tip.anchored_header.block_hash();
        block_reward.consensus_hash = new_tip.consensus_hash.clone();

        let mut tx = chainstate.index_tx_begin();
        let tip = StacksChainState::advance_tip(
            &mut tx,
            parent_header_info
                .anchored_header
                .as_stacks_epoch2()
                .unwrap(),
            &parent_header_info.consensus_hash,
            new_tip.anchored_header.as_stacks_epoch2().unwrap(),
            &new_tip.consensus_hash,
            &new_tip.burn_header_hash,
            new_tip.burn_header_height,
            new_tip.burn_header_timestamp,
            new_tip.microblock_tail.clone(),
            &block_reward,
            None,
            &ExecutionCost::ZERO,
            123,
            false,
            vec![],
            vec![],
            vec![],
            vec![],
            parent_header_info.anchored_header.height() + 1,
        )
        .unwrap();
        tx.commit().unwrap();
        tip
    }

    #[test]
    fn get_tip_ancestor() {
        let mut chainstate = instantiate_chainstate(false, 0x80000000, function_name!());
        let miner_1 =
            StacksAddress::from_string(&"SP1A2K3ENNA6QQ7G8DVJXM24T6QMBDVS7D0TRTAR5".to_string())
                .unwrap();
        let user_1 =
            StacksAddress::from_string(&"SP2837ZMC89J40K4YTS64B00M7065C6X46JX6ARG0".to_string())
                .unwrap();
        let mut miner_reward = make_dummy_miner_payment_schedule(&miner_1, 500, 0, 0, 1000, 1000);
        let user_reward = make_dummy_user_payment_schedule(&user_1, 500, 0, 0, 750, 1000, 1);

        // dummy reward
        let mut tip_reward = make_dummy_miner_payment_schedule(
            &StacksAddress {
                version: 0,
                bytes: Hash160([0u8; 20]),
            },
            0,
            0,
            0,
            0,
            0,
        );

        {
            let mut tx = chainstate.index_tx_begin();
            let ancestor_0 = StacksChainState::get_tip_ancestor(
                &mut tx,
                &StacksHeaderInfo::regtest_genesis(),
                0,
            )
            .unwrap();
            assert!(ancestor_0.is_some());
        }

        let parent_tip = advance_tip(
            &mut chainstate,
            &StacksHeaderInfo::regtest_genesis(),
            &mut miner_reward,
        );

        {
            let mut tx = chainstate.index_tx_begin();
            let ancestor_0 = StacksChainState::get_tip_ancestor(&mut tx, &parent_tip, 0).unwrap();
            let ancestor_1 = StacksChainState::get_tip_ancestor(&mut tx, &parent_tip, 1).unwrap();

            assert!(ancestor_1.is_some());
            assert!(ancestor_0.is_some());
            assert_eq!(ancestor_0.unwrap().stacks_block_height, 0); // block 0 is the boot block
            assert_eq!(ancestor_1.unwrap().stacks_block_height, 1);
        }

        let tip = advance_tip(&mut chainstate, &parent_tip, &mut tip_reward);

        {
            let mut tx = chainstate.index_tx_begin();
            let ancestor_2 = StacksChainState::get_tip_ancestor(&mut tx, &tip, 2).unwrap();
            let ancestor_1 = StacksChainState::get_tip_ancestor(&mut tx, &tip, 1).unwrap();
            let ancestor_0 = StacksChainState::get_tip_ancestor(&mut tx, &tip, 0).unwrap();

            assert!(ancestor_2.is_some());
            assert_eq!(ancestor_2.unwrap().stacks_block_height, 2);
            assert!(ancestor_1.is_some());
            assert_eq!(ancestor_1.unwrap().stacks_block_height, 1);
            assert!(ancestor_0.is_some());
            assert_eq!(ancestor_0.unwrap().stacks_block_height, 0); // block 0 is the boot block
        }
    }

    #[test]
    fn load_store_miner_payment_schedule() {
        let mut chainstate = instantiate_chainstate(false, 0x80000000, function_name!());
        let miner_1 =
            StacksAddress::from_string(&"SP1A2K3ENNA6QQ7G8DVJXM24T6QMBDVS7D0TRTAR5".to_string())
                .unwrap();

        let mut miner_reward = make_dummy_miner_payment_schedule(&miner_1, 500, 0, 0, 1000, 1000);

        let initial_tip = StacksHeaderInfo::regtest_genesis();

        let parent_tip = advance_tip(
            &mut chainstate,
            &StacksHeaderInfo::regtest_genesis(),
            &mut miner_reward,
        );

        // dummy reward
        let mut tip_reward = make_dummy_miner_payment_schedule(
            &StacksAddress {
                version: 0,
                bytes: Hash160([0u8; 20]),
            },
            0,
            0,
            0,
            0,
            0,
        );
        let tip = advance_tip(&mut chainstate, &parent_tip, &mut tip_reward);

        {
            let mut tx = chainstate.index_tx_begin();
            let payments_0 =
                StacksChainState::get_scheduled_block_rewards_in_fork_at_height(&mut tx, &tip, 0)
                    .unwrap();
            let payments_1 =
                StacksChainState::get_scheduled_block_rewards_in_fork_at_height(&mut tx, &tip, 1)
                    .unwrap();
            let payments_2 =
                StacksChainState::get_scheduled_block_rewards_in_fork_at_height(&mut tx, &tip, 2)
                    .unwrap();

            assert_eq!(payments_0, vec![]);
            assert_eq!(payments_1, vec![miner_reward]);
            assert_eq!(payments_2, vec![tip_reward]);
        };
    }

    #[test]
    fn load_store_miner_payment_schedule_pay_contract() {
        let mut chainstate = instantiate_chainstate(false, 0x80000000, function_name!());
        let miner_1 =
            StacksAddress::from_string(&"SP1A2K3ENNA6QQ7G8DVJXM24T6QMBDVS7D0TRTAR5".to_string())
                .unwrap();

        let mut miner_reward = make_dummy_miner_payment_schedule(&miner_1, 500, 0, 0, 1000, 1000);
        miner_reward.recipient = PrincipalData::Contract(QualifiedContractIdentifier::transient());

        let initial_tip = StacksHeaderInfo::regtest_genesis();

        let parent_tip = advance_tip(
            &mut chainstate,
            &StacksHeaderInfo::regtest_genesis(),
            &mut miner_reward,
        );

        // dummy reward
        let mut tip_reward = make_dummy_miner_payment_schedule(
            &StacksAddress {
                version: 0,
                bytes: Hash160([0u8; 20]),
            },
            0,
            0,
            0,
            0,
            0,
        );
        let tip = advance_tip(&mut chainstate, &parent_tip, &mut tip_reward);

        {
            let mut tx = chainstate.index_tx_begin();
            let payments_0 =
                StacksChainState::get_scheduled_block_rewards_in_fork_at_height(&mut tx, &tip, 0)
                    .unwrap();
            let payments_1 =
                StacksChainState::get_scheduled_block_rewards_in_fork_at_height(&mut tx, &tip, 1)
                    .unwrap();
            let payments_2 =
                StacksChainState::get_scheduled_block_rewards_in_fork_at_height(&mut tx, &tip, 2)
                    .unwrap();

            assert_eq!(payments_0, vec![]);
            assert_eq!(payments_1, vec![miner_reward]);
            assert_eq!(payments_2, vec![tip_reward]);
        };
    }

    #[test]
    fn miner_reward_one_miner_no_tx_fees_no_users() {
        let miner_1 =
            StacksAddress::from_string(&"SP1A2K3ENNA6QQ7G8DVJXM24T6QMBDVS7D0TRTAR5".to_string())
                .unwrap();
        let participant = make_dummy_miner_payment_schedule(&miner_1, 500, 0, 0, 1000, 1000);

        let (parent_reward, miner_reward) = StacksChainState::calculate_miner_reward(
            false,
            StacksEpochId::Epoch2_05,
            &participant,
            &participant,
            &[],
            &MinerPaymentSchedule::genesis(true),
            None,
        );

        // miner should have received the entire coinbase
        assert_eq!(miner_reward.coinbase, 500);
        assert_eq!(miner_reward.tx_fees_anchored, 0);
        assert_eq!(miner_reward.tx_fees_streamed_produced, 0);
        assert_eq!(miner_reward.tx_fees_streamed_confirmed, 0);

        // parent gets nothing -- no tx fees
        assert_eq!(parent_reward.coinbase, 0);
        assert_eq!(parent_reward.tx_fees_anchored, 0);
        assert_eq!(parent_reward.tx_fees_streamed_produced, 0);
        assert_eq!(parent_reward.tx_fees_streamed_confirmed, 0);
    }

    #[test]
    fn miner_reward_one_miner_no_tx_fees_no_users_pay_contract() {
        let miner_1 =
            StacksAddress::from_string(&"SP1A2K3ENNA6QQ7G8DVJXM24T6QMBDVS7D0TRTAR5".to_string())
                .unwrap();
        let mut participant = make_dummy_miner_payment_schedule(&miner_1, 500, 0, 0, 1000, 1000);
        participant.recipient = PrincipalData::Contract(QualifiedContractIdentifier::transient());

        let (parent_reward, miner_reward) = StacksChainState::calculate_miner_reward(
            false,
            StacksEpochId::Epoch2_05,
            &participant,
            &participant,
            &[],
            &MinerPaymentSchedule::genesis(true),
            None,
        );

        // miner should have received the entire coinbase
        assert_eq!(miner_reward.coinbase, 500);
        assert_eq!(miner_reward.tx_fees_anchored, 0);
        assert_eq!(miner_reward.tx_fees_streamed_produced, 0);
        assert_eq!(miner_reward.tx_fees_streamed_confirmed, 0);
        assert_eq!(
            miner_reward.recipient,
            PrincipalData::Contract(QualifiedContractIdentifier::transient())
        );

        // parent gets nothing -- no tx fees
        assert_eq!(parent_reward.coinbase, 0);
        assert_eq!(parent_reward.tx_fees_anchored, 0);
        assert_eq!(parent_reward.tx_fees_streamed_produced, 0);
        assert_eq!(parent_reward.tx_fees_streamed_confirmed, 0);
        assert_eq!(
            parent_reward.recipient,
            parent_reward.address.to_account_principal()
        );
    }

    #[test]
    fn miner_reward_one_miner_one_user_no_tx_fees() {
        let miner_1 =
            StacksAddress::from_string(&"SP1A2K3ENNA6QQ7G8DVJXM24T6QMBDVS7D0TRTAR5".to_string())
                .unwrap();
        let user_1 =
            StacksAddress::from_string(&"SP2837ZMC89J40K4YTS64B00M7065C6X46JX6ARG0".to_string())
                .unwrap();

        let miner = make_dummy_miner_payment_schedule(&miner_1, 500, 0, 0, 250, 1000);
        let user = make_dummy_user_payment_schedule(&user_1, 500, 0, 0, 750, 1000, 1);

        let (parent_miner_1, reward_miner_1) = StacksChainState::calculate_miner_reward(
            false,
            StacksEpochId::Epoch2_05,
            &miner,
            &miner,
            &[user.clone()],
            &MinerPaymentSchedule::genesis(true),
            None,
        );
        let (parent_user_1, reward_user_1) = StacksChainState::calculate_miner_reward(
            false,
            StacksEpochId::Epoch2_05,
            &user,
            &miner,
            &[user.clone()],
            &MinerPaymentSchedule::genesis(true),
            None,
        );

        // miner should have received 1/4 the coinbase
        assert_eq!(reward_miner_1.coinbase, 125);
        assert_eq!(reward_miner_1.tx_fees_anchored, 0);
        assert_eq!(reward_miner_1.tx_fees_streamed_produced, 0);
        assert_eq!(reward_miner_1.tx_fees_streamed_confirmed, 0);

        assert_eq!(parent_miner_1.total(), 0);

        // user should have received 3/4 the coinbase
        assert_eq!(reward_user_1.coinbase, 375);
        assert_eq!(reward_user_1.tx_fees_anchored, 0);
        assert_eq!(reward_user_1.tx_fees_streamed_produced, 0);
        assert_eq!(reward_user_1.tx_fees_streamed_confirmed, 0);

        assert_eq!(parent_user_1.total(), 0);
    }

    #[test]
    fn miner_reward_tx_fees() {
        let miner_1 =
            StacksAddress::from_string(&"SP1A2K3ENNA6QQ7G8DVJXM24T6QMBDVS7D0TRTAR5".to_string())
                .unwrap();

        let parent_miner_1 =
            StacksAddress::from_string(&"SP2QDF700V0FWXVNQJJ4XFGBWE6R2Y4APTSFQNBVE".to_string())
                .unwrap();

        let participant = make_dummy_miner_payment_schedule(&miner_1, 500, 100, 105, 1000, 1000);
        let parent_participant =
            make_dummy_miner_payment_schedule(&parent_miner_1, 500, 100, 395, 1000, 1000);

        let (parent_reward, miner_reward) = StacksChainState::calculate_miner_reward(
            false,
            StacksEpochId::Epoch2_05,
            &participant,
            &participant,
            &[],
            &parent_participant,
            None,
        );

        // miner should have received the entire coinbase
        assert_eq!(miner_reward.coinbase, 500);
        assert_eq!(miner_reward.tx_fees_anchored, 100);
        assert_eq!(miner_reward.tx_fees_streamed_produced, 0); // not rewarded yet
        assert_eq!(miner_reward.tx_fees_streamed_confirmed, (105 * 3) / 5);

        // parent gets produced stream fees
        assert_eq!(parent_reward.coinbase, 0);
        assert_eq!(parent_reward.tx_fees_anchored, 0);
        assert_eq!(parent_reward.tx_fees_streamed_produced, (395 * 2) / 5);
        assert_eq!(parent_reward.tx_fees_streamed_confirmed, 0);
    }
}
