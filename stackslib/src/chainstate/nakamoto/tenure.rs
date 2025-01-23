// Copyright (C) 2013-2020 Blockstack PBC, a public benefit corporation
// Copyright (C) 2020-2023 Stacks Open Internet Foundation
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

//! This module is concerned with tracking all Nakamoto tenures.
//!
//! A _tenure_ is the sequence of blocks that a miner produces from a winning sortition.  A tenure
//! can last for the duration of one or more burnchain blocks, and may be extended by Stackers.  As
//! such, every tenure corresponds to exactly one cryptographic sortition with a winning miner.
//! The consensus hash of the winning miner's sortition serves as the _tenure ID_, and it is
//! guaranteed to be globally unique across all Stacks chain histories and burnchain histories.
//!
//! The tenures within one burnchain fork are well-ordered.  Each tenure has exactly one parent
//! tenure, such that the last block in the parent tenure is the parent of the first block in the
//! child tenure.  The first-ever Nakamoto tenure's parent block is the last epoch2 Stacks block.
//! Due to well-ordering, each burnchain fork has a highest tenure, which is used to validate
//! blocks before processing them.  Namely, a Nakamoto block must belong to the highest tenure in
//! order to be appended to the chain tip.
//!
//! Treating tenures as sequences of blocks mined by a winning miner allows us to cause coinbases
//! to mature based on tenure confirmations.  This is consistent with the epoch2 behavior.  It also
//! allows us to quickly identify whether or not a block belongs to a given tenure, and it allows a
//! booting miner to identify the set of all tenure IDs in a reward cycle using only burnchain
//! state (although some of these tenures may be empty).
//!
//! Tenures are created and extended via `TenureChange` transactions.  These come in two flavors:
//!
//! * A `BlockFound` tenure change, which is induced by a winning sortition.  This causes the new
//! miner to start producing blocks, and stops the current miner from producing more blocks.
//!
//! * An `Extended` tenure change, which is induced by Stackers. This resets the tenure's ongoing
//! execution budget, thereby allowing the miner to continue producing blocks.
//!
//! A tenure may be extended at any time by Stackers, and may span multiple Bitcoin blocks (such
//! as if there was no sortition winner, or the winning miner never comes online).
//!
//! `TenureChanges` contain three pointers to chainstate:
//! * The _tenure consensus hash_: this is the consensus hash of the sortition that chose the last
//! winning miner.  Note that due to the above, it may not be the highest sortition processed.
//! * The _previous tenure consensus hash_: this is the consensus hash of the sortition that chose
//! the miner who produced the parent tenure of the current ongoing tenure.
//! * The _sortition consensus hash: this is the tip of the sortition history that Stackers knew
//! about when they created the `TenureChange.
//!
//! The Nakamoto system uses this module to track the set of all tenures.  It does so within a
//! (derived-state) table called `nakamoto_tenure_events`.  Whenever a `TenureChange` transaction is
//! processed, a new row will be added to this table.
//!
use std::collections::HashSet;
use std::ops::DerefMut;

use clarity::vm::ast::ASTRules;
use clarity::vm::costs::ExecutionCost;
use clarity::vm::database::BurnStateDB;
use clarity::vm::events::StacksTransactionEvent;
use clarity::vm::types::StacksAddressExtensions;
use lazy_static::{__Deref, lazy_static};
use rusqlite::types::{FromSql, FromSqlError, ToSql};
use rusqlite::{params, Connection, OptionalExtension};
use sha2::{Digest as Sha2Digest, Sha512_256};
use stacks_common::codec::{
    read_next, write_next, Error as CodecError, StacksMessageCodec, MAX_MESSAGE_LEN,
};
use stacks_common::consts::{
    FIRST_BURNCHAIN_CONSENSUS_HASH, FIRST_STACKS_BLOCK_HASH, MINER_REWARD_MATURITY,
};
use stacks_common::types::chainstate::{
    BlockHeaderHash, BurnchainHeaderHash, ConsensusHash, StacksBlockId, StacksPrivateKey,
    StacksPublicKey, TrieHash, VRFSeed,
};
use stacks_common::types::sqlite::NO_PARAMS;
use stacks_common::types::{PrivateKey, StacksEpochId};
use stacks_common::util::get_epoch_time_secs;
use stacks_common::util::hash::{to_hex, Hash160, MerkleHashFunc, MerkleTree, Sha512Trunc256Sum};
use stacks_common::util::retry::BoundReader;
use stacks_common::util::secp256k1::MessageSignature;
use stacks_common::util::vrf::{VRFProof, VRFPublicKey, VRF};

use crate::burnchains::{PoxConstants, Txid};
use crate::chainstate::burn::db::sortdb::{
    SortitionDB, SortitionHandle, SortitionHandleConn, SortitionHandleTx,
};
use crate::chainstate::burn::{BlockSnapshot, SortitionHash};
use crate::chainstate::coordinator::{BlockEventDispatcher, Error};
use crate::chainstate::nakamoto::{
    MaturedMinerPaymentSchedules, MaturedMinerRewards, NakamotoBlock, NakamotoBlockHeader,
    NakamotoChainState, StacksDBIndexed,
};
use crate::chainstate::stacks::db::accounts::MinerReward;
use crate::chainstate::stacks::db::{
    ChainstateTx, ClarityTx, DBConfig as ChainstateConfig, MinerPaymentSchedule,
    MinerPaymentTxFees, MinerRewardInfo, StacksBlockHeaderTypes, StacksChainState, StacksDBTx,
    StacksEpochReceipt, StacksHeaderInfo,
};
use crate::chainstate::stacks::events::StacksTransactionReceipt;
use crate::chainstate::stacks::{
    Error as ChainstateError, StacksBlock, StacksBlockHeader, StacksMicroblock, StacksTransaction,
    TenureChangeCause, TenureChangeError, TenureChangePayload, TransactionPayload,
    MINER_BLOCK_CONSENSUS_HASH, MINER_BLOCK_HEADER_HASH,
};
use crate::clarity_vm::clarity::{ClarityInstance, PreCommitClarityBlock};
use crate::clarity_vm::database::SortitionDBRef;
use crate::core::BOOT_BLOCK_HASH;
use crate::monitoring;
use crate::net::Error as net_error;
use crate::util_lib::db::{
    query_int, query_row, query_row_panic, query_rows, u64_to_sql, DBConn, Error as DBError,
    FromRow,
};

pub static NAKAMOTO_TENURES_SCHEMA_1: &str = r#"
    CREATE TABLE nakamoto_tenures (
        -- consensus hash of start-tenure block (i.e. the consensus hash of the sortition in which the miner's block-commit
        -- was mined)
        tenure_id_consensus_hash TEXT NOT NULL,
        -- consensus hash of the previous tenure's start-tenure block
        prev_tenure_id_consensus_hash TEXT NOT NULL,
        -- consensus hash of the last-processed sortition
        burn_view_consensus_hash TEXT NOT NULL,
        -- whether or not this tenure was triggered by a sortition (as opposed to a tenure-extension).
        -- this is equal to the `cause` field in a TenureChange
        cause INTEGER NOT NULL,
        -- block hash of start-tenure block
        block_hash TEXT NOT NULL,
        -- block ID of this start block (this is the StacksBlockId of the above tenure_id_consensus_hash and block_hash)
        block_id TEXT NOT NULL,
        -- this field is the total number of _sortition-induced_ tenures in the chain history (including this tenure),
        -- as of the _end_ of this block.  A tenure can contain multiple TenureChanges; if so, then this
        -- is the height of the _sortition-induced_ TenureChange that created it.
        coinbase_height INTEGER NOT NULL,
        -- number of blocks this tenure.
        -- * for tenure-changes induced by sortitions, this is the number of blocks in the previous tenure
        -- * for tenure-changes induced by extension, this is the number of blocks in the current tenure so far.
        num_blocks_confirmed INTEGER NOT NULL,
        -- this is the ith tenure transaction in its respective Nakamoto chain history.
        tenure_index INTEGER NOT NULL,

        PRIMARY KEY(burn_view_consensus_hash,tenure_index)
    );
    CREATE INDEX nakamoto_tenures_by_block_id ON nakamoto_tenures(block_id);
    CREATE INDEX nakamoto_tenures_by_tenure_id ON nakamoto_tenures(tenure_id_consensus_hash);
    CREATE INDEX nakamoto_tenures_by_block_and_consensus_hashes ON nakamoto_tenures(tenure_id_consensus_hash,block_hash);
    CREATE INDEX nakamoto_tenures_by_burn_view_consensus_hash ON nakamoto_tenures(burn_view_consensus_hash);
    CREATE INDEX nakamoto_tenures_by_tenure_index ON nakamoto_tenures(tenure_index);
    CREATE INDEX nakamoto_tenures_by_parent ON nakamoto_tenures(tenure_id_consensus_hash,prev_tenure_id_consensus_hash);
"#;

pub static NAKAMOTO_TENURES_SCHEMA_2: &str = r#"
    -- Drop the nakamoto_tenures table if it exists
    DROP TABLE IF EXISTS nakamoto_tenures;

    CREATE TABLE nakamoto_tenures (
        -- consensus hash of start-tenure block (i.e. the consensus hash of the sortition in which the miner's block-commit
        -- was mined)
        tenure_id_consensus_hash TEXT NOT NULL,
        -- consensus hash of the previous tenure's start-tenure block
        prev_tenure_id_consensus_hash TEXT NOT NULL,
        -- consensus hash of the last-processed sortition
        burn_view_consensus_hash TEXT NOT NULL,
        -- whether or not this tenure was triggered by a sortition (as opposed to a tenure-extension).
        -- this is equal to the `cause` field in a TenureChange
        cause INTEGER NOT NULL,
        -- block hash of start-tenure block
        block_hash TEXT NOT NULL,
        -- block ID of this start block (this is the StacksBlockId of the above tenure_id_consensus_hash and block_hash)
        block_id TEXT NOT NULL,
        -- this field is the total number of _sortition-induced_ tenures in the chain history (including this tenure),
        -- as of the _end_ of this block.  A tenure can contain multiple TenureChanges; if so, then this
        -- is the height of the _sortition-induced_ TenureChange that created it.
        coinbase_height INTEGER NOT NULL,
        -- number of blocks this tenure.
        -- * for tenure-changes induced by sortitions, this is the number of blocks in the previous tenure
        -- * for tenure-changes induced by extension, this is the number of blocks in the current tenure so far.
        num_blocks_confirmed INTEGER NOT NULL,
        -- this is the ith tenure transaction in its respective Nakamoto chain history.
        tenure_index INTEGER NOT NULL,
    
        PRIMARY KEY(burn_view_consensus_hash,tenure_index)
    );
    CREATE INDEX nakamoto_tenures_by_block_id ON nakamoto_tenures(block_id);
    CREATE INDEX nakamoto_tenures_by_tenure_id ON nakamoto_tenures(tenure_id_consensus_hash);
    CREATE INDEX nakamoto_tenures_by_block_and_consensus_hashes ON nakamoto_tenures(tenure_id_consensus_hash,block_hash);
    CREATE INDEX nakamoto_tenures_by_burn_view_consensus_hash ON nakamoto_tenures(burn_view_consensus_hash);
    CREATE INDEX nakamoto_tenures_by_tenure_index ON nakamoto_tenures(tenure_index);
    CREATE INDEX nakamoto_tenures_by_parent ON nakamoto_tenures(tenure_id_consensus_hash,prev_tenure_id_consensus_hash);
"#;

pub static NAKAMOTO_TENURES_SCHEMA_3: &str = r#"
    -- Drop the nakamoto_tenures table if it exists
    DROP TABLE IF EXISTS nakamoto_tenures;

    -- This table records each tenure-change, be it a BlockFound or Extended tenure.
    -- These are not tenures themselves; these are instead inserted each time a TenureChange transaction occurs.
    -- Each row is a state-change in the ongoing tenure.
    CREATE TABLE nakamoto_tenure_events (
        -- consensus hash of start-tenure block (i.e. the consensus hash of the sortition in which the miner's block-commit
        -- was mined)
        tenure_id_consensus_hash TEXT NOT NULL,
        -- consensus hash of the previous tenure's start-tenure block
        prev_tenure_id_consensus_hash TEXT NOT NULL,
        -- consensus hash of the last-processed sortition
        burn_view_consensus_hash TEXT NOT NULL,
        -- whether or not this tenure was triggered by a sortition (as opposed to a tenure-extension).
        -- this is equal to the `cause` field in a TenureChange
        cause INTEGER NOT NULL,
        -- block hash of start-tenure block
        block_hash TEXT NOT NULL,
        -- block ID of this start block (this is the StacksBlockId of the above tenure_id_consensus_hash and block_hash)
        block_id TEXT NOT NULL,
        -- this field is the total number of _sortition-induced_ tenures in the chain history (including this tenure),
        -- as of the _end_ of this block.  A tenure can contain multiple TenureChanges; if so, then this
        -- is the height of the _sortition-induced_ TenureChange that created it.
        coinbase_height INTEGER NOT NULL,
        -- number of blocks this tenure.
        -- * for tenure-changes induced by sortitions, this is the number of blocks in the previous tenure
        -- * for tenure-changes induced by extension, this is the number of blocks in the current tenure so far.
        num_blocks_confirmed INTEGER NOT NULL,
   
        -- key each tenure by its tenure-start block, and the burn view (since the tenure can span multiple sortitions, and thus
        -- there can be multiple burn_view_consensus_hash values per block_id)
        PRIMARY KEY(burn_view_consensus_hash,block_id)
    ) STRICT;
    CREATE INDEX nakamoto_tenure_events_by_block_id ON nakamoto_tenure_events(block_id);
    CREATE INDEX nakamoto_tenure_events_by_tenure_id ON nakamoto_tenure_events(tenure_id_consensus_hash);
    CREATE INDEX nakamoto_tenure_events_by_block_and_consensus_hashes ON nakamoto_tenure_events(tenure_id_consensus_hash,block_hash);
    CREATE INDEX nakamoto_tenure_events_by_burn_view_consensus_hash ON nakamoto_tenure_events(burn_view_consensus_hash);
    CREATE INDEX nakamoto_tenure_events_by_parent ON nakamoto_tenure_events(tenure_id_consensus_hash,prev_tenure_id_consensus_hash);
"#;

/// Primary key into nakamoto_tenure_events.
/// Used for MARF lookups
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct NakamotoTenureEventId {
    /// last sortition in this tenure
    pub burn_view_consensus_hash: ConsensusHash,
    /// start block ID of this tenure
    pub block_id: StacksBlockId,
}

/// Nakamto tenure event.  Something happened to the tenure stream, and this struct encodes it (be
/// it a new tenure was started, or the current tenure was extended).
#[derive(Debug, Clone, PartialEq)]
pub struct NakamotoTenureEvent {
    /// consensus hash of start-tenure block
    pub tenure_id_consensus_hash: ConsensusHash,
    /// consensus hash of parent tenure's start-tenure block
    pub prev_tenure_id_consensus_hash: ConsensusHash,
    /// sortition tip consensus hash when this tenure was processed
    pub burn_view_consensus_hash: ConsensusHash,
    /// the cause of this tenure -- either a new miner was chosen, or the current miner's tenure
    /// was extended
    pub cause: TenureChangeCause,
    /// block hash of start-tenure block
    pub block_hash: BlockHeaderHash,
    /// block ID of this start block
    pub block_id: StacksBlockId,
    /// coinbase height of this tenure
    pub coinbase_height: u64,
    /// number of blocks this tenure confirms
    pub num_blocks_confirmed: u32,
}

impl FromRow<NakamotoTenureEvent> for NakamotoTenureEvent {
    fn from_row(row: &rusqlite::Row) -> Result<NakamotoTenureEvent, DBError> {
        let tenure_id_consensus_hash = row.get("tenure_id_consensus_hash")?;
        let prev_tenure_id_consensus_hash = row.get("prev_tenure_id_consensus_hash")?;
        let burn_view_consensus_hash = row.get("burn_view_consensus_hash")?;
        let cause_u8: u8 = row.get("cause")?;
        let cause = TenureChangeCause::try_from(cause_u8).map_err(|_| DBError::ParseError)?;
        let block_hash = row.get("block_hash")?;
        let block_id = row.get("block_id")?;
        let coinbase_height_i64: i64 = row.get("coinbase_height")?;
        let coinbase_height =
            u64::try_from(coinbase_height_i64).map_err(|_| DBError::ParseError)?;
        let num_blocks_confirmed: u32 = row.get("num_blocks_confirmed")?;
        Ok(NakamotoTenureEvent {
            tenure_id_consensus_hash,
            prev_tenure_id_consensus_hash,
            burn_view_consensus_hash,
            cause,
            block_hash,
            block_id,
            coinbase_height,
            num_blocks_confirmed,
        })
    }
}

impl NakamotoChainState {
    /// Create the block reward for a NakamotoBlock
    /// `coinbase_reward_ustx` is the total coinbase reward for this block, including any
    ///    accumulated rewards from missed sortitions or initial mining rewards.
    /// TODO: unit test
    pub fn make_scheduled_miner_reward(
        mainnet: bool,
        epoch_id: StacksEpochId,
        parent_block_hash: &BlockHeaderHash,
        parent_consensus_hash: &ConsensusHash,
        block_hash: &BlockHeaderHash,
        block_consensus_hash: &ConsensusHash,
        block_height: u64,
        coinbase_tx: &StacksTransaction,
        parent_fees: u128,
        burnchain_commit_burn: u64,
        burnchain_sortition_burn: u64,
        coinbase_reward_ustx: u128,
    ) -> MinerPaymentSchedule {
        let miner_auth = coinbase_tx.get_origin();
        let miner_addr = miner_auth.get_address(mainnet);

        let recipient = if epoch_id >= StacksEpochId::Epoch21 {
            // pay to tx-designated recipient, or if there is none, pay to the origin
            match coinbase_tx.try_as_coinbase() {
                Some((_, recipient_opt, _)) => recipient_opt
                    .cloned()
                    .unwrap_or(miner_addr.to_account_principal()),
                None => miner_addr.to_account_principal(),
            }
        } else {
            // pre-2.1, always pay to the origin
            miner_addr.to_account_principal()
        };

        // N.B. a `MinerPaymentSchedule` that pays to a contract can never be created before 2.1,
        // per the above check (and moreover, a Stacks block with a pay-to-alt-recipient coinbase would
        // not become valid until after 2.1 activates).
        let miner_reward = MinerPaymentSchedule {
            address: miner_addr,
            recipient,
            block_hash: block_hash.clone(),
            consensus_hash: block_consensus_hash.clone(),
            parent_block_hash: parent_block_hash.clone(),
            parent_consensus_hash: parent_consensus_hash.clone(),
            coinbase: coinbase_reward_ustx,
            tx_fees: MinerPaymentTxFees::Nakamoto { parent_fees },
            burnchain_commit_burn,
            burnchain_sortition_burn,
            miner: true,
            stacks_block_height: block_height,
            vtxindex: 0,
        };

        miner_reward
    }

    /// Get scheduled miner rewards that have matured when this tenure starts.
    /// Returns (list of miners to pay, any residual payments to the parent miner) on success.
    pub(crate) fn get_matured_miner_reward_schedules(
        chainstate_tx: &mut ChainstateTx,
        tip_index_hash: &StacksBlockId,
        coinbase_height: u64,
    ) -> Result<Option<MaturedMinerPaymentSchedules>, ChainstateError> {
        let mainnet = chainstate_tx.get_config().mainnet;

        // find matured miner rewards, so we can grant them within the Clarity DB tx.
        if coinbase_height < MINER_REWARD_MATURITY {
            return Ok(Some(MaturedMinerPaymentSchedules::genesis(mainnet)));
        }

        let matured_coinbase_height = coinbase_height - MINER_REWARD_MATURITY;
        let matured_tenure_block_header = Self::get_header_by_coinbase_height(
            chainstate_tx.deref_mut(),
            &tip_index_hash,
            matured_coinbase_height,
        )?
        .ok_or_else(|| {
            warn!("Matured tenure data not found");
            ChainstateError::NoSuchBlockError
        })?;

        let latest_miners = StacksChainState::get_scheduled_block_rewards_at_block(
            chainstate_tx.deref_mut(),
            &matured_tenure_block_header.index_block_hash(),
        )?;
        let parent_miner = StacksChainState::get_parent_matured_miner(
            chainstate_tx.deref_mut(),
            mainnet,
            &latest_miners,
        )?;
        Ok(Some(MaturedMinerPaymentSchedules {
            latest_miners,
            parent_miner,
        }))
    }

    /// Calculate the total matured rewards from the scheduled matured rewards.
    /// This takes a ClarityTx, so PoisonMicroblocks can be taken into account (which deduct
    /// STX from the block reward for offending miners).
    /// The recipient of the block reward may not be the miner, but may be a PoisonMicroblock
    /// reporter (both are captured as the sole `recipient` in the `MaturedMinerRewards` struct).
    ///
    /// Returns Ok(Some(rewards)) if we were able to calculate the rewards
    /// Returns Ok(None) if there are no matured rewards yet
    /// Returns Err(..) on DB error
    /// TODO: unit test
    pub(crate) fn calculate_matured_miner_rewards(
        clarity_tx: &mut ClarityTx,
        sortdb_conn: &Connection,
        parent_stacks_height: u64,
        matured_miner_schedule: MaturedMinerPaymentSchedules,
    ) -> Result<Option<MaturedMinerRewards>, ChainstateError> {
        let matured_miner_rewards_opt = match StacksChainState::find_mature_miner_rewards(
            clarity_tx,
            sortdb_conn,
            parent_stacks_height,
            matured_miner_schedule.latest_miners,
            matured_miner_schedule.parent_miner,
        ) {
            Ok(Some((recipient, _user_burns, parent, reward_info))) => Some(MaturedMinerRewards {
                recipient,
                parent_reward: parent,
                reward_info,
            }),
            Ok(None) => None,
            Err(e) => {
                let msg = format!("Failed to load miner rewards: {:?}", &e);
                warn!("{}", &msg);
                return Err(ChainstateError::InvalidStacksBlock(msg));
            }
        };
        Ok(matured_miner_rewards_opt)
    }

    /// Determine if a tenure has been fully processed.
    /// That is, we've processed both its tenure-start block, and we've processed a tenure-change that
    /// claims this tenure as its parent tenure.
    ///
    /// If we haven't processed a tenure-start block for this tenure, then return false.
    pub fn has_processed_nakamoto_tenure<SDBI: StacksDBIndexed>(
        conn: &mut SDBI,
        tip_block_id: &StacksBlockId,
        tenure_id_consensus_hash: &ConsensusHash,
    ) -> Result<bool, ChainstateError> {
        Ok(conn
            .is_tenure_finished(tip_block_id, tenure_id_consensus_hash)?
            .unwrap_or(false))
    }

    /// Insert a nakamoto tenure.
    /// `block_header` is the header of the block containing `tenure`.
    /// No validation will be done.
    pub(crate) fn insert_nakamoto_tenure(
        tx: &Connection,
        block_header: &NakamotoBlockHeader,
        coinbase_height: u64,
        tenure: &TenureChangePayload,
    ) -> Result<(), ChainstateError> {
        // NOTE: this is checked with check_nakamoto_tenure()
        assert_eq!(block_header.consensus_hash, tenure.tenure_consensus_hash);
        let args = params![
            tenure.tenure_consensus_hash,
            tenure.prev_tenure_consensus_hash,
            tenure.burn_view_consensus_hash,
            tenure.cause.as_u8(),
            block_header.block_hash(),
            block_header.block_id(),
            u64_to_sql(coinbase_height)?,
            tenure.previous_tenure_blocks,
        ];
        tx.execute(
            "INSERT INTO nakamoto_tenure_events
                (tenure_id_consensus_hash, prev_tenure_id_consensus_hash, burn_view_consensus_hash, cause,
                block_hash, block_id, coinbase_height, num_blocks_confirmed)
            VALUES
                (?1,?2,?3,?4,?5,?6,?7,?8)",
            args,
        )?;

        Ok(())
    }

    /// Drop a nakamoto tenure.
    /// Used for testing
    #[cfg(test)]
    pub(crate) fn delete_nakamoto_tenure(
        tx: &Connection,
        ch: &ConsensusHash,
    ) -> Result<(), ChainstateError> {
        tx.execute(
            "DELETE FROM nakamoto_tenure_events WHERE tenure_id_consensus_hash = ?1",
            &[ch],
        )?;
        Ok(())
    }

    /// Get the consensus hash of the parent tenure
    /// Used by the p2p code.
    /// Don't use in consensus code.
    pub fn get_nakamoto_parent_tenure_id_consensus_hash<SDBI: StacksDBIndexed>(
        chainstate_conn: &mut SDBI,
        tip_block_id: &StacksBlockId,
        consensus_hash: &ConsensusHash,
    ) -> Result<Option<ConsensusHash>, ChainstateError> {
        Ok(chainstate_conn.get_parent_tenure_consensus_hash(tip_block_id, consensus_hash)?)
    }

    /// Get the number of blocks in a tenure, given a block ID.
    /// Only works for Nakamoto blocks, not Stacks epoch2 blocks.
    /// Returns 0 if there are no blocks in this tenure
    pub fn get_nakamoto_tenure_length(
        chainstate_conn: &Connection,
        block_id: &StacksBlockId,
    ) -> Result<u32, ChainstateError> {
        // at least one block in this tenure
        let sql = "SELECT height_in_tenure FROM nakamoto_block_headers WHERE index_block_hash = ?1";
        let count = match query_int(chainstate_conn, sql, &[block_id]) {
            Ok(count_i64) => {
                let count: u32 = count_i64
                    .try_into()
                    .expect("FATAL: too many blocks in tenure");
                count
            }
            Err(DBError::NotFoundError) => 0,
            Err(e) => {
                return Err(e.into());
            }
        };
        Ok(count)
    }

    /// Get a Nakamoto tenure change by its ID
    pub fn get_nakamoto_tenure_change(
        headers_conn: &Connection,
        tenure_id: &NakamotoTenureEventId,
    ) -> Result<Option<NakamotoTenureEvent>, ChainstateError> {
        let sql =
            "SELECT * FROM nakamoto_tenure_events WHERE burn_view_consensus_hash = ?1 AND block_id = ?2";
        let args = rusqlite::params![tenure_id.burn_view_consensus_hash, tenure_id.block_id];
        Ok(query_row(headers_conn, sql, args)?)
    }

    /// Get the tenure-change most recently processed in the history tipped by the given block.
    /// This can be a block-found or an extended tenure change.
    /// Returns None if this tip is an epoch2x block ID
    pub fn get_ongoing_tenure<SDBI: StacksDBIndexed>(
        headers_conn: &mut SDBI,
        tip_block_id: &StacksBlockId,
    ) -> Result<Option<NakamotoTenureEvent>, ChainstateError> {
        let Some(tenure_id) = headers_conn.get_ongoing_tenure_id(tip_block_id)? else {
            return Ok(None);
        };
        Self::get_nakamoto_tenure_change(headers_conn.sqlite(), &tenure_id)
    }

    /// Get the block-found tenure-change for a given tenure ID consensus hash
    pub fn get_block_found_tenure<SDBI: StacksDBIndexed>(
        headers_conn: &mut SDBI,
        tip_block_id: &StacksBlockId,
        tenure_id_consensus_hash: &ConsensusHash,
    ) -> Result<Option<NakamotoTenureEvent>, ChainstateError> {
        let Some(tenure_id) =
            headers_conn.get_block_found_tenure_id(tip_block_id, tenure_id_consensus_hash)?
        else {
            return Ok(None);
        };
        Self::get_nakamoto_tenure_change(headers_conn.sqlite(), &tenure_id)
    }

    /// Verify that a tenure change tx is a valid first-ever tenure change.  It must connect to an
    /// epoch2 block, and it must be sortition-induced.
    ///
    /// Returns Some(mocked-epoch2-tenure) on success
    /// Returns None on error
    pub(crate) fn check_first_nakamoto_tenure_change(
        headers_conn: &Connection,
        tenure_payload: &TenureChangePayload,
    ) -> Result<Option<NakamotoTenureEvent>, ChainstateError> {
        // must be a tenure-change
        if !tenure_payload.cause.expects_sortition() {
            warn!("Invalid tenure-change: not a sortition-induced tenure-change";
                  "consensus_hash" => %tenure_payload.tenure_consensus_hash,
                  "previous_tenure_end" => %tenure_payload.previous_tenure_end
            );
            return Ok(None);
        }

        let Some(parent_header) =
            Self::get_block_header(headers_conn, &tenure_payload.previous_tenure_end)?
        else {
            warn!("Invalid tenure-change from epoch2: no parent epoch2 header";
                  "consensus_hash" => %tenure_payload.tenure_consensus_hash,
                  "previous_tenure_end" => %tenure_payload.previous_tenure_end
            );
            return Ok(None);
        };
        if tenure_payload.previous_tenure_blocks != 1 {
            warn!("Invalid tenure-change from epoch2: expected 1 previous tenure block";
                  "consensus_hash" => %tenure_payload.tenure_consensus_hash,
                  "previous_tenure_blocks" => %tenure_payload.previous_tenure_blocks
            );
            return Ok(None);
        }
        if tenure_payload.prev_tenure_consensus_hash != parent_header.consensus_hash {
            warn!("Invalid tenure-change from epoch2: parent tenure consensus hash mismatch";
                  "prev_tenure_consensus_hash" => %tenure_payload.prev_tenure_consensus_hash,
                  "parent_header.consensus_hash" => %parent_header.consensus_hash
            );
            return Ok(None);
        }
        let Some(epoch2_header_info) = parent_header.anchored_header.as_stacks_epoch2() else {
            warn!("Invalid tenure-change: parent header is not epoch2";
                  "consensus_hash" => %tenure_payload.tenure_consensus_hash,
                  "previous_tenure_end" => %tenure_payload.previous_tenure_end
            );
            return Ok(None);
        };

        // synthesize the "last epoch2" tenure info, so we can calculate the first nakamoto tenure
        let last_epoch2_tenure = NakamotoTenureEvent {
            tenure_id_consensus_hash: parent_header.consensus_hash.clone(),
            prev_tenure_id_consensus_hash: ConsensusHash([0x00; 20]), // ignored,
            burn_view_consensus_hash: parent_header.consensus_hash.clone(),
            cause: TenureChangeCause::BlockFound,
            block_hash: epoch2_header_info.block_hash(),
            block_id: StacksBlockId::new(
                &parent_header.consensus_hash,
                &epoch2_header_info.block_hash(),
            ),
            coinbase_height: epoch2_header_info.total_work.work,
            num_blocks_confirmed: 1,
        };
        Ok(Some(last_epoch2_tenure))
    }

    /// Check that a consensus hash is on the canonical burnchain fork
    /// Returns Some(corresponding snapshot) if so
    /// Returns None if it's not on the canonical fork
    pub(crate) fn check_valid_consensus_hash<SH: SortitionHandle>(
        sort_handle: &mut SH,
        ch: &ConsensusHash,
    ) -> Result<Option<BlockSnapshot>, ChainstateError> {
        // the target sortition must exist, and it must be on the canonical fork
        let Some(sn) = SortitionDB::get_block_snapshot_consensus(sort_handle.sqlite(), ch)? else {
            // no sortition
            warn!("Invalid consensus hash: no such snapshot"; "consensus_hash" => %ch);
            return Ok(None);
        };
        let Some(ancestor_sn) = sort_handle.get_block_snapshot_by_height(sn.block_height)? else {
            // not canonical
            warn!("Invalid consensus hash: snapshot is not canonical"; "consensus_hash" => %ch);
            return Ok(None);
        };
        if ancestor_sn.sortition_id != sn.sortition_id {
            // not canonical
            return Ok(None);
        }
        Ok(Some(sn))
    }

    /// Check a Nakamoto tenure transaction's validity with respect to the last-processed tenure
    /// and the sortition DB.  This validates the following fields:
    /// * tenure_consensus_hash
    /// * prev_tenure_consensus_hash
    /// * previous_tenure_end
    /// * previous_tenure_blocks
    /// * cause
    ///
    /// `block_header` is the block header of a tenure-change block, which includes
    /// `tenure_payload` as its first transaction.
    ///
    /// Returns Ok(Some(processed-tenure)) on success
    /// Returns Ok(None) if the tenure change is invalid
    /// Returns Err(..) on DB error
    pub(crate) fn check_nakamoto_tenure<SH: SortitionHandle, SDBI: StacksDBIndexed>(
        headers_conn: &mut SDBI,
        sort_handle: &mut SH,
        block_header: &NakamotoBlockHeader,
        tenure_payload: &TenureChangePayload,
    ) -> Result<Option<NakamotoTenureEvent>, ChainstateError> {
        // block header must match this tenure
        if block_header.consensus_hash != tenure_payload.tenure_consensus_hash {
            warn!("Invalid tenure-change (or block) -- mismatched consensus hash";
                  "tenure_payload.tenure_consensus_hash" => %tenure_payload.tenure_consensus_hash,
                  "block_header.consensus_hash" => %block_header.consensus_hash
            );
            return Ok(None);
        }

        // this tenure_payload must point to the parent block
        if tenure_payload.previous_tenure_end != block_header.parent_block_id {
            warn!("Invalid tenure-change: does not confirm parent block";
                  "previous_tenure_end" => %tenure_payload.previous_tenure_end,
                  "parent_block_id" => %block_header.parent_block_id
            );
            return Ok(None);
        }

        // all consensus hashes must be on the canonical burnchain fork, if they're not the first-ever
        let Some(tenure_sn) =
            Self::check_valid_consensus_hash(sort_handle, &tenure_payload.tenure_consensus_hash)?
        else {
            return Ok(None);
        };
        let Some(sortition_sn) = Self::check_valid_consensus_hash(
            sort_handle,
            &tenure_payload.burn_view_consensus_hash,
        )?
        else {
            return Ok(None);
        };

        // tenure_sn must be no more recent than sortition_sn
        if tenure_sn.block_height > sortition_sn.block_height {
            warn!("Invalid tenure-change: tenure snapshot comes before sortition snapshot"; "tenure_consensus_hash" => %tenure_payload.tenure_consensus_hash, "burn_view_consensus_hash" => %tenure_payload.prev_tenure_consensus_hash);
            return Ok(None);
        }

        if tenure_payload.prev_tenure_consensus_hash != FIRST_BURNCHAIN_CONSENSUS_HASH {
            // the parent sortition must exist, must be canonical, and must be an ancestor of the
            // sortition for the given consensus hash.
            let Some(prev_sn) = Self::check_valid_consensus_hash(
                sort_handle,
                &tenure_payload.prev_tenure_consensus_hash,
            )?
            else {
                return Ok(None);
            };
            match tenure_payload.cause {
                TenureChangeCause::BlockFound => {
                    if prev_sn.block_height >= tenure_sn.block_height {
                        // parent comes after child
                        warn!("Invalid tenure-change: parent snapshot comes at or after current tenure"; "tenure_consensus_hash" => %tenure_payload.tenure_consensus_hash, "prev_tenure_consensus_hash" => %tenure_payload.prev_tenure_consensus_hash);
                        return Ok(None);
                    }
                }
                TenureChangeCause::Extended => {
                    // prev and current tenure consensus hashes must be identical
                    if prev_sn.consensus_hash != tenure_sn.consensus_hash {
                        warn!("Invalid tenure-change extension: parent snapshot is not the same as the current tenure snapshot"; "tenure_consensus_hash" => %tenure_payload.tenure_consensus_hash, "prev_tenure_consensus_hash" => %tenure_payload.prev_tenure_consensus_hash);
                        return Ok(None);
                    }
                }
            }

            if prev_sn.block_height > sortition_sn.block_height {
                // parent comes after tip
                warn!("Invalid tenure-change: parent snapshot comes after current tip"; "burn_view_consensus_hash" => %tenure_payload.burn_view_consensus_hash, "prev_tenure_consensus_hash" => %tenure_payload.prev_tenure_consensus_hash);
                return Ok(None);
            }

            // is the parent a shadow block?
            // Only possible if the parent is also a nakamoto block
            let is_parent_shadow_block = NakamotoChainState::get_nakamoto_block_version(
                headers_conn.sqlite(),
                &block_header.parent_block_id,
            )?
            .map(NakamotoBlockHeader::is_shadow_block_version)
            .unwrap_or(false);

            if !is_parent_shadow_block && !prev_sn.sortition {
                // parent wasn't a shadow block (we expect a sortition), but this wasn't a sortition-induced tenure change
                warn!("Invalid tenure-change: no block found";
                      "prev_tenure_consensus_hash" => %tenure_payload.prev_tenure_consensus_hash
                );
                return Ok(None);
            }
        }

        // if this isn't a shadow block, then the tenure must correspond to sortitions
        if !block_header.is_shadow_block() && !tenure_sn.sortition {
            warn!("Invalid tenure-change: no block found";
                  "tenure_consensus_hash" => %tenure_payload.tenure_consensus_hash
            );
            return Ok(None);
        }

        // What tenure are we building off of?  This is the tenure in which the parent block
        // resides.  Note that if this block is a tenure-extend block, then parent_block_id and
        // this block reside in the same tenure (but this block will insert a tenure-extend record
        // into the tenure-changes table).
        let Some(parent_tenure) =
            Self::get_ongoing_tenure(headers_conn, &block_header.parent_block_id)?
        else {
            // not building off of a previous Nakamoto tenure.  This is the first tenure change.  It should point to an epoch
            // 2.x block.
            return Self::check_first_nakamoto_tenure_change(headers_conn.sqlite(), tenure_payload);
        };

        // validate cause
        match tenure_payload.cause {
            TenureChangeCause::BlockFound => {
                // this tenure_payload's prev_consensus_hash must match the parent block tenure's
                // tenure_consensus_hash -- i.e. this tenure must be distinct from the parent
                // block's tenure
                if parent_tenure.tenure_id_consensus_hash
                    != tenure_payload.prev_tenure_consensus_hash
                {
                    warn!("Invalid tenure-change: tenure block-found does not confirm parent block's tenure";
                          "parent_tenure.tenure_consensus_hash" => %parent_tenure.tenure_id_consensus_hash,
                          "prev_consensus_hash" => %tenure_payload.prev_tenure_consensus_hash
                    );
                    return Ok(None);
                }
            }
            TenureChangeCause::Extended => {
                // tenure extensions don't begin a new tenure (since the miner isn't changing), so
                // the tenure consensus hash must be the same as the previous tenure consensus hash
                if tenure_payload.tenure_consensus_hash != tenure_payload.prev_tenure_consensus_hash
                {
                    warn!("Invalid tenure-change: tenure extension tries to start a new tenure";
                          "tenure_consensus_hash" => %tenure_payload.tenure_consensus_hash,
                          "prev_tenure_consensus_hash" => %tenure_payload.prev_tenure_consensus_hash,
                    );
                    return Ok(None);
                }
            }
        };

        // The tenure-change must report the number of blocks _so far_ in the previous tenure (note if this is a TenureChangeCause::Extended, then its parent tenure will be its own tenure).
        // If there is a succession of tenure-extensions for a given tenure, then the reported tenure
        // length must report the number of blocks since the last _sortition-induced_ tenure
        // change.
        let tenure_len =
            Self::get_nakamoto_tenure_length(headers_conn.sqlite(), &block_header.parent_block_id)?;

        if tenure_len != tenure_payload.previous_tenure_blocks {
            // invalid -- does not report the correct number of blocks in the past tenure
            warn!("Invalid tenure-change: wrong number of blocks";
                  "tenure_consensus_hash" => %tenure_payload.tenure_consensus_hash,
                  "prev_tenure_consensus_hash" => %tenure_payload.prev_tenure_consensus_hash,
                  "tenure_len" => tenure_len,
                  "tenure_payload.previous_tenure_blocks" => tenure_payload.previous_tenure_blocks
            );
            return Ok(None);
        }

        Ok(Some(parent_tenure))
    }

    /// Advance the tenures table with a validated block's tenure data.
    /// This applies to both tenure-changes and tenure-extends.
    /// Returns the tenure-change height (this is parent_coinbase_height + 1 if there was a
    /// tenure-change tx, or just parent_coinbase_height if there was a tenure-extend tx or no tenure
    /// txs at all).
    /// TODO: unit test
    pub(crate) fn advance_nakamoto_tenure<SH: SortitionHandle>(
        headers_tx: &mut StacksDBTx,
        handle: &mut SH,
        block: &NakamotoBlock,
        parent_coinbase_height: u64,
        do_not_advance: bool,
    ) -> Result<u64, ChainstateError> {
        let Some(tenure_payload) = block.get_tenure_tx_payload() else {
            // no new tenure
            return Ok(parent_coinbase_height);
        };

        let coinbase_height = match tenure_payload.cause {
            TenureChangeCause::BlockFound => {
                // tenure height advances
                parent_coinbase_height
                    .checked_add(1)
                    .expect("FATAL: too many tenures")
            }
            TenureChangeCause::Extended => {
                // tenure height does not advance
                parent_coinbase_height
            }
        };

        if Self::check_nakamoto_tenure(headers_tx, handle, &block.header, tenure_payload)?.is_none()
        {
            return Err(ChainstateError::InvalidStacksTransaction(
                "Invalid tenure tx".into(),
                false,
            ));
        };

        if do_not_advance {
            return Ok(coinbase_height);
        }
        Self::insert_nakamoto_tenure(headers_tx, &block.header, coinbase_height, tenure_payload)?;
        return Ok(coinbase_height);
    }

    /// Check that this block is in the same tenure as its parent, and that this tenure is the
    /// highest-seen tenure.  Use this to check blocks that do _not_ have BlockFound tenure-changes.
    ///
    /// `parent_ch` is the tenure ID consensus hash of the given block's parent.
    ///
    /// Returns Ok(bool) to indicate whether or not this block is in the same tenure as its parent.
    /// Returns Err(..) on DB error
    pub(crate) fn check_tenure_continuity<SDBI: StacksDBIndexed>(
        headers_conn: &mut SDBI,
        parent_ch: &ConsensusHash,
        block_header: &NakamotoBlockHeader,
    ) -> Result<bool, ChainstateError> {
        // block must have the same consensus hash as its parent
        if block_header.is_first_mined() || parent_ch != &block_header.consensus_hash {
            test_debug!("Block is discontinuous with tenure: either first-mined or has a different tenure ID";
                        "parent_ch" => %parent_ch,
                        "block_header.consensus_hash" => %block_header.consensus_hash,
                        "is_first_mined()" => block_header.is_first_mined(),
            );
            return Ok(false);
        }

        // block must be in the same tenure as the highest-processed tenure.
        let Some(highest_tenure) =
            Self::get_ongoing_tenure(headers_conn, &block_header.parent_block_id)?
        else {
            // no tenures yet, so definitely not continuous
            test_debug!("Block is discontinuous with tenure: no ongoing tenure";
                        "block_header.parent_block_id" => %block_header.parent_block_id,
            );
            return Ok(false);
        };

        if &highest_tenure.tenure_id_consensus_hash != parent_ch {
            // this block is not in the highest-known tenure, so it can't be continuous
            test_debug!("Block is discontinuous with tenure: parent is not in current tenure";
                        "parent_ch" => %parent_ch,
                        "highest_tenure.tenure_id_consensus_hash" => %highest_tenure.tenure_id_consensus_hash,
            );
            return Ok(false);
        }

        Ok(true)
    }

    /// Calculate the scheduled block-reward for this tenure.
    /// - chainstate_tx: the transaction open against the chainstate
    /// - burn_dbconn: the sortition fork tx open against the sortition DB
    /// - block: the block being processed
    /// - parent_coinbase_height: the number of tenures represented by the parent of this block
    /// (equivalent to the number of coinbases)
    /// - chain_tip_burn_header_height: the height of the burnchain block mined when this block was
    /// produced
    /// - burnchain_commit_burn: how many burnchain tokens were spent by this block's tenure's block-commit
    /// - burnchain_sortition_burn: total burnchain tokens spent by all miners for this block's
    /// tenure
    ///
    /// Returns the scheduled reward for this block's miner, subject to:
    /// - accumulated STX from missed sortitions
    /// - initial mining bonus, if any
    /// - the coinbase reward at this burnchain block height
    /// - the parent tenure's total fees
    ///
    /// TODO: unit test
    pub(crate) fn calculate_scheduled_tenure_reward(
        chainstate_tx: &mut ChainstateTx,
        burn_dbconn: &SortitionHandleConn,
        block: &NakamotoBlock,
        evaluated_epoch: StacksEpochId,
        parent_coinbase_height: u64,
        chain_tip_burn_header_height: u64,
        burnchain_commit_burn: u64,
        burnchain_sortition_burn: u64,
    ) -> Result<MinerPaymentSchedule, ChainstateError> {
        let mainnet = chainstate_tx.get_config().mainnet;

        // figure out if there any accumulated rewards by
        //   getting the snapshot that elected this block.
        let accumulated_rewards = SortitionDB::get_block_snapshot_consensus(
            burn_dbconn.conn(),
            &block.header.consensus_hash,
        )?
        .expect("CORRUPTION: failed to load snapshot that elected processed block")
        .accumulated_coinbase_ustx;

        let coinbase_at_block = StacksChainState::get_coinbase_reward(
            evaluated_epoch,
            chainstate_tx.config.mainnet,
            chain_tip_burn_header_height,
            burn_dbconn.context.first_block_height,
        );

        let total_coinbase = coinbase_at_block.saturating_add(accumulated_rewards);
        let parent_tenure_start_header: StacksHeaderInfo = Self::get_header_by_coinbase_height(
            chainstate_tx.deref_mut(),
            &block.header.parent_block_id,
            parent_coinbase_height,
        )?
        .ok_or_else(|| {
            warn!("While processing tenure change, failed to look up parent tenure";
                  "parent_coinbase_height" => parent_coinbase_height,
                  "parent_block_id" => %block.header.parent_block_id,
                  "consensus_hash" => %block.header.consensus_hash,
                  "stacks_block_hash" => %block.header.block_hash(),
                  "stacks_block_id" => %block.header.block_id()
            );
            ChainstateError::NoSuchBlockError
        })?;
        // fetch the parent tenure fees by reading the total tx fees from this block's
        // *parent* (not parent_tenure_start_header), because `parent_block_id` is the last
        // block of that tenure, so contains a total fee accumulation for the whole tenure
        let parent_tenure_fees = if parent_tenure_start_header.is_nakamoto_block() {
            Self::get_total_tenure_tx_fees_at(
                chainstate_tx,
                &block.header.parent_block_id
            )?.ok_or_else(|| {
                warn!("While processing tenure change, failed to look up parent block's total tx fees";
                      "parent_block_id" => %block.header.parent_block_id,
                      "consensus_hash" => %block.header.consensus_hash,
                      "stacks_block_hash" => %block.header.block_hash(),
                      "stacks_block_id" => %block.header.block_id()
                    );
                ChainstateError::NoSuchBlockError
            })?
        } else {
            // if the parent tenure is an epoch-2 block, don't pay
            // any fees to them in this schedule: nakamoto blocks
            // cannot confirm microblock transactions, and
            // anchored transactions are scheduled
            // by the parent in epoch-2.
            0
        };

        Ok(Self::make_scheduled_miner_reward(
            mainnet,
            evaluated_epoch,
            &parent_tenure_start_header.anchored_header.block_hash(),
            &parent_tenure_start_header.consensus_hash,
            &block.header.block_hash(),
            &block.header.consensus_hash,
            block.header.chain_length,
            block
                .get_coinbase_tx()
                .ok_or(ChainstateError::InvalidStacksBlock(
                    "No coinbase transaction in tenure changing block".into(),
                ))?,
            parent_tenure_fees,
            burnchain_commit_burn,
            burnchain_sortition_burn,
            total_coinbase,
        ))
    }

    /// Check that a given Nakamoto block's tenure's sortition exists and was processed on this
    /// particular burnchain fork.
    /// Return the block snapshot if so.
    pub(crate) fn check_sortition_exists(
        burn_dbconn: &SortitionHandleConn,
        block_consensus_hash: &ConsensusHash,
    ) -> Result<BlockSnapshot, ChainstateError> {
        // check that the burnchain block that this block is associated with has been processed.
        // N.B. we must first get its hash, and then verify that it's in the same Bitcoin fork as
        // our `burn_dbconn` indicates.
        let burn_header_hash =
            SortitionDB::get_burnchain_header_hash_by_consensus(burn_dbconn, block_consensus_hash)?
                .ok_or_else(|| {
                    warn!(
                        "Unrecognized consensus hash";
                        "consensus_hash" => %block_consensus_hash,
                    );
                    ChainstateError::NoSuchBlockError
                })?;

        let snapshot = burn_dbconn
            .get_block_snapshot(&burn_header_hash)?
            .ok_or_else(|| {
                warn!(
                    "Tried to process Nakamoto block before its burn view was processed";
                    "burn_header_hash" => %burn_header_hash,
                );
                ChainstateError::NoSuchBlockError
            })?;

        if snapshot.consensus_hash != *block_consensus_hash {
            // should be unreachable, but check defensively
            warn!(
                "Snapshot for {} is not the same as the one for {}",
                &burn_header_hash, block_consensus_hash
            );
            return Err(ChainstateError::NoSuchBlockError);
        }

        Ok(snapshot)
    }
}
