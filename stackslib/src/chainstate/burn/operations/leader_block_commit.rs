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

use std::io::{Read, Write};

use stacks_common::address::AddressHashMode;
use stacks_common::codec::{write_next, Error as codec_error, StacksMessageCodec};
use stacks_common::types::chainstate::{
    BlockHeaderHash, BurnchainHeaderHash, StacksAddress, StacksBlockId, TrieHash, VRFSeed,
};
use stacks_common::util::hash::to_hex;
use stacks_common::util::log;
use stacks_common::util::vrf::{VRFPrivateKey, VRFPublicKey, VRF};

use crate::burnchains::bitcoin::BitcoinNetworkType;
use crate::burnchains::{
    Address, Burnchain, BurnchainBlockHeader, BurnchainRecipient, BurnchainSigner,
    BurnchainTransaction, PoxConstants, PublicKey, Txid,
};
use crate::chainstate::burn::db::sortdb::{SortitionDB, SortitionHandle, SortitionHandleTx};
use crate::chainstate::burn::operations::{
    parse_u16_from_be, parse_u32_from_be, BlockstackOperationType, Error as op_error,
    LeaderBlockCommitOp, LeaderKeyRegisterOp,
};
use crate::chainstate::burn::{ConsensusHash, Opcodes, SortitionId};
use crate::chainstate::stacks::address::PoxAddress;
use crate::chainstate::stacks::index::storage::TrieFileStorage;
use crate::chainstate::stacks::{StacksPrivateKey, StacksPublicKey};
use crate::core::{
    StacksEpoch, StacksEpochId, STACKS_EPOCH_2_05_MARKER, STACKS_EPOCH_2_1_MARKER,
    STACKS_EPOCH_2_2_MARKER, STACKS_EPOCH_2_3_MARKER, STACKS_EPOCH_2_4_MARKER,
    STACKS_EPOCH_2_5_MARKER, STACKS_EPOCH_3_0_MARKER, STACKS_EPOCH_3_1_MARKER,
};
use crate::net::Error as net_error;

// return type from parse_data below
#[derive(Debug)]
pub struct ParsedData {
    block_header_hash: BlockHeaderHash,
    new_seed: VRFSeed,
    parent_block_ptr: u32,
    parent_vtxindex: u16,
    key_block_ptr: u32,
    key_vtxindex: u16,
    pub burn_parent_modulus: u8,
    memo: u8,
}

/// This struct captures how a particular
/// PoxAddress was treated by a given block commit.
#[derive(Debug, PartialEq, Clone, Eq, Serialize, Deserialize)]
pub enum Treatment {
    Reward(PoxAddress),
    Punish(PoxAddress),
}

impl Treatment {
    pub fn is_reward(&self) -> bool {
        matches!(self, Treatment::Reward(_))
    }
    pub fn is_punish(&self) -> bool {
        matches!(self, Treatment::Punish(_))
    }
}

impl std::ops::Deref for Treatment {
    type Target = PoxAddress;

    fn deref(&self) -> &Self::Target {
        match self {
            Treatment::Reward(ref a) | Treatment::Punish(ref a) => a,
        }
    }
}

pub static OUTPUTS_PER_COMMIT: usize = 2;
pub static BURN_BLOCK_MINED_AT_MODULUS: u64 = 5;

impl LeaderBlockCommitOp {
    #[cfg(test)]
    pub fn initial(
        block_header_hash: &BlockHeaderHash,
        block_height: u64,
        new_seed: &VRFSeed,
        paired_key: &LeaderKeyRegisterOp,
        burn_fee: u64,
        input: &(Txid, u32),
        apparent_sender: &BurnchainSigner,
    ) -> LeaderBlockCommitOp {
        LeaderBlockCommitOp {
            sunset_burn: 0,
            block_height,
            burn_parent_modulus: if block_height > 0 {
                u8::try_from((block_height - 1) % BURN_BLOCK_MINED_AT_MODULUS)
                    .expect("FATAL: unreachable: unable to form u8 from 3-bit number")
            } else {
                u8::try_from(BURN_BLOCK_MINED_AT_MODULUS)
                    .expect("FATAL: unreachable: 5 is not a u8")
                    - 1
            },
            new_seed: new_seed.clone(),
            key_block_ptr: paired_key.block_height as u32,
            key_vtxindex: paired_key.vtxindex as u16,
            parent_block_ptr: 0,
            parent_vtxindex: 0,
            memo: vec![0x00],
            burn_fee,
            input: input.clone(),
            block_header_hash: block_header_hash.clone(),
            commit_outs: vec![],
            apparent_sender: apparent_sender.clone(),

            // to be filled in
            txid: Txid([0u8; 32]),
            vtxindex: 0,
            burn_header_hash: BurnchainHeaderHash::zero(),
            treatment: vec![],
        }
    }

    #[cfg(test)]
    pub fn new(
        block_header_hash: &BlockHeaderHash,
        block_height: u64,
        new_seed: &VRFSeed,
        parent_block_height: u32,
        parent_vtxindex: u16,
        key_block_ptr: u32,
        key_vtxindex: u16,
        burn_fee: u64,
        input: &(Txid, u32),
        apparent_sender: &BurnchainSigner,
    ) -> LeaderBlockCommitOp {
        LeaderBlockCommitOp {
            sunset_burn: 0,
            new_seed: new_seed.clone(),
            key_block_ptr,
            key_vtxindex,
            parent_block_ptr: parent_block_height,
            parent_vtxindex,
            memo: vec![],
            burn_fee,
            input: input.clone(),
            block_header_hash: block_header_hash.clone(),
            commit_outs: vec![],
            apparent_sender: apparent_sender.clone(),

            // to be filled in
            txid: Txid([0u8; 32]),
            vtxindex: 0,
            block_height: 0,
            burn_parent_modulus: u8::try_from(BURN_BLOCK_MINED_AT_MODULUS)
                .expect("FATAL: unreachable: 5 is not a u8")
                - 1,

            burn_header_hash: BurnchainHeaderHash::zero(),
            treatment: vec![],
        }
    }

    #[cfg(test)]
    pub fn set_burn_height(&mut self, height: u64) {
        self.block_height = height;
        let new_burn_parent_modulus = if height > 0 {
            (height - 1) % BURN_BLOCK_MINED_AT_MODULUS
        } else {
            BURN_BLOCK_MINED_AT_MODULUS - 1
        };
        self.burn_parent_modulus = u8::try_from(new_burn_parent_modulus)
            .expect("FATAL: unreachable: 3-bit number is not a u8");
    }

    pub fn expected_chained_utxo(burn_only: bool) -> u32 {
        if burn_only {
            2 // if sunset has occurred, or we're in the prepare phase, then chained commits should spend the output after the burn commit
        } else {
            // otherwise, it's the output after the last PoX output
            (OUTPUTS_PER_COMMIT as u32) + 1
        }
    }

    pub fn burn_block_mined_at(&self) -> u64 {
        u64::from(self.burn_parent_modulus) % BURN_BLOCK_MINED_AT_MODULUS
    }

    /// In Nakamoto, the block header hash is actually the index block hash of the first Nakamoto
    /// block of the last tenure (the "tenure id"). This helper obtains it.
    pub fn last_tenure_id(&self) -> StacksBlockId {
        StacksBlockId(self.block_header_hash.0.clone())
    }

    pub fn parse_data(data: &[u8]) -> Option<ParsedData> {
        /*
            Wire format:
            0      2  3            35               67     71     73    77   79     80
            |------|--|-------------|---------------|------|------|-----|-----|-----|
             magic  op   block hash     new seed     parent parent key   key    burn_block_parent modulus
                                                     block  txoff  block txoff

             Note that `data` is missing the first 3 bytes -- the magic and op have been stripped

             The values parent-block, parent-txoff, key-block, and key-txoff are in network byte order.

             parent-delta and parent-txoff will both be 0 if this block builds off of the genesis block.
        */

        if data.len() < 77 {
            // too short
            warn!(
                "LEADER_BLOCK_COMMIT payload is malformed ({} bytes)",
                data.len()
            );
            return None;
        }

        let block_header_hash = BlockHeaderHash::from_bytes(&data[0..32]).unwrap();
        let new_seed = VRFSeed::from_bytes(&data[32..64]).unwrap();
        let parent_block_ptr = parse_u32_from_be(&data[64..68]).unwrap();
        let parent_vtxindex = parse_u16_from_be(&data[68..70]).unwrap();
        let key_block_ptr = parse_u32_from_be(&data[70..74]).unwrap();
        let key_vtxindex = parse_u16_from_be(&data[74..76]).unwrap();

        let burn_parent_modulus_and_memo_byte = data[76];

        let burn_parent_modulus = u8::try_from(
            u64::from(burn_parent_modulus_and_memo_byte & 0b111) % BURN_BLOCK_MINED_AT_MODULUS,
        )
        .expect("FATAL: unreachable: could not make u8 from a 3-bit number");
        let memo = (burn_parent_modulus_and_memo_byte >> 3) & 0x1f;

        Some(ParsedData {
            block_header_hash,
            new_seed,
            parent_block_ptr,
            parent_vtxindex,
            key_block_ptr,
            key_vtxindex,
            burn_parent_modulus,
            memo,
        })
    }

    pub fn from_tx(
        burnchain: &Burnchain,
        block_header: &BurnchainBlockHeader,
        epoch_id: StacksEpochId,
        tx: &BurnchainTransaction,
    ) -> Result<LeaderBlockCommitOp, op_error> {
        LeaderBlockCommitOp::parse_from_tx(
            burnchain,
            block_header.block_height,
            &block_header.block_hash,
            epoch_id,
            tx,
        )
    }

    #[cfg_attr(test, mutants::skip)]
    pub fn is_parent_genesis(&self) -> bool {
        self.parent_block_ptr == 0 && self.parent_vtxindex == 0
    }

    /// parse a LeaderBlockCommitOp
    pub fn parse_from_tx(
        burnchain: &Burnchain,
        block_height: u64,
        block_hash: &BurnchainHeaderHash,
        epoch_id: StacksEpochId,
        tx: &BurnchainTransaction,
    ) -> Result<LeaderBlockCommitOp, op_error> {
        // can't be too careful...
        let outputs = tx.get_recipients();

        if tx.num_signers() == 0 {
            warn!(
                "Invalid tx: inputs: {}, outputs: {}",
                tx.num_signers(),
                outputs.len()
            );
            return Err(op_error::InvalidInput);
        }

        if outputs.is_empty() {
            warn!(
                "Invalid tx: inputs: {}, outputs: {}",
                tx.num_signers(),
                outputs.len()
            );
            return Err(op_error::InvalidInput);
        }

        if tx.opcode() != Opcodes::LeaderBlockCommit as u8 {
            warn!("Invalid tx: invalid opcode {}", tx.opcode());
            return Err(op_error::InvalidInput);
        };

        let data = LeaderBlockCommitOp::parse_data(&tx.data()).ok_or_else(|| {
            warn!("Invalid tx data");
            op_error::ParseError
        })?;

        // basic sanity checks
        // if parent block ptr and parent vtxindex are both 0, then this block's parent is
        // the genesis block.
        if data.parent_block_ptr == 0 && data.parent_vtxindex != 0 {
            warn!("Invalid tx: parent block back-pointer must be positive");
            return Err(op_error::ParseError);
        }

        if u64::from(data.parent_block_ptr) >= block_height {
            warn!(
                "Invalid tx: parent block back-pointer {} exceeds block height {}",
                data.parent_block_ptr, block_height
            );
            return Err(op_error::ParseError);
        }

        if data.key_block_ptr == 0 {
            warn!("Invalid tx: key block back-pointer must be positive");
            return Err(op_error::ParseError);
        }

        if u64::from(data.key_block_ptr) >= block_height {
            warn!(
                "Invalid tx: key block back-pointer {} exceeds block height {}",
                data.key_block_ptr, block_height
            );
            return Err(op_error::ParseError);
        }

        // check if we've reached PoX disable
        let (commit_outs, sunset_burn, burn_fee, apparent_sender) = if burnchain
            .pox_constants
            .is_after_pox_sunset_end(block_height, epoch_id)
            || burnchain.is_in_prepare_phase(block_height)
        {
            // PoX is disabled by sunset (not possible in epoch 2.1 or later), OR,
            // we're in the prepare phase.
            // should be only one burn output.
            let output_0 = outputs[0].clone().ok_or_else(|| {
                warn!("Invalid commit tx: unrecognized output 0");
                op_error::InvalidInput
            })?;

            if !output_0.address.is_burn() {
                return Err(op_error::BlockCommitBadOutputs);
            }
            let BurnchainRecipient { address, amount } = output_0;
            let apparent_sender = BurnchainSigner(
                outputs
                    .get(1)
                    .map(|out| {
                        out.as_ref()
                            .map(|out| out.address.clone().to_b58())
                            .unwrap_or("<undecodable-output>".to_string())
                    })
                    .unwrap_or("<no-change-output>".to_string()),
            );

            let sunset_burn = tx.get_burn_amount();
            (vec![address], sunset_burn, amount, apparent_sender)
        } else {
            // we're in a reward phase, which may or may not be PoX.
            // check if this transaction provided a sunset burn (which is still allowed in epoch
            // 2.1; it's just not doing anything for the miner).
            let sunset_burn = tx.get_burn_amount();

            let mut commit_outs = vec![];
            let mut pox_fee = None;
            for (ix, output_opt) in outputs.iter().enumerate() {
                let output = output_opt.clone().ok_or_else(|| {
                    warn!("Invalid commit tx: unrecognized output {}", ix);
                    op_error::InvalidInput
                })?;

                // only look at the first OUTPUTS_PER_COMMIT outputs
                if ix >= OUTPUTS_PER_COMMIT {
                    break;
                }
                // all pox outputs must have the same fee
                if let Some(pox_fee) = pox_fee {
                    if output.amount != pox_fee {
                        warn!("Invalid commit tx: different output amounts for different PoX reward addresses ({} != {})", pox_fee, output.amount);
                        return Err(op_error::ParseError);
                    }
                } else {
                    pox_fee.replace(output.amount);
                }
                commit_outs.push(output.address);
            }

            if commit_outs.len() != OUTPUTS_PER_COMMIT {
                warn!("Invalid commit tx: {} commit addresses, but {} PoX addresses should be committed to", commit_outs.len(), OUTPUTS_PER_COMMIT);
                return Err(op_error::InvalidInput);
            }

            // compute the total amount transfered/burned, and check that the burn amount
            //   is expected given the amount transfered.
            let burn_fee = pox_fee
                .expect("A 0-len output should have already errored")
                .checked_mul(u64::try_from(OUTPUTS_PER_COMMIT).expect(">2^64 outputs per commit")) // total commitment is the pox_amount * outputs
                .ok_or_else(|| op_error::ParseError)?;

            if burn_fee == 0 {
                warn!("Invalid commit tx: burn/transfer amount is 0");
                return Err(op_error::ParseError);
            }

            let apparent_sender = BurnchainSigner(
                outputs
                    .get(2)
                    .map(|out| {
                        out.as_ref()
                            .map(|out| out.address.clone().to_b58())
                            .unwrap_or("<undecodable-output>".to_string())
                    })
                    .unwrap_or("<no-change-output>".to_string()),
            );
            (commit_outs, sunset_burn, burn_fee, apparent_sender)
        };

        let input = tx
            .get_input_tx_ref(0)
            .expect("UNREACHABLE: checked that inputs > 0")
            .clone();

        Ok(LeaderBlockCommitOp {
            block_header_hash: data.block_header_hash,
            new_seed: data.new_seed,
            parent_block_ptr: data.parent_block_ptr,
            parent_vtxindex: data.parent_vtxindex,
            key_block_ptr: data.key_block_ptr,
            key_vtxindex: data.key_vtxindex,
            memo: vec![data.memo],
            burn_parent_modulus: data.burn_parent_modulus,

            commit_outs,
            sunset_burn,
            burn_fee,
            input,
            apparent_sender,

            treatment: Vec::new(),
            txid: tx.txid(),
            vtxindex: tx.vtxindex(),
            block_height,
            burn_header_hash: block_hash.clone(),
        })
    }

    /// are all the outputs for this block commit burns?
    pub fn all_outputs_burn(&self) -> bool {
        self.commit_outs
            .iter()
            .all(|output_addr| output_addr.is_burn())
    }

    pub fn spent_txid(&self) -> &Txid {
        &self.input.0
    }

    pub fn spent_output(&self) -> u32 {
        self.input.1
    }

    pub fn is_first_block(&self) -> bool {
        self.parent_block_ptr == 0 && self.parent_vtxindex == 0
    }
}

impl StacksMessageCodec for LeaderBlockCommitOp {
    /*
        Wire format:

        0      2  3            35               67     71     73    77   79     80
        |------|--|-------------|---------------|------|------|-----|-----|-----|
         magic  op   block hash     new seed     parent parent key   key   burn parent modulus
                                                block  txoff  block txoff
    */
    fn consensus_serialize<W: Write>(&self, fd: &mut W) -> Result<(), codec_error> {
        write_next(fd, &(Opcodes::LeaderBlockCommit as u8))?;
        write_next(fd, &self.block_header_hash)?;
        fd.write_all(&self.new_seed.as_bytes()[..])
            .map_err(codec_error::WriteError)?;
        write_next(fd, &self.parent_block_ptr)?;
        write_next(fd, &self.parent_vtxindex)?;
        write_next(fd, &self.key_block_ptr)?;
        write_next(fd, &self.key_vtxindex)?;
        let memo_burn_parent_modulus =
            (self.memo.get(0).copied().unwrap_or(0x00) << 3) + (self.burn_parent_modulus & 0b111);
        write_next(fd, &memo_burn_parent_modulus)?;
        Ok(())
    }

    fn consensus_deserialize<R: Read>(_fd: &mut R) -> Result<LeaderBlockCommitOp, codec_error> {
        // Op deserialized through burchain indexer
        unimplemented!();
    }
}

#[derive(Debug, Clone)]
pub struct RewardSetInfo {
    pub anchor_block: BlockHeaderHash,
    pub recipients: Vec<(PoxAddress, u16)>,
    pub allow_nakamoto_punishment: bool,
}

#[derive(Debug, Clone)]
pub struct MissedBlockCommit {
    pub txid: Txid,
    pub input: (Txid, u32),
    pub intended_sortition: SortitionId,
}

impl MissedBlockCommit {
    pub fn spent_txid(&self) -> &Txid {
        &self.input.0
    }

    pub fn spent_output(&self) -> u32 {
        self.input.1
    }
}

impl RewardSetInfo {
    /// Create a RewardSetInfo struct for a missed block commit
    fn from_missed_commit(
        tx: &mut SortitionHandleTx,
        intended_sortition: &SortitionId,
    ) -> Result<Option<RewardSetInfo>, op_error> {
        // did this block-commit pay to the correct PoX addresses?
        let intended_recipients = tx
            .get_reward_set_payouts_at(&intended_sortition)
            .map_err(|_e| op_error::BlockCommitBadOutputs)?
            .0;
        let block_height = SortitionDB::get_block_snapshot(tx.tx(), intended_sortition)
            .map_err(|_e| op_error::BlockCommitBadOutputs)?
            .ok_or_else(|| op_error::BlockCommitBadOutputs)?
            .block_height;
        let allow_nakamoto_punishment = SortitionDB::get_stacks_epoch(tx.sqlite(), block_height)
            .map_err(|_e| op_error::BlockCommitBadOutputs)?
            .ok_or_else(|| op_error::BlockCommitBadOutputs)?
            .epoch_id
            .allows_pox_punishment();

        Ok(tx.get_last_anchor_block_hash()?.map(|bhh| RewardSetInfo {
            allow_nakamoto_punishment,
            anchor_block: bhh,
            recipients: intended_recipients
                .into_iter()
                .enumerate()
                .map(|(i, addr)| (addr, i as u16))
                .collect(),
        }))
    }

    /// Takes an Option<RewardSetInfo> and produces the commit_outs
    ///   for a corresponding LeaderBlockCommitOp. If RewardSetInfo is none,
    ///   the LeaderBlockCommitOp will use burn addresses.
    pub fn into_commit_outs(from: Option<RewardSetInfo>, mainnet: bool) -> Vec<PoxAddress> {
        if let Some(recipient_set) = from {
            let mut outs: Vec<_> = recipient_set
                .recipients
                .into_iter()
                .map(|(recipient, _)| recipient)
                .collect();
            while outs.len() < OUTPUTS_PER_COMMIT {
                outs.push(PoxAddress::standard_burn_address(mainnet));
            }
            outs
        } else {
            (0..OUTPUTS_PER_COMMIT)
                .map(|_| PoxAddress::standard_burn_address(mainnet))
                .collect()
        }
    }
}

impl LeaderBlockCommitOp {
    /// Perform PoX checks on this block-commit, given the reward set info (which may be None if
    /// PoX is not active).
    ///
    /// If PoX was active (i.e., `reward_set_info` is `Some`), this method will return how the
    ///  PoX addresses were treated by the block commit. Prior to Epoch 3.0, these will be all
    ///  treated with rewards (attempting to punish pre-nakamoto will result in a op_error).
    ///
    /// If `reward_set_info` is not None, then *only* the addresses in .recipients are used.  The u16
    /// indexes are *ignored* (and *must be* ignored, since this method gets called by
    /// `check_intneded_sortition()`, which does not have this information).
    fn check_pox<SH: SortitionHandle>(
        &self,
        epoch_id: StacksEpochId,
        burnchain: &Burnchain,
        tx: &mut SH,
        reward_set_info: Option<&RewardSetInfo>,
    ) -> Result<Vec<Treatment>, op_error> {
        let parent_block_height = u64::from(self.parent_block_ptr);

        if PoxConstants::has_pox_sunset(epoch_id) {
            // sunset only applies in epochs prior to 2.1.  After 2.1, miners can put whatever they
            // want into the sunset burn but it won't be checked, nor will it count towards their
            // sortition
            let total_committed = self
                .burn_fee
                .checked_add(self.sunset_burn)
                .expect("BUG: Overflow in total committed calculation");

            let expected_sunset_burn =
                burnchain.expected_sunset_burn(self.block_height, total_committed, epoch_id);
            if self.sunset_burn < expected_sunset_burn {
                warn!(
                    "Invalid block commit: should have included sunset burn amount of {}, found {}",
                    expected_sunset_burn, self.sunset_burn
                );
                return Err(op_error::BlockCommitBadOutputs);
            }
        }

        /////////////////////////////////////////////////////////////////////////////////////
        // This tx must have the expected commit or burn outputs:
        //    * if there is a known anchor block for the current reward cycle, and this
        //       block commit descends from that block, and this block commit is not in the
        //       prepare phase of the reward cycle, and there are still reward addresses
        //       left in this reward cycle to pay out to, then
        //       the commit outputs must = the expected set of commit outputs.
        //    * otherwise, the commit outputs must be burn outputs.
        /////////////////////////////////////////////////////////////////////////////////////
        let Some(reward_set_info) = reward_set_info else {
            // no recipient info for this sortition, so expect all burns
            if !self.all_outputs_burn() {
                warn!("Invalid block commit: this transaction should only have burn outputs.");
                return Err(op_error::BlockCommitBadOutputs);
            }
            return Ok(vec![]);
        };

        // we do some check-inversion here so that we check the commit_outs _before_
        //   we check whether or not the block is descended from the anchor.
        // we do this because the descended_from check isn't particularly cheap, so
        //   we want to make sure that any TX that forces us to perform the check
        //   has either burned BTC or sent BTC to the PoX recipients

        // if we're in the prepare phase, then this block-commit _must_ burn.
        // No PoX descent check needs to be performed -- prepare-phase block commits
        // stand alone.
        if burnchain.is_in_prepare_phase(self.block_height) {
            if let Err(e) = self.check_prepare_commit_burn() {
                warn!("Invalid block commit: in block {} which is in the prepare phase, but did not burn to a single output as expected ({:?})", self.block_height, &e);
                return Err(op_error::BlockCommitBadOutputs);
            }
            return Ok(vec![]);
        }

        // Not in prepare phase, so this can be either PoB or PoX (a descent check from the
        // anchor block will be necessary if the block-commit is well-formed).
        //
        // first, handle a corner case:
        //    all of the commitment outputs are _burns_
        //    _and_ the reward set chose two burn addresses as reward addresses.
        // then, don't need to do a pox descendant check.
        let recipient_set_all_burns = reward_set_info
            .recipients
            .iter()
            .fold(true, |prior_is_burn, (addr, ..)| {
                prior_is_burn && addr.is_burn()
            });

        if recipient_set_all_burns {
            if !self.all_outputs_burn() {
                warn!("Invalid block commit: recipient set should be all burns");
                return Err(op_error::BlockCommitBadOutputs);
            }
            return Ok(vec![]);
        }

        // Now, we are checking the reward sets match, and if they don't,
        //  whether or not pox descendant is necessary

        // first, if we're in a nakamoto epoch, any block commit building directly off of the anchor block
        //  is descendant
        let directly_descended_from_anchor = epoch_id.block_commits_to_parent()
            && self.block_header_hash == reward_set_info.anchor_block;

        // second, if we're in a nakamoto epoch, and the parent block has vtxindex 0 (i.e. the
        // coinbase of the burnchain block), then assume that this block descends from the anchor
        // block for the purposes of validating its PoX payouts.  The block validation logic will
        // check that the parent block is indeed a shadow block, and that `self.parent_block_ptr`
        // points to the shadow block's tenure's burnchain block.
        let maybe_shadow_parent = epoch_id.supports_shadow_blocks()
            && self.parent_block_ptr != 0
            && self.parent_vtxindex == 0;

        let descended_from_anchor = directly_descended_from_anchor
            || maybe_shadow_parent
            || tx.descended_from(parent_block_height, &reward_set_info.anchor_block)
            .map_err(|e| {
                error!("Failed to check whether parent (height={}) is descendent of anchor block={}: {}",
                       parent_block_height, &reward_set_info.anchor_block, e);
                op_error::BlockCommitAnchorCheck
            })?;

        if self.all_outputs_burn() {
            // If we're not descended from the anchor, then great, this is just a "normal" non-descendant burn commit
            // But, if we are descended from the anchor and nakamoto pox punishments are allowed, this commit may have
            //  been a double punishment
            if !descended_from_anchor {
                return Ok(vec![]);
            }
            if reward_set_info.allow_nakamoto_punishment {
                // all non-burn recipients were punished -- when we do the block processing
                //  enforcement check, "burn recipients" can be treated as 1 or a 0 in the
                //  bitvec interchangeably (whether they are punished or not doesn't matter).
                let punished = reward_set_info
                    .recipients
                    .iter()
                    .map(|(addr, _)| Treatment::Punish(addr.clone()))
                    .collect();
                return Ok(punished);
            } else {
                warn!(
                    "Invalid block commit: descended from PoX anchor {}, but used burn outputs",
                    &reward_set_info.anchor_block
                );
                return Err(op_error::BlockCommitBadOutputs);
            }
        } else {
            let mut check_recipients: Vec<_> = reward_set_info
                .recipients
                .iter()
                .map(|(addr, ix)| (addr.clone(), *ix))
                .collect();

            if check_recipients.len() == 1 {
                // If the number of recipients in the set was odd, we need to pad
                // with a burn address.
                // NOTE: this used the old burnchain.is_mainnet() code, which always
                // returns false
                check_recipients.push((PoxAddress::standard_burn_address(false), 0))
            }

            if self.commit_outs.len() != check_recipients.len() {
                warn!(
                    "Invalid block commit: expected {} PoX transfers, but commit has {}",
                    reward_set_info.recipients.len(),
                    self.commit_outs.len()
                );
                return Err(op_error::BlockCommitBadOutputs);
            }

            // we've checked length equality, so we can just iterate through
            //  self.commit_outs and check if each is in `check_recipients`
            //  *OR* if `allows_pox_punishment`, then it could be a burn.
            // NOTE: we do a find and remove here so that the same recipient
            //  isn't found multiple times by different commit_outs.
            let mut rewarded = vec![];
            for self_commit in self.commit_outs.iter() {
                let search_predicate = self_commit.to_burnchain_repr();
                let found = check_recipients
                    .iter()
                    .enumerate()
                    .find(|(_, (check_commit, _))| {
                        search_predicate == check_commit.to_burnchain_repr()
                    });
                if let Some((index, _)) = found {
                    rewarded.push(Treatment::Reward(check_recipients.remove(index).0));
                } else {
                    // if we didn't find the pox output, then maybe its a pox punishment?
                    if reward_set_info.allow_nakamoto_punishment && self_commit.is_burn() {
                        continue;
                    } else {
                        warn!("Invalid block commit: committed output {} does not match expected recipient set: {:?}",
                              self_commit.to_burnchain_repr(), check_recipients);
                        return Err(op_error::BlockCommitBadOutputs);
                    }
                };
            }

            if !descended_from_anchor {
                warn!(
                    "Invalid block commit: not descended from PoX anchor {}, but used PoX outputs",
                    &reward_set_info.anchor_block
                );
                return Err(op_error::BlockCommitBadOutputs);
            }

            let mut treated_outputs: Vec<_> = check_recipients
                .into_iter()
                .map(|x| Treatment::Punish(x.0))
                .collect();
            treated_outputs.extend(rewarded);
            return Ok(treated_outputs);
        }
    }

    fn check_single_burn_output(&self) -> Result<(), op_error> {
        if self.commit_outs.len() != 1 {
            warn!("Invalid prepare-phase block commit, should have 1 commit out");
            return Err(op_error::BlockCommitBadOutputs);
        }
        if !self.commit_outs[0].is_burn() {
            warn!("Invalid prepare-phase block commit, should have burn address output");
            return Err(op_error::BlockCommitBadOutputs);
        }
        Ok(())
    }

    fn check_after_pox_sunset(&self) -> Result<(), op_error> {
        self.check_single_burn_output()
    }

    fn check_prepare_commit_burn(&self) -> Result<(), op_error> {
        self.check_single_burn_output()
    }

    /// Check the epoch marker in a block-commit to make sure it matches the right epoch.
    /// Valid in Stacks 2.05+
    fn check_epoch_commit_marker(&self, marker: u8) -> Result<(), op_error> {
        if self.memo.is_empty() {
            debug!(
                "Invalid block commit";
                "reason" => "no epoch marker byte given",
            );
            return Err(op_error::BlockCommitBadEpoch);
        }
        if self.memo[0] < marker {
            debug!(
                "Invalid block commit";
                "reason" => "invalid epoch marker byte",
                "marker_byte" => self.memo[0],
                "expected_marker_byte" => marker,
            );
            return Err(op_error::BlockCommitBadEpoch);
        }

        Ok(())
    }

    /// Check the epoch marker in the block commit, given the epoch we're in
    fn check_epoch_commit(&self, epoch_id: StacksEpochId) -> Result<(), op_error> {
        match epoch_id {
            StacksEpochId::Epoch10 => {
                panic!("FATAL: processed block-commit pre-Stacks 2.0");
            }
            StacksEpochId::Epoch20 => {
                // no-op, but log for helping node operators watch for old nodes
                if self.memo.is_empty() {
                    debug!(
                        "Soon-to-be-invalid block commit";
                        "reason" => "no epoch marker byte given",
                    );
                } else if self.memo[0] < STACKS_EPOCH_2_05_MARKER {
                    debug!(
                        "Soon-to-be-invalid block commit";
                        "reason" => "invalid epoch marker byte",
                        "marker_byte" => self.memo[0],
                    );
                }
                Ok(())
            }
            StacksEpochId::Epoch2_05 => self.check_epoch_commit_marker(STACKS_EPOCH_2_05_MARKER),
            StacksEpochId::Epoch21 => self.check_epoch_commit_marker(STACKS_EPOCH_2_1_MARKER),
            StacksEpochId::Epoch22 => self.check_epoch_commit_marker(STACKS_EPOCH_2_2_MARKER),
            StacksEpochId::Epoch23 => self.check_epoch_commit_marker(STACKS_EPOCH_2_3_MARKER),
            StacksEpochId::Epoch24 => self.check_epoch_commit_marker(STACKS_EPOCH_2_4_MARKER),
            StacksEpochId::Epoch25 => self.check_epoch_commit_marker(STACKS_EPOCH_2_5_MARKER),
            StacksEpochId::Epoch30 => self.check_epoch_commit_marker(STACKS_EPOCH_3_0_MARKER),
            StacksEpochId::Epoch31 => self.check_epoch_commit_marker(STACKS_EPOCH_3_1_MARKER),
        }
    }

    /// Verify that a missed block-commit would have been valid if it was not missed.
    /// This contains epoch-specific checks.
    fn check_intended_sortition(
        &self,
        epoch_id: StacksEpochId,
        burnchain: &Burnchain,
        tx: &mut SortitionHandleTx,
        miss_distance: u64,
    ) -> Result<SortitionId, op_error> {
        let tx_tip = tx.context.chain_tip.clone();
        let intended_sortition = match epoch_id {
            StacksEpochId::Epoch21
            | StacksEpochId::Epoch22
            | StacksEpochId::Epoch23
            | StacksEpochId::Epoch24
            | StacksEpochId::Epoch25
            | StacksEpochId::Epoch30
            | StacksEpochId::Epoch31 => {
                // correct behavior -- uses *sortition height* to find the intended sortition ID
                let sortition_height = self
                    .block_height
                    .checked_sub(burnchain.first_block_height)
                    .ok_or_else(|| op_error::BlockCommitPredatesGenesis)?;

                if miss_distance > sortition_height {
                    return Err(op_error::BlockCommitBadModulus);
                }

                if miss_distance > 1 {
                    // can't miss by more than 1 block; otherwise a miner can just bunch up all
                    // their block-commits into a single burnchain block and mine when they want
                    // without the 6-block warm-up period.
                    return Err(op_error::BlockCommitMissDistanceTooBig);
                }

                let intended_sortition = tx
                    .get_ancestor_block_hash(sortition_height - miss_distance, &tx_tip)?
                    .ok_or_else(|| op_error::BlockCommitNoParent)?;

                let intended_sn = SortitionDB::get_block_snapshot(tx, &intended_sortition)?
                    .expect("FATAL: no snapshot for known sortition");
                debug!("Block commit for {} missed, meant to land in burnchain block {} (sortition {})", &self.block_header_hash, intended_sn.block_height, &intended_sortition);

                // NOTE: we're not doing the checks in check_common() because it doesn't matter if
                // the late block-commit does not meet them -- it will never be a sortition winner
                // anyway.
                //
                // But, we must disincentivize deliberately sending late block-commits (e.g. to
                // improve the miner's median sortition spend), so it's necessary to require the
                // miner to pay burnchain tokens to the intended sortition's reward addresses.  Then,
                // doing this on purpose is at least as costly as mining honestly.
                let reward_set_info_opt =
                    RewardSetInfo::from_missed_commit(tx, &intended_sortition)?;
                self.check_pox(epoch_id, burnchain, tx, reward_set_info_opt.as_ref())?;

                intended_sortition
            }
            StacksEpochId::Epoch20 | StacksEpochId::Epoch2_05 => {
                // buggy behavior that must be preserved for compatibility :(
                // bug: uses self.block_height to find the intended sortition ID (which won't work)
                if miss_distance > self.block_height {
                    return Err(op_error::BlockCommitBadModulus);
                }
                tx.get_ancestor_block_hash(self.block_height - miss_distance, &tx_tip)?
                    .ok_or_else(|| op_error::BlockCommitNoParent)?

                // also buggy behavior -- the block-commit can pay to any PoX output it wants, so
                // sending them deliberately is "free" because the sender can just pay themselves.
            }
            StacksEpochId::Epoch10 => {
                panic!("Block commits are not supported in epoch 1.0");
            }
        };
        Ok(intended_sortition)
    }

    /// Perform the block-commit checks that are the same in both PoX and PoB, and common to both
    /// on-time and late block-commits
    fn check_common(
        &self,
        epoch_id: StacksEpochId,
        tx: &mut SortitionHandleTx,
    ) -> Result<(), op_error> {
        let leader_key_block_height = u64::from(self.key_block_ptr);
        let parent_block_height = u64::from(self.parent_block_ptr);

        let tx_tip = tx.context.chain_tip.clone();
        let apparent_sender_repr = format!("{}", &self.apparent_sender);

        /////////////////////////////////////////////////////////////////////////////////////
        // This tx must occur after the start of the network
        /////////////////////////////////////////////////////////////////////////////////////

        let first_block_snapshot = SortitionDB::get_first_block_snapshot(tx.tx())?;

        if self.block_height < first_block_snapshot.block_height {
            warn!(
                "Invalid block commit from {}: predates genesis height {}",
                self.block_height,
                first_block_snapshot.block_height;
                "apparent_sender" => %apparent_sender_repr
            );
            return Err(op_error::BlockCommitPredatesGenesis);
        }

        /////////////////////////////////////////////////////////////////////////////////////
        // Block must be unique in this burnchain fork
        /////////////////////////////////////////////////////////////////////////////////////

        let is_already_committed = tx.expects_stacks_block_in_fork(&self.block_header_hash)?;

        // in Epoch3.0+, block commits can include Stacks blocks already accepted in the fork.
        if is_already_committed && epoch_id < StacksEpochId::Epoch30 {
            warn!(
                "Invalid block commit: already committed to {}",
                self.block_header_hash;
                "apparent_sender" => %apparent_sender_repr
            );
            return Err(op_error::BlockCommitAlreadyExists);
        }

        /////////////////////////////////////////////////////////////////////////////////////
        // There must exist a previously-accepted key from a LeaderKeyRegister
        /////////////////////////////////////////////////////////////////////////////////////

        if leader_key_block_height >= self.block_height {
            warn!(
                "Invalid block commit: references leader key in the same or later block ({} >= {})",
                leader_key_block_height, self.block_height;
                "apparent_sender" => %apparent_sender_repr
            );
            return Err(op_error::BlockCommitNoLeaderKey);
        }

        let _register_key = tx
            .get_leader_key_at(leader_key_block_height, self.key_vtxindex.into(), &tx_tip)?
            .ok_or_else(|| {
                warn!(
                    "Invalid block commit: no corresponding leader key at {},{} in fork {}",
                    leader_key_block_height, self.key_vtxindex, &tx.context.chain_tip;
                    "apparent_sender" => %apparent_sender_repr
                );
                op_error::BlockCommitNoLeaderKey
            })?;

        /////////////////////////////////////////////////////////////////////////////////////
        // There must exist a previously-accepted block from a LeaderBlockCommit, or this
        // LeaderBlockCommit must build off of the genesis block.  If _not_ building off of the
        // genesis block, then the parent block must be in a different epoch (i.e. its parent must
        // be committed already).
        /////////////////////////////////////////////////////////////////////////////////////

        if parent_block_height == self.block_height {
            // tried to build off a block in the same epoch (not allowed)
            warn!("Invalid block commit: cannot build off of a commit in the same block";
                  "apparent_sender" => %apparent_sender_repr
            );
            return Err(op_error::BlockCommitNoParent);
        } else if self.parent_block_ptr != 0 || self.parent_vtxindex != 0 {
            // not building off of genesis, so the parent block must exist
            // unless the parent is a shadow block
            let has_parent = tx
                .get_block_commit_parent(parent_block_height, self.parent_vtxindex.into(), &tx_tip)?
                .is_some();
            let maybe_shadow_block = self.parent_vtxindex == 0 && epoch_id.supports_shadow_blocks();
            if !has_parent && !maybe_shadow_block {
                warn!("Invalid block commit: no parent block in this fork";
                      "apparent_sender" => %apparent_sender_repr
                );
                return Err(op_error::BlockCommitNoParent);
            }
        }

        /////////////////////////////////////////////////////////////////////////////////////
        // If we are in Stacks 2.05 or later, then the memo field *must* have the appropriate epoch
        // marker.  That is, the upper 5 bits of the byte whose lower 3 bits contain the burn
        // parent modulus must have the marker bit pattern.  For example, in 2.05, this is 0b00101.
        //
        // This means that the byte must look like 0bXXXXXYYY, where XXXXX is the epoch marker bit
        // pattern, and YYY is the burn parent modulus.
        //
        // The epoch marker is a minimum-allowed value.  The miner can put a larger number in the
        // epoch marker field -- for example, to signal support for a new epoch or to be
        // forwards-compatible with it -- but cannot put a lesser number in.
        /////////////////////////////////////////////////////////////////////////////////////
        self.check_epoch_commit(epoch_id)?;
        Ok(())
    }

    /// Returns Ok() and a vector of PoxAddresses which were punished by this op
    pub fn check(
        &mut self,
        burnchain: &Burnchain,
        tx: &mut SortitionHandleTx,
        reward_set_info: Option<&RewardSetInfo>,
    ) -> Result<(), op_error> {
        /////////////////////////////////////////////////////////////////////////////////////
        // There must be a burn
        /////////////////////////////////////////////////////////////////////////////////////

        let apparent_sender_repr = format!("{}", &self.apparent_sender);

        if self.burn_fee == 0 {
            warn!("Invalid block commit: no burn amount";
                  "apparent_sender" => %apparent_sender_repr
            );
            return Err(op_error::BlockCommitBadInput);
        }
        let epoch = SortitionDB::get_stacks_epoch(tx, self.block_height)?.unwrap_or_else(|| {
            panic!(
                "FATAL: impossible block height: no epoch defined for {}",
                self.block_height
            )
        });

        let intended_modulus = (self.burn_block_mined_at() + 1) % BURN_BLOCK_MINED_AT_MODULUS;
        let actual_modulus = self.block_height % BURN_BLOCK_MINED_AT_MODULUS;
        if actual_modulus != intended_modulus {
            // This transaction "missed" its target burn block, the transaction
            //  is not valid, but we should allow this UTXO to "chain" to valid
            //  UTXOs to allow the miner windowing to work in the face of missed
            //  blocks.
            let miss_distance = if actual_modulus > intended_modulus {
                actual_modulus - intended_modulus
            } else {
                BURN_BLOCK_MINED_AT_MODULUS + actual_modulus - intended_modulus
            };
            warn!("Invalid block commit: missed target block";
                  "intended_modulus" => intended_modulus,
                  "actual_modulus" => actual_modulus,
                  "miss_distance" => miss_distance,
                  "block_height" => self.block_height,
                  "apparent_sender" => %apparent_sender_repr
            );
            let intended_sortition =
                self.check_intended_sortition(epoch.epoch_id, burnchain, tx, miss_distance)?;
            let missed_data = MissedBlockCommit {
                input: self.input.clone(),
                txid: self.txid.clone(),
                intended_sortition,
            };

            return Err(op_error::MissedBlockCommit(missed_data));
        }

        let punished = if burnchain
            .pox_constants
            .is_after_pox_sunset_end(self.block_height, epoch.epoch_id)
        {
            // sunset has begun and we're not in epoch 2.1 or later, so apply sunset check
            self.check_after_pox_sunset().map_err(|e| {
                warn!("Invalid block-commit: bad PoX after sunset: {:?}", &e;
                          "apparent_sender" => %apparent_sender_repr);
                e
            })?;
            vec![]
        } else {
            // either in epoch 2.1, or the PoX sunset hasn't completed yet
            self.check_pox(epoch.epoch_id, burnchain, tx, reward_set_info)
                .map_err(|e| {
                    warn!("Invalid block-commit: bad PoX: {:?}", &e;
                          "apparent_sender" => %apparent_sender_repr);
                    e
                })?
        };

        self.check_common(epoch.epoch_id, tx)?;

        if reward_set_info.is_some_and(|r| r.allow_nakamoto_punishment) {
            self.treatment = punished;
        }

        // good to go!
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use clarity::vm::costs::ExecutionCost;
    use rand::{thread_rng, RngCore};
    use stacks_common::address::AddressHashMode;
    use stacks_common::deps_common::bitcoin::blockdata::transaction::{Transaction, TxOut};
    use stacks_common::deps_common::bitcoin::network::serialize::{deserialize, serialize_hex};
    use stacks_common::types::chainstate::{BlockHeaderHash, SortitionId, StacksAddress, VRFSeed};
    use stacks_common::util::get_epoch_time_secs;
    use stacks_common::util::hash::*;
    use stacks_common::util::vrf::VRFPublicKey;

    use super::*;
    use crate::burnchains::bitcoin::address::*;
    use crate::burnchains::bitcoin::blocks::BitcoinBlockParser;
    use crate::burnchains::bitcoin::keys::BitcoinPublicKey;
    use crate::burnchains::bitcoin::*;
    use crate::burnchains::*;
    use crate::chainstate::burn::db::sortdb::tests::{
        test_append_snapshot, test_append_snapshot_with_winner,
    };
    use crate::chainstate::burn::db::sortdb::*;
    use crate::chainstate::burn::db::*;
    use crate::chainstate::burn::operations::*;
    use crate::chainstate::burn::{ConsensusHash, *};
    use crate::chainstate::stacks::address::StacksAddressExtensions;
    use crate::chainstate::stacks::StacksPublicKey;
    use crate::core::{
        StacksEpoch, StacksEpochExtension, StacksEpochId, PEER_VERSION_EPOCH_1_0,
        PEER_VERSION_EPOCH_2_0, PEER_VERSION_EPOCH_2_05, PEER_VERSION_EPOCH_2_1, STACKS_EPOCH_MAX,
    };

    struct OpFixture {
        txstr: String,
        opstr: String,
        result: Option<LeaderBlockCommitOp>,
    }

    struct CheckFixture {
        op: LeaderBlockCommitOp,
        res: Result<(), op_error>,
    }

    fn make_tx(hex_str: &str) -> Result<Transaction, &'static str> {
        let tx_bin = hex_bytes(hex_str).map_err(|_e| "failed to decode hex string")?;
        let tx = deserialize(&tx_bin.to_vec()).map_err(|_e| "failed to deserialize")?;
        Ok(tx)
    }

    fn stacks_address_to_bitcoin_tx_out(addr: &StacksAddress, value: u64) -> TxOut {
        let btc_version = to_b58_version_byte(addr.version)
            .expect("BUG: failed to decode Stacks version byte to Bitcoin version byte");
        let btc_addr_type = legacy_version_byte_to_address_type(btc_version)
            .expect("BUG: failed to decode Bitcoin version byte")
            .0;
        match btc_addr_type {
            LegacyBitcoinAddressType::PublicKeyHash => {
                LegacyBitcoinAddress::to_p2pkh_tx_out(&addr.bytes, value)
            }
            LegacyBitcoinAddressType::ScriptHash => {
                LegacyBitcoinAddress::to_p2sh_tx_out(&addr.bytes, value)
            }
        }
    }

    #[test]
    fn test_parse_sunset_end() {
        let tx = BurnchainTransaction::Bitcoin(BitcoinTransaction {
            data_amt: 0,
            txid: Txid([0; 32]),
            vtxindex: 0,
            opcode: Opcodes::LeaderBlockCommit as u8,
            data: vec![1; 80],
            inputs: vec![BitcoinTxInputStructured {
                keys: vec![],
                num_required: 0,
                in_type: BitcoinInputType::Standard,
                tx_ref: (Txid([0; 32]), 0),
            }
            .into()],
            outputs: vec![
                BitcoinTxOutput {
                    units: 10,
                    address: BitcoinAddress::Legacy(LegacyBitcoinAddress {
                        addrtype: LegacyBitcoinAddressType::PublicKeyHash,
                        network_id: BitcoinNetworkType::Mainnet,
                        bytes: Hash160([1; 20]),
                    }),
                },
                BitcoinTxOutput {
                    units: 10,
                    address: BitcoinAddress::Legacy(LegacyBitcoinAddress {
                        addrtype: LegacyBitcoinAddressType::PublicKeyHash,
                        network_id: BitcoinNetworkType::Mainnet,
                        bytes: Hash160([2; 20]),
                    }),
                },
                BitcoinTxOutput {
                    units: 30,
                    address: BitcoinAddress::Legacy(LegacyBitcoinAddress {
                        addrtype: LegacyBitcoinAddressType::PublicKeyHash,
                        network_id: BitcoinNetworkType::Mainnet,
                        bytes: Hash160([3; 20]),
                    }),
                },
            ],
        });

        let mut burnchain = Burnchain::regtest("nope");
        burnchain.pox_constants.sunset_start = 16843021;
        burnchain.pox_constants.sunset_end = 16843022;

        // should fail in epoch 2.05 -- not a burn output
        let err = LeaderBlockCommitOp::parse_from_tx(
            &burnchain,
            16843022,
            &BurnchainHeaderHash([0; 32]),
            StacksEpochId::Epoch2_05,
            &tx,
        )
        .unwrap_err();

        assert!(if let op_error::BlockCommitBadOutputs = err {
            true
        } else {
            false
        });

        // should succeed in epoch 2.1 -- can be PoX in 2.1
        let _op = LeaderBlockCommitOp::parse_from_tx(
            &burnchain,
            16843022,
            &BurnchainHeaderHash([0; 32]),
            StacksEpochId::Epoch21,
            &tx,
        )
        .unwrap();

        let tx = BurnchainTransaction::Bitcoin(BitcoinTransaction {
            data_amt: 0,
            txid: Txid([0; 32]),
            vtxindex: 0,
            opcode: Opcodes::LeaderBlockCommit as u8,
            data: vec![1; 80],
            inputs: vec![BitcoinTxInputStructured {
                keys: vec![],
                num_required: 0,
                in_type: BitcoinInputType::Standard,
                tx_ref: (Txid([0; 32]), 0),
            }
            .into()],
            outputs: vec![
                BitcoinTxOutput {
                    units: 10,
                    address: BitcoinAddress::Legacy(LegacyBitcoinAddress {
                        addrtype: LegacyBitcoinAddressType::PublicKeyHash,
                        network_id: BitcoinNetworkType::Mainnet,
                        bytes: Hash160([0; 20]),
                    }),
                },
                BitcoinTxOutput {
                    units: 10,
                    address: BitcoinAddress::Legacy(LegacyBitcoinAddress {
                        addrtype: LegacyBitcoinAddressType::PublicKeyHash,
                        network_id: BitcoinNetworkType::Mainnet,
                        bytes: Hash160([2; 20]),
                    }),
                },
                BitcoinTxOutput {
                    units: 30,
                    address: BitcoinAddress::Legacy(LegacyBitcoinAddress {
                        addrtype: LegacyBitcoinAddressType::PublicKeyHash,
                        network_id: BitcoinNetworkType::Mainnet,
                        bytes: Hash160([0; 20]),
                    }),
                },
            ],
        });

        let mut burnchain = Burnchain::regtest("nope");
        burnchain.pox_constants.sunset_start = 16843021;
        burnchain.pox_constants.sunset_end = 16843022;

        // succeeds in epoch 2.05 because of the burn output
        let op = LeaderBlockCommitOp::parse_from_tx(
            &burnchain,
            16843022,
            &BurnchainHeaderHash([0; 32]),
            StacksEpochId::Epoch2_05,
            &tx,
        )
        .unwrap();

        assert_eq!(op.commit_outs.len(), 1);
        assert!(op.commit_outs[0].is_burn());
        assert_eq!(op.burn_fee, 10);

        // succeeds in epoch 2.1 because the sunset doesn't apply
        let op = LeaderBlockCommitOp::parse_from_tx(
            &burnchain,
            16843022,
            &BurnchainHeaderHash([0; 32]),
            StacksEpochId::Epoch21,
            &tx,
        )
        .unwrap();

        assert_eq!(op.commit_outs.len(), 2);
        assert!(op.commit_outs[0].is_burn());
        assert_eq!(op.burn_fee, 20);
    }

    #[test]
    fn test_parse_pox_commits() {
        let tx = BurnchainTransaction::Bitcoin(BitcoinTransaction {
            data_amt: 30,
            txid: Txid([0; 32]),
            vtxindex: 0,
            opcode: Opcodes::LeaderBlockCommit as u8,
            data: vec![1; 80],
            inputs: vec![BitcoinTxInputStructured {
                keys: vec![],
                num_required: 0,
                in_type: BitcoinInputType::Standard,
                tx_ref: (Txid([0; 32]), 0),
            }
            .into()],
            outputs: vec![
                BitcoinTxOutput {
                    units: 10,
                    address: BitcoinAddress::Legacy(LegacyBitcoinAddress {
                        addrtype: LegacyBitcoinAddressType::PublicKeyHash,
                        network_id: BitcoinNetworkType::Mainnet,
                        bytes: Hash160([1; 20]),
                    }),
                },
                BitcoinTxOutput {
                    units: 10,
                    address: BitcoinAddress::Legacy(LegacyBitcoinAddress {
                        addrtype: LegacyBitcoinAddressType::PublicKeyHash,
                        network_id: BitcoinNetworkType::Mainnet,
                        bytes: Hash160([2; 20]),
                    }),
                },
                BitcoinTxOutput {
                    units: 30,
                    address: BitcoinAddress::Legacy(LegacyBitcoinAddress {
                        addrtype: LegacyBitcoinAddressType::PublicKeyHash,
                        network_id: BitcoinNetworkType::Mainnet,
                        bytes: Hash160([0; 20]),
                    }),
                },
            ],
        });

        let mut burnchain = Burnchain::regtest("nope");
        burnchain.pox_constants.prepare_length = 1;
        burnchain.pox_constants.anchor_threshold = 1;
        burnchain.pox_constants.sunset_start = 16843019;
        burnchain.pox_constants.sunset_end = 16843020;

        let op = LeaderBlockCommitOp::parse_from_tx(
            &burnchain,
            16843019,
            &BurnchainHeaderHash([0; 32]),
            StacksEpochId::Epoch2_05,
            &tx,
        )
        .unwrap();

        // should have 2 commit outputs, summing to 20 burned units
        assert_eq!(op.commit_outs.len(), 2);
        assert_eq!(op.burn_fee, 20);
        // the third output, because it's a burn, should have counted as a sunset_burn
        assert_eq!(op.sunset_burn, 30);

        let tx = BurnchainTransaction::Bitcoin(BitcoinTransaction {
            data_amt: 0,
            txid: Txid([0; 32]),
            vtxindex: 0,
            opcode: Opcodes::LeaderBlockCommit as u8,
            data: vec![1; 80],
            inputs: vec![BitcoinTxInputStructured {
                keys: vec![],
                num_required: 0,
                in_type: BitcoinInputType::Standard,
                tx_ref: (Txid([0; 32]), 0),
            }
            .into()],
            outputs: vec![
                BitcoinTxOutput {
                    units: 10,
                    address: BitcoinAddress::Legacy(LegacyBitcoinAddress {
                        addrtype: LegacyBitcoinAddressType::PublicKeyHash,
                        network_id: BitcoinNetworkType::Mainnet,
                        bytes: Hash160([1; 20]),
                    }),
                },
                BitcoinTxOutput {
                    units: 9,
                    address: BitcoinAddress::Legacy(LegacyBitcoinAddress {
                        addrtype: LegacyBitcoinAddressType::PublicKeyHash,
                        network_id: BitcoinNetworkType::Mainnet,
                        bytes: Hash160([0; 20]),
                    }),
                },
            ],
        });

        let mut burnchain = Burnchain::regtest("nope");
        burnchain.pox_constants.prepare_length = 1;
        burnchain.pox_constants.anchor_threshold = 1;
        burnchain.pox_constants.sunset_start = 16843019;
        burnchain.pox_constants.sunset_end = 16843020;

        // burn amount should have been 10, not 9
        match LeaderBlockCommitOp::parse_from_tx(
            &burnchain,
            16843019,
            &BurnchainHeaderHash([0; 32]),
            StacksEpochId::Epoch2_05,
            &tx,
        )
        .unwrap_err()
        {
            op_error::ParseError => {}
            _ => unreachable!(),
        };

        let tx = BurnchainTransaction::Bitcoin(BitcoinTransaction {
            data_amt: 0,
            txid: Txid([0; 32]),
            vtxindex: 0,
            opcode: Opcodes::LeaderBlockCommit as u8,
            data: vec![1; 80],
            inputs: vec![BitcoinTxInputStructured {
                keys: vec![],
                num_required: 0,
                in_type: BitcoinInputType::Standard,
                tx_ref: (Txid([0; 32]), 0),
            }
            .into()],
            outputs: vec![
                BitcoinTxOutput {
                    units: 13,
                    address: BitcoinAddress::Legacy(LegacyBitcoinAddress {
                        addrtype: LegacyBitcoinAddressType::PublicKeyHash,
                        network_id: BitcoinNetworkType::Mainnet,
                        bytes: Hash160([1; 20]),
                    }),
                },
                BitcoinTxOutput {
                    units: 13,
                    address: BitcoinAddress::Legacy(LegacyBitcoinAddress {
                        addrtype: LegacyBitcoinAddressType::PublicKeyHash,
                        network_id: BitcoinNetworkType::Mainnet,
                        bytes: Hash160([2; 20]),
                    }),
                },
                BitcoinTxOutput {
                    units: 13,
                    address: BitcoinAddress::Legacy(LegacyBitcoinAddress {
                        addrtype: LegacyBitcoinAddressType::PublicKeyHash,
                        network_id: BitcoinNetworkType::Mainnet,
                        bytes: Hash160([2; 20]),
                    }),
                },
                BitcoinTxOutput {
                    units: 13,
                    address: BitcoinAddress::Legacy(LegacyBitcoinAddress {
                        addrtype: LegacyBitcoinAddressType::PublicKeyHash,
                        network_id: BitcoinNetworkType::Mainnet,
                        bytes: Hash160([2; 20]),
                    }),
                },
                BitcoinTxOutput {
                    units: 13,
                    address: BitcoinAddress::Legacy(LegacyBitcoinAddress {
                        addrtype: LegacyBitcoinAddressType::PublicKeyHash,
                        network_id: BitcoinNetworkType::Mainnet,
                        bytes: Hash160([2; 20]),
                    }),
                },
            ],
        });

        let mut burnchain = Burnchain::regtest("nope");
        burnchain.pox_constants.prepare_length = 1;
        burnchain.pox_constants.anchor_threshold = 1;
        burnchain.pox_constants.sunset_start = 16843019;
        burnchain.pox_constants.sunset_end = 16843020;

        let op = LeaderBlockCommitOp::parse_from_tx(
            &burnchain,
            16843019,
            &BurnchainHeaderHash([0; 32]),
            StacksEpochId::Epoch2_05,
            &tx,
        )
        .unwrap();

        // should have 2 commit outputs
        assert_eq!(op.commit_outs.len(), 2);
        assert_eq!(op.burn_fee, 26);
        // the third output, because it's not a burn, should not have counted as a sunset_burn
        assert_eq!(op.sunset_burn, 0);

        let tx = BurnchainTransaction::Bitcoin(BitcoinTransaction {
            data_amt: 0,
            txid: Txid([0; 32]),
            vtxindex: 0,
            opcode: Opcodes::LeaderBlockCommit as u8,
            data: vec![1; 80],
            inputs: vec![BitcoinTxInputStructured {
                keys: vec![],
                num_required: 0,
                in_type: BitcoinInputType::Standard,
                tx_ref: (Txid([0; 32]), 0),
            }
            .into()],
            outputs: vec![BitcoinTxOutput {
                units: 13,
                address: BitcoinAddress::Legacy(LegacyBitcoinAddress {
                    addrtype: LegacyBitcoinAddressType::PublicKeyHash,
                    network_id: BitcoinNetworkType::Mainnet,
                    bytes: Hash160([1; 20]),
                }),
            }],
        });

        let mut burnchain = Burnchain::regtest("nope");
        burnchain.pox_constants.prepare_length = 1;
        burnchain.pox_constants.anchor_threshold = 1;
        burnchain.pox_constants.sunset_start = 16843019;
        burnchain.pox_constants.sunset_end = 16843020;

        // not enough PoX outputs
        match LeaderBlockCommitOp::parse_from_tx(
            &burnchain,
            16843019,
            &BurnchainHeaderHash([0; 32]),
            StacksEpochId::Epoch2_05,
            &tx,
        )
        .unwrap_err()
        {
            op_error::InvalidInput => {}
            _ => unreachable!(),
        };

        let tx = BurnchainTransaction::Bitcoin(BitcoinTransaction {
            data_amt: 0,
            txid: Txid([0; 32]),
            vtxindex: 0,
            opcode: Opcodes::LeaderBlockCommit as u8,
            data: vec![1; 80],
            inputs: vec![BitcoinTxInputStructured {
                keys: vec![],
                num_required: 0,
                in_type: BitcoinInputType::Standard,
                tx_ref: (Txid([0; 32]), 0),
            }
            .into()],
            outputs: vec![
                BitcoinTxOutput {
                    units: 13,
                    address: BitcoinAddress::Legacy(LegacyBitcoinAddress {
                        addrtype: LegacyBitcoinAddressType::PublicKeyHash,
                        network_id: BitcoinNetworkType::Mainnet,
                        bytes: Hash160([1; 20]),
                    }),
                },
                BitcoinTxOutput {
                    units: 10,
                    address: BitcoinAddress::Legacy(LegacyBitcoinAddress {
                        addrtype: LegacyBitcoinAddressType::PublicKeyHash,
                        network_id: BitcoinNetworkType::Mainnet,
                        bytes: Hash160([2; 20]),
                    }),
                },
            ],
        });

        let mut burnchain = Burnchain::regtest("nope");
        burnchain.pox_constants.prepare_length = 1;
        burnchain.pox_constants.anchor_threshold = 1;
        burnchain.pox_constants.sunset_start = 16843019;
        burnchain.pox_constants.sunset_end = 16843020;

        // unequal PoX outputs
        match LeaderBlockCommitOp::parse_from_tx(
            &burnchain,
            16843019,
            &BurnchainHeaderHash([0; 32]),
            StacksEpochId::Epoch2_05,
            &tx,
        )
        .unwrap_err()
        {
            op_error::ParseError => {}
            _ => unreachable!(),
        };

        let tx = BurnchainTransaction::Bitcoin(BitcoinTransaction {
            data_amt: 0,
            txid: Txid([0; 32]),
            vtxindex: 0,
            opcode: Opcodes::LeaderBlockCommit as u8,
            data: vec![1; 80],
            inputs: vec![BitcoinTxInputStructured {
                keys: vec![],
                num_required: 0,
                in_type: BitcoinInputType::Standard,
                tx_ref: (Txid([0; 32]), 0),
            }
            .into()],
            outputs: vec![
                BitcoinTxOutput {
                    units: 0,
                    address: BitcoinAddress::Legacy(LegacyBitcoinAddress {
                        addrtype: LegacyBitcoinAddressType::PublicKeyHash,
                        network_id: BitcoinNetworkType::Mainnet,
                        bytes: Hash160([1; 20]),
                    }),
                },
                BitcoinTxOutput {
                    units: 0,
                    address: BitcoinAddress::Legacy(LegacyBitcoinAddress {
                        addrtype: LegacyBitcoinAddressType::PublicKeyHash,
                        network_id: BitcoinNetworkType::Mainnet,
                        bytes: Hash160([2; 20]),
                    }),
                },
                BitcoinTxOutput {
                    units: 0,
                    address: BitcoinAddress::Legacy(LegacyBitcoinAddress {
                        addrtype: LegacyBitcoinAddressType::PublicKeyHash,
                        network_id: BitcoinNetworkType::Mainnet,
                        bytes: Hash160([2; 20]),
                    }),
                },
                BitcoinTxOutput {
                    units: 0,
                    address: BitcoinAddress::Legacy(LegacyBitcoinAddress {
                        addrtype: LegacyBitcoinAddressType::PublicKeyHash,
                        network_id: BitcoinNetworkType::Mainnet,
                        bytes: Hash160([2; 20]),
                    }),
                },
                BitcoinTxOutput {
                    units: 0,
                    address: BitcoinAddress::Legacy(LegacyBitcoinAddress {
                        addrtype: LegacyBitcoinAddressType::PublicKeyHash,
                        network_id: BitcoinNetworkType::Mainnet,
                        bytes: Hash160([2; 20]),
                    }),
                },
            ],
        });

        let mut burnchain = Burnchain::regtest("nope");
        burnchain.pox_constants.prepare_length = 1;
        burnchain.pox_constants.anchor_threshold = 1;
        burnchain.pox_constants.sunset_start = 16843019;
        burnchain.pox_constants.sunset_end = 16843020;

        // 0 total burn
        match LeaderBlockCommitOp::parse_from_tx(
            &burnchain,
            16843019,
            &BurnchainHeaderHash([0; 32]),
            StacksEpochId::Epoch2_05,
            &tx,
        )
        .unwrap_err()
        {
            op_error::ParseError => {}
            _ => unreachable!(),
        };
    }

    #[test]
    fn test_parse() {
        let vtxindex = 1;
        let block_height = 0x71706363; // epoch number must be strictly smaller than block height
        let burn_header_hash = BurnchainHeaderHash::from_hex(
            "0000000000000000000000000000000000000000000000000000000000000000",
        )
        .unwrap();

        let tx_fixtures = vec![
            OpFixture {
                // valid
                txstr: "01000000011111111111111111111111111111111111111111111111111111111111111111000000006b483045022100eba8c0a57c1eb71cdfba0874de63cf37b3aace1e56dcbd61701548194a79af34022041dd191256f3f8a45562e5d60956bb871421ba69db605716250554b23b08277b012102d8015134d9db8178ac93acbc43170a2f20febba5087a5b0437058765ad5133d000000000040000000000000000536a4c5069645b22222222222222222222222222222222222222222222222222222222222222223333333333333333333333333333333333333333333333333333333333333333404142435051606162637071fa39300000000000001976a914000000000000000000000000000000000000000088ac39300000000000001976a914000000000000000000000000000000000000000088aca05b0000000000001976a9140be3e286a15ea85882761618e366586b5574100d88ac00000000".into(),
                opstr: "69645b22222222222222222222222222222222222222222222222222222222222222223333333333333333333333333333333333333333333333333333333333333333404142435051606162637071fa".to_string(),
                result: Some(LeaderBlockCommitOp {
                    sunset_burn: 0,
                    block_header_hash: BlockHeaderHash::from_bytes(&hex_bytes("2222222222222222222222222222222222222222222222222222222222222222").unwrap()).unwrap(),
                    new_seed: VRFSeed::from_bytes(&hex_bytes("3333333333333333333333333333333333333333333333333333333333333333").unwrap()).unwrap(),
                    parent_block_ptr: 0x40414243,
                    parent_vtxindex: 0x5051,
                    key_block_ptr: 0x60616263,
                    key_vtxindex: 0x7071,
                    memo: vec![0x1f],

                    commit_outs: vec![
                        PoxAddress::Standard( StacksAddress { version: 26, bytes: Hash160::empty() }, None ),
                        PoxAddress::Standard( StacksAddress { version: 26, bytes: Hash160::empty() }, None ),
                    ],

                    burn_fee: 24690,
                    input: (Txid([0x11; 32]), 0),
                    apparent_sender: BurnchainSigner("mgbpit8FvkVJ9kuXY8QSM5P7eibnhcEMBk".to_string()),

                    txid: Txid::from_hex("502f3e5756de7e1bdba8c713cd2daab44adb5337d14ff668fdc57cc27d67f0d4").unwrap(),
                    vtxindex,
                    block_height,
                    burn_parent_modulus: ((block_height - 1) % BURN_BLOCK_MINED_AT_MODULUS) as u8,
                    burn_header_hash,
                    treatment: vec![],                })
            },
            OpFixture {
                // invalid -- wrong opcode
                txstr: "01000000011111111111111111111111111111111111111111111111111111111111111111000000006946304302207129fa2054a61cdb4b7db0b8fab6e8ff4af0edf979627aa5cf41665b7475a451021f70032b48837df091223c1d0bb57fb0298818eb11d0c966acff4b82f4b2d5c8012102d8015134d9db8178ac93acbc43170a2f20febba5087a5b0437058765ad5133d000000000030000000000000000536a4c5069645c222222222222222222222222222222222222222222222222222222222222222233333333333333333333333333333333333333333333333333333333333333334041424350516061626370718039300000000000001976a914000000000000000000000000000000000000000088aca05b0000000000001976a9140be3e286a15ea85882761618e366586b5574100d88ac00000000".to_string(),
                opstr: "".to_string(),
                result: None,
            },
            OpFixture {
                // invalid -- wrong burn address
                txstr: "01000000011111111111111111111111111111111111111111111111111111111111111111000000006b483045022100e25f5f9f660339cd665caba231d5bdfc3f0885bcc0b3f85dc35564058c9089d702206aa142ea6ccd89e56fdc0743cdcf3a2744e133f335e255e9370e4f8a6d0f6ffd012102d8015134d9db8178ac93acbc43170a2f20febba5087a5b0437058765ad5133d000000000030000000000000000536a4c5069645b222222222222222222222222222222222222222222222222222222222222222233333333333333333333333333333333333333333333333333333333333333334041424350516061626370718039300000000000001976a914000000000000000000000000000000000000000188aca05b0000000000001976a9140be3e286a15ea85882761618e366586b5574100d88ac00000000".to_string(),
                opstr: "".to_string(),
                result: None,
            },
            OpFixture {
                // invalid -- bad OP_RETURN (missing memo)
                txstr: "01000000011111111111111111111111111111111111111111111111111111111111111111000000006b483045022100c6c3ccc9b5a6ba5161706f3a5e4518bc3964e8de1cf31dbfa4d38082535c88e902205860de620cfe68a72d5a1fc3be1171e6fd8b2cdde0170f76724faca0db5ee0b6012102d8015134d9db8178ac93acbc43170a2f20febba5087a5b0437058765ad5133d000000000030000000000000000526a4c4f69645b2222222222222222222222222222222222222222222222222222222222222222333333333333333333333333333333333333333333333333333333333333333340414243505160616263707139300000000000001976a914000000000000000000000000000000000000000088aca05b0000000000001976a9140be3e286a15ea85882761618e366586b5574100d88ac00000000".to_string(),
                opstr: "".to_string(),
                result: None,
            }
        ];

        let parser = BitcoinBlockParser::new(BitcoinNetworkType::Testnet, BLOCKSTACK_MAGIC_MAINNET);

        let mut is_first = false;
        for tx_fixture in tx_fixtures {
            let mut tx = make_tx(&tx_fixture.txstr).unwrap();
            if is_first {
                eprintln!("TX outputs: {}", tx.output.len());
                tx.output.insert(
                    2,
                    stacks_address_to_bitcoin_tx_out(&StacksAddress::burn_address(false), 12345),
                );
                is_first = false;
                eprintln!("Updated txstr = {}", serialize_hex(&tx).unwrap());
                assert!(false);
            }

            let header = match tx_fixture.result {
                Some(ref op) => BurnchainBlockHeader {
                    block_height: op.block_height,
                    block_hash: op.burn_header_hash.clone(),
                    parent_block_hash: op.burn_header_hash.clone(),
                    num_txs: 1,
                    timestamp: get_epoch_time_secs(),
                },
                None => BurnchainBlockHeader {
                    block_height: 0,
                    block_hash: BurnchainHeaderHash::zero(),
                    parent_block_hash: BurnchainHeaderHash::zero(),
                    num_txs: 0,
                    timestamp: get_epoch_time_secs(),
                },
            };
            let burnchain_tx = BurnchainTransaction::Bitcoin(
                parser
                    .parse_tx(&tx, vtxindex as usize, StacksEpochId::Epoch2_05)
                    .unwrap(),
            );

            let mut burnchain = Burnchain::regtest("nope");
            burnchain.pox_constants.prepare_length = 1;
            burnchain.pox_constants.anchor_threshold = 1;
            burnchain.pox_constants.sunset_start = block_height;
            burnchain.pox_constants.sunset_end = block_height + 1;

            let op = LeaderBlockCommitOp::from_tx(
                &burnchain,
                &header,
                StacksEpochId::Epoch2_05,
                &burnchain_tx,
            );

            match (op, tx_fixture.result) {
                (Ok(parsed_tx), Some(result)) => {
                    let opstr = {
                        let mut buffer = vec![];
                        let mut magic_bytes = BLOCKSTACK_MAGIC_MAINNET.as_bytes().to_vec();
                        buffer.append(&mut magic_bytes);
                        parsed_tx
                            .consensus_serialize(&mut buffer)
                            .expect("FATAL: invalid operation");
                        to_hex(&buffer)
                    };

                    assert_eq!(tx_fixture.opstr, opstr);
                    assert_eq!(parsed_tx, result);
                }
                (Err(_e), None) => (),
                (Ok(_parsed_tx), None) => {
                    eprintln!("Parsed a tx when we should not have");
                    assert!(false);
                }
                (Err(_e), Some(_result)) => {
                    eprintln!("Did not parse a tx when we should have");
                    assert!(false);
                }
            }
        }
    }

    fn pox_constants() -> PoxConstants {
        PoxConstants::new(
            6,
            2,
            2,
            25,
            5,
            5000,
            10000,
            u32::MAX,
            u32::MAX,
            u32::MAX,
            u32::MAX,
        )
    }

    #[test]
    fn test_check_2_1() {
        let first_block_height = 121;
        let first_burn_hash = BurnchainHeaderHash::from_hex(
            "0000000000000000000000000000000000000000000000000000000000000123",
        )
        .unwrap();

        let block_122_hash = BurnchainHeaderHash::from_hex(
            "0000000000000000000000000000000000000000000000000000000000001220",
        )
        .unwrap();
        let block_123_hash = BurnchainHeaderHash::from_hex(
            "0000000000000000000000000000000000000000000000000000000000001230",
        )
        .unwrap();
        let block_124_hash = BurnchainHeaderHash::from_hex(
            "0000000000000000000000000000000000000000000000000000000000001240",
        )
        .unwrap();
        let block_125_hash = BurnchainHeaderHash::from_hex(
            "0000000000000000000000000000000000000000000000000000000000001250",
        )
        .unwrap();
        let block_126_hash = BurnchainHeaderHash::from_hex(
            "0000000000000000000000000000000000000000000000000000000000001260",
        )
        .unwrap();

        let block_header_hashes = [
            block_122_hash.clone(),
            block_123_hash.clone(),
            block_124_hash.clone(),
            block_125_hash.clone(), // prepare phase
            block_126_hash.clone(), // prepare phase
        ];

        let burnchain = Burnchain {
            pox_constants: pox_constants(),
            peer_version: 0x012345678,
            network_id: 0x9abcdef0,
            chain_name: "bitcoin".to_string(),
            network_name: "testnet".to_string(),
            working_dir: "/nope".to_string(),
            consensus_hash_lifetime: 24,
            stable_confirmations: 7,
            first_block_height,
            initial_reward_start_block: first_block_height,
            first_block_timestamp: 0,
            first_block_hash: first_burn_hash.clone(),
        };

        let leader_key_1 = LeaderKeyRegisterOp {
            consensus_hash: ConsensusHash::from_bytes(
                &hex_bytes("2222222222222222222222222222222222222222").unwrap(),
            )
            .unwrap(),
            public_key: VRFPublicKey::from_bytes(
                &hex_bytes("a366b51292bef4edd64063d9145c617fec373bceb0758e98cd72becd84d54c7a")
                    .unwrap(),
            )
            .unwrap(),
            memo: vec![1, 2, 3, 4, 5],

            txid: Txid::from_bytes_be(
                &hex_bytes("1bfa831b5fc56c858198acb8e77e5863c1e9d8ac26d49ddb914e24d8d4083562")
                    .unwrap(),
            )
            .unwrap(),
            vtxindex: 456,
            block_height: 124,
            burn_header_hash: block_124_hash.clone(),
        };

        let leader_key_2 = LeaderKeyRegisterOp {
            consensus_hash: ConsensusHash::from_bytes(
                &hex_bytes("3333333333333333333333333333333333333333").unwrap(),
            )
            .unwrap(),
            public_key: VRFPublicKey::from_bytes(
                &hex_bytes("bb519494643f79f1dea0350e6fb9a1da88dfdb6137117fc2523824a8aa44fe1c")
                    .unwrap(),
            )
            .unwrap(),
            memo: vec![1, 2, 3, 4, 5],

            txid: Txid::from_bytes_be(
                &hex_bytes("9410df84e2b440055c33acb075a0687752df63fe8fe84aeec61abe469f0448c7")
                    .unwrap(),
            )
            .unwrap(),
            vtxindex: 457,
            block_height: 124,
            burn_header_hash: block_124_hash.clone(),
        };

        // consumes leader_key_1
        let block_commit_1 = LeaderBlockCommitOp {
            sunset_burn: 0,
            block_header_hash: BlockHeaderHash::from_bytes(
                &hex_bytes("2222222222222222222222222222222222222222222222222222222222222222")
                    .unwrap(),
            )
            .unwrap(),
            new_seed: VRFSeed::from_bytes(
                &hex_bytes("3333333333333333333333333333333333333333333333333333333333333333")
                    .unwrap(),
            )
            .unwrap(),
            parent_block_ptr: 0,
            parent_vtxindex: 0,
            key_block_ptr: 124,
            key_vtxindex: 456,
            memo: vec![0x80],
            commit_outs: vec![],

            burn_fee: 12345,
            treatment: vec![],
            input: (Txid([0; 32]), 0),
            apparent_sender: BurnchainSigner::mock_parts(
                AddressHashMode::SerializeP2PKH,
                1,
                vec![StacksPublicKey::from_hex(
                    "02d8015134d9db8178ac93acbc43170a2f20febba5087a5b0437058765ad5133d0",
                )
                .unwrap()],
            ),

            txid: Txid::from_bytes_be(
                &hex_bytes("3c07a0a93360bc85047bbaadd49e30c8af770f73a37e10fec400174d2e5f27cf")
                    .unwrap(),
            )
            .unwrap(),
            vtxindex: 444,
            block_height: 125,
            burn_parent_modulus: (124 % BURN_BLOCK_MINED_AT_MODULUS) as u8,
            burn_header_hash: block_125_hash.clone(),
        };

        let mut db = SortitionDB::connect_test_with_epochs(
            first_block_height,
            &first_burn_hash,
            StacksEpoch::all(0, 0, first_block_height),
        )
        .unwrap();
        let block_ops = [
            // 122
            vec![],
            // 123
            vec![],
            // 124
            vec![
                BlockstackOperationType::LeaderKeyRegister(leader_key_1.clone()),
                BlockstackOperationType::LeaderKeyRegister(leader_key_2.clone()),
            ],
            // 125
            vec![BlockstackOperationType::LeaderBlockCommit(
                block_commit_1.clone(),
            )],
            // 126
            vec![],
        ];

        let tip_index_root = {
            let mut prev_snapshot = SortitionDB::get_first_block_snapshot(db.conn()).unwrap();
            for i in 0..block_header_hashes.len() {
                let mut snapshot_row = BlockSnapshot {
                    accumulated_coinbase_ustx: 0,
                    pox_valid: true,
                    block_height: (i + 1 + first_block_height as usize) as u64,
                    burn_header_timestamp: get_epoch_time_secs(),
                    burn_header_hash: block_header_hashes[i].clone(),
                    sortition_id: SortitionId(block_header_hashes[i].0.clone()),
                    parent_sortition_id: prev_snapshot.sortition_id.clone(),
                    parent_burn_header_hash: prev_snapshot.burn_header_hash.clone(),
                    consensus_hash: ConsensusHash::from_bytes(&[
                        0,
                        0,
                        0,
                        0,
                        0,
                        0,
                        0,
                        0,
                        0,
                        0,
                        0,
                        0,
                        0,
                        0,
                        0,
                        0,
                        0,
                        0,
                        0,
                        (i + 1) as u8,
                    ])
                    .unwrap(),
                    ops_hash: OpsHash::from_bytes(&[
                        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                        0, 0, 0, 0, 0, 0, i as u8,
                    ])
                    .unwrap(),
                    total_burn: i as u64,
                    sortition: true,
                    sortition_hash: SortitionHash::initial(),
                    winning_block_txid: Txid::from_hex(
                        "0000000000000000000000000000000000000000000000000000000000000000",
                    )
                    .unwrap(),
                    winning_stacks_block_hash: BlockHeaderHash::from_hex(
                        "0000000000000000000000000000000000000000000000000000000000000000",
                    )
                    .unwrap(),
                    index_root: TrieHash::from_empty_data(),
                    num_sortitions: (i + 1) as u64,
                    stacks_block_accepted: false,
                    stacks_block_height: 0,
                    arrival_index: 0,
                    canonical_stacks_tip_height: 0,
                    canonical_stacks_tip_hash: BlockHeaderHash([0u8; 32]),
                    canonical_stacks_tip_consensus_hash: ConsensusHash([0u8; 20]),
                    miner_pk_hash: None,
                };
                let mut tx =
                    SortitionHandleTx::begin(&mut db, &prev_snapshot.sortition_id).unwrap();
                let next_index_root = tx
                    .append_chain_tip_snapshot(
                        &prev_snapshot,
                        &snapshot_row,
                        &block_ops[i],
                        &[],
                        None,
                        None,
                        None,
                    )
                    .unwrap();

                snapshot_row.index_root = next_index_root;
                tx.commit().unwrap();

                prev_snapshot = snapshot_row;
            }

            prev_snapshot.index_root.clone()
        };

        let mut fixtures = vec![
            CheckFixture {
                // accept -- consumes leader_key_2
                op: LeaderBlockCommitOp {
                    sunset_burn: 0,
                    treatment: vec![],
                    block_header_hash: BlockHeaderHash::from_bytes(
                        &hex_bytes(
                            "2222222222222222222222222222222222222222222222222222222222222222",
                        )
                        .unwrap(),
                    )
                    .unwrap(),
                    new_seed: VRFSeed::from_bytes(
                        &hex_bytes(
                            "3333333333333333333333333333333333333333333333333333333333333333",
                        )
                        .unwrap(),
                    )
                    .unwrap(),
                    parent_block_ptr: 125,
                    parent_vtxindex: 444,
                    key_block_ptr: 124,
                    key_vtxindex: 457,
                    memo: vec![STACKS_EPOCH_2_1_MARKER],
                    commit_outs: vec![],

                    burn_fee: 12345,
                    input: (Txid([0; 32]), 0),
                    apparent_sender: BurnchainSigner::mock_parts(
                        AddressHashMode::SerializeP2PKH,
                        1,
                        vec![StacksPublicKey::from_hex(
                            "02d8015134d9db8178ac93acbc43170a2f20febba5087a5b0437058765ad5133d0",
                        )
                        .unwrap()],
                    ),

                    txid: Txid::from_bytes_be(
                        &hex_bytes(
                            "3c07a0a93360bc85047bbaadd49e30c8af770f73a37e10fec400174d2e5f27cf",
                        )
                        .unwrap(),
                    )
                    .unwrap(),
                    vtxindex: 445,
                    block_height: 126,
                    burn_parent_modulus: (125 % BURN_BLOCK_MINED_AT_MODULUS) as u8,
                    burn_header_hash: block_126_hash.clone(),
                },
                res: Ok(()),
            },
            CheckFixture {
                // accept -- builds directly off of genesis block and consumes leader_key_2
                op: LeaderBlockCommitOp {
                    treatment: vec![],
                    sunset_burn: 0,
                    block_header_hash: BlockHeaderHash::from_bytes(
                        &hex_bytes(
                            "2222222222222222222222222222222222222222222222222222222222222222",
                        )
                        .unwrap(),
                    )
                    .unwrap(),
                    new_seed: VRFSeed::from_bytes(
                        &hex_bytes(
                            "3333333333333333333333333333333333333333333333333333333333333333",
                        )
                        .unwrap(),
                    )
                    .unwrap(),
                    parent_block_ptr: 0,
                    parent_vtxindex: 0,
                    key_block_ptr: 124,
                    key_vtxindex: 457,
                    memo: vec![STACKS_EPOCH_2_1_MARKER],
                    commit_outs: vec![],

                    burn_fee: 12345,
                    input: (Txid([0; 32]), 0),
                    apparent_sender: BurnchainSigner::mock_parts(
                        AddressHashMode::SerializeP2PKH,
                        1,
                        vec![StacksPublicKey::from_hex(
                            "02d8015134d9db8178ac93acbc43170a2f20febba5087a5b0437058765ad5133d0",
                        )
                        .unwrap()],
                    ),

                    txid: Txid::from_bytes_be(
                        &hex_bytes(
                            "3c07a0a93360bc85047bbaadd49e30c8af770f73a37e10fec400174d2e5f27cf",
                        )
                        .unwrap(),
                    )
                    .unwrap(),
                    vtxindex: 445,
                    block_height: 126,
                    burn_parent_modulus: (125 % BURN_BLOCK_MINED_AT_MODULUS) as u8,
                    burn_header_hash: block_126_hash.clone(),
                },
                res: Ok(()),
            },
            CheckFixture {
                // accept -- also consumes leader_key_1
                op: LeaderBlockCommitOp {
                    treatment: vec![],
                    sunset_burn: 0,
                    block_header_hash: BlockHeaderHash::from_bytes(
                        &hex_bytes(
                            "2222222222222222222222222222222222222222222222222222222222222222",
                        )
                        .unwrap(),
                    )
                    .unwrap(),
                    new_seed: VRFSeed::from_bytes(
                        &hex_bytes(
                            "3333333333333333333333333333333333333333333333333333333333333333",
                        )
                        .unwrap(),
                    )
                    .unwrap(),
                    parent_block_ptr: 0,
                    parent_vtxindex: 0,
                    key_block_ptr: 124,
                    key_vtxindex: 456,
                    memo: vec![STACKS_EPOCH_2_1_MARKER],
                    commit_outs: vec![],

                    burn_fee: 12345,
                    input: (Txid([0; 32]), 0),
                    apparent_sender: BurnchainSigner::mock_parts(
                        AddressHashMode::SerializeP2PKH,
                        1,
                        vec![StacksPublicKey::from_hex(
                            "02d8015134d9db8178ac93acbc43170a2f20febba5087a5b0437058765ad5133d0",
                        )
                        .unwrap()],
                    ),

                    txid: Txid::from_bytes_be(
                        &hex_bytes(
                            "3c07a0a93360bc85047bbaadd49e30c8af770f73a37e10fec400174d2e5f27cf",
                        )
                        .unwrap(),
                    )
                    .unwrap(),
                    vtxindex: 444,
                    block_height: 126,
                    burn_parent_modulus: (125 % BURN_BLOCK_MINED_AT_MODULUS) as u8,
                    burn_header_hash: block_126_hash.clone(),
                },
                res: Ok(()),
            },
            CheckFixture {
                // reject -- bad burn parent modulus
                op: LeaderBlockCommitOp {
                    treatment: vec![],
                    sunset_burn: 0,
                    block_header_hash: BlockHeaderHash::from_bytes(
                        &hex_bytes(
                            "2222222222222222222222222222222222222222222222222222222222222222",
                        )
                        .unwrap(),
                    )
                    .unwrap(),
                    new_seed: VRFSeed::from_bytes(
                        &hex_bytes(
                            "3333333333333333333333333333333333333333333333333333333333333333",
                        )
                        .unwrap(),
                    )
                    .unwrap(),
                    parent_block_ptr: 0,
                    parent_vtxindex: 0,
                    key_block_ptr: 124,
                    key_vtxindex: 456,
                    memo: vec![0x80],
                    commit_outs: vec![],

                    burn_fee: 12345,
                    input: (Txid([0; 32]), 0),
                    apparent_sender: BurnchainSigner::mock_parts(
                        AddressHashMode::SerializeP2PKH,
                        1,
                        vec![StacksPublicKey::from_hex(
                            "02d8015134d9db8178ac93acbc43170a2f20febba5087a5b0437058765ad5133d0",
                        )
                        .unwrap()],
                    ),

                    txid: Txid::from_bytes_be(
                        &hex_bytes(
                            "3c07a0a93360bc85047bbaadd49e30c8af770f73a37e10fec400174d2e5f27cf",
                        )
                        .unwrap(),
                    )
                    .unwrap(),
                    vtxindex: 444,
                    block_height: 126,
                    burn_parent_modulus: (124 % BURN_BLOCK_MINED_AT_MODULUS) as u8,
                    burn_header_hash: block_126_hash.clone(),
                },
                res: Err(op_error::MissedBlockCommit(MissedBlockCommit {
                    input: (Txid([0; 32]), 0),
                    txid: Txid::from_bytes_be(
                        &hex_bytes(
                            "3c07a0a93360bc85047bbaadd49e30c8af770f73a37e10fec400174d2e5f27cf",
                        )
                        .unwrap(),
                    )
                    .unwrap(),
                    // miss distance from height 126 was 1, which corresponds to the hash at height
                    // 125 (intended modulus = ((124 % 5) + 1) % 5 = 0, actual = (126 % 5) = 1
                    intended_sortition: SortitionId(block_125_hash.0.clone()),
                })),
            },
            CheckFixture {
                // reject -- bad burn parent modulus
                op: LeaderBlockCommitOp {
                    treatment: vec![],
                    sunset_burn: 0,
                    block_header_hash: BlockHeaderHash::from_bytes(
                        &hex_bytes(
                            "2222222222222222222222222222222222222222222222222222222222222222",
                        )
                        .unwrap(),
                    )
                    .unwrap(),
                    new_seed: VRFSeed::from_bytes(
                        &hex_bytes(
                            "3333333333333333333333333333333333333333333333333333333333333333",
                        )
                        .unwrap(),
                    )
                    .unwrap(),
                    parent_block_ptr: 0,
                    parent_vtxindex: 0,
                    key_block_ptr: 124,
                    key_vtxindex: 456,
                    memo: vec![0x80],
                    commit_outs: vec![],

                    burn_fee: 12345,
                    input: (Txid([0; 32]), 0),
                    apparent_sender: BurnchainSigner::mock_parts(
                        AddressHashMode::SerializeP2PKH,
                        1,
                        vec![StacksPublicKey::from_hex(
                            "02d8015134d9db8178ac93acbc43170a2f20febba5087a5b0437058765ad5133d0",
                        )
                        .unwrap()],
                    ),

                    txid: Txid::from_bytes_be(
                        &hex_bytes(
                            "3c07a0a93360bc85047bbaadd49e30c8af770f73a37e10fec400174d2e5f27cf",
                        )
                        .unwrap(),
                    )
                    .unwrap(),
                    vtxindex: 444,
                    block_height: 124,
                    burn_parent_modulus: (125 % BURN_BLOCK_MINED_AT_MODULUS) as u8,
                    burn_header_hash: block_126_hash.clone(),
                },
                // miss distance from height 124 was 3, which corresponds to the hash at height
                // 121 (intended modulus = (((125 % 5) + 1) % 5) = 1, actual modulus = 124 % 5 = 4
                res: Err(op_error::BlockCommitMissDistanceTooBig),
            },
        ];

        for (ix, fixture) in fixtures.iter_mut().enumerate() {
            eprintln!("Processing {}", ix);
            let header = BurnchainBlockHeader {
                block_height: fixture.op.block_height,
                block_hash: fixture.op.burn_header_hash.clone(),
                parent_block_hash: fixture.op.burn_header_hash.clone(),
                num_txs: 1,
                timestamp: get_epoch_time_secs(),
            };
            let mut ic = SortitionHandleTx::begin(
                &mut db,
                &SortitionId::stubbed(&fixture.op.burn_header_hash),
            )
            .unwrap();
            assert_eq!(
                format!("{:?}", &fixture.res),
                format!("{:?}", &fixture.op.check(&burnchain, &mut ic, None))
            );
        }
    }

    #[test]
    fn test_check() {
        let first_block_height = 121;
        let first_burn_hash = BurnchainHeaderHash::from_hex(
            "0000000000000000000000000000000000000000000000000000000000000123",
        )
        .unwrap();

        let block_122_hash = BurnchainHeaderHash::from_hex(
            "0000000000000000000000000000000000000000000000000000000000001220",
        )
        .unwrap();
        let block_123_hash = BurnchainHeaderHash::from_hex(
            "0000000000000000000000000000000000000000000000000000000000001230",
        )
        .unwrap();
        let block_124_hash = BurnchainHeaderHash::from_hex(
            "0000000000000000000000000000000000000000000000000000000000001240",
        )
        .unwrap();
        let block_125_hash = BurnchainHeaderHash::from_hex(
            "0000000000000000000000000000000000000000000000000000000000001250",
        )
        .unwrap();
        let block_126_hash = BurnchainHeaderHash::from_hex(
            "0000000000000000000000000000000000000000000000000000000000001260",
        )
        .unwrap();

        let block_header_hashes = [
            block_122_hash.clone(),
            block_123_hash.clone(),
            block_124_hash.clone(),
            block_125_hash.clone(), // prepare phase
            block_126_hash.clone(), // prepare phase
        ];

        let burnchain = Burnchain {
            pox_constants: pox_constants(),
            peer_version: 0x012345678,
            network_id: 0x9abcdef0,
            chain_name: "bitcoin".to_string(),
            network_name: "testnet".to_string(),
            working_dir: "/nope".to_string(),
            consensus_hash_lifetime: 24,
            stable_confirmations: 7,
            first_block_height,
            initial_reward_start_block: first_block_height,
            first_block_timestamp: 0,
            first_block_hash: first_burn_hash.clone(),
        };

        let leader_key_1 = LeaderKeyRegisterOp {
            consensus_hash: ConsensusHash::from_bytes(
                &hex_bytes("2222222222222222222222222222222222222222").unwrap(),
            )
            .unwrap(),
            public_key: VRFPublicKey::from_bytes(
                &hex_bytes("a366b51292bef4edd64063d9145c617fec373bceb0758e98cd72becd84d54c7a")
                    .unwrap(),
            )
            .unwrap(),
            memo: vec![1, 2, 3, 4, 5],

            txid: Txid::from_bytes_be(
                &hex_bytes("1bfa831b5fc56c858198acb8e77e5863c1e9d8ac26d49ddb914e24d8d4083562")
                    .unwrap(),
            )
            .unwrap(),
            vtxindex: 456,
            block_height: 124,
            burn_header_hash: block_124_hash.clone(),
        };

        let leader_key_2 = LeaderKeyRegisterOp {
            consensus_hash: ConsensusHash::from_bytes(
                &hex_bytes("3333333333333333333333333333333333333333").unwrap(),
            )
            .unwrap(),
            public_key: VRFPublicKey::from_bytes(
                &hex_bytes("bb519494643f79f1dea0350e6fb9a1da88dfdb6137117fc2523824a8aa44fe1c")
                    .unwrap(),
            )
            .unwrap(),
            memo: vec![1, 2, 3, 4, 5],

            txid: Txid::from_bytes_be(
                &hex_bytes("9410df84e2b440055c33acb075a0687752df63fe8fe84aeec61abe469f0448c7")
                    .unwrap(),
            )
            .unwrap(),
            vtxindex: 457,
            block_height: 124,
            burn_header_hash: block_124_hash.clone(),
        };

        // consumes leader_key_1
        let block_commit_1 = LeaderBlockCommitOp {
            sunset_burn: 0,
            treatment: vec![],
            block_header_hash: BlockHeaderHash::from_bytes(
                &hex_bytes("2222222222222222222222222222222222222222222222222222222222222222")
                    .unwrap(),
            )
            .unwrap(),
            new_seed: VRFSeed::from_bytes(
                &hex_bytes("3333333333333333333333333333333333333333333333333333333333333333")
                    .unwrap(),
            )
            .unwrap(),
            parent_block_ptr: 0,
            parent_vtxindex: 0,
            key_block_ptr: 124,
            key_vtxindex: 456,
            memo: vec![0x80],
            commit_outs: vec![],

            burn_fee: 12345,
            input: (Txid([0; 32]), 0),
            apparent_sender: BurnchainSigner::mock_parts(
                AddressHashMode::SerializeP2PKH,
                1,
                vec![StacksPublicKey::from_hex(
                    "02d8015134d9db8178ac93acbc43170a2f20febba5087a5b0437058765ad5133d0",
                )
                .unwrap()],
            ),

            txid: Txid::from_bytes_be(
                &hex_bytes("3c07a0a93360bc85047bbaadd49e30c8af770f73a37e10fec400174d2e5f27cf")
                    .unwrap(),
            )
            .unwrap(),
            vtxindex: 444,
            block_height: 125,
            burn_parent_modulus: (124 % BURN_BLOCK_MINED_AT_MODULUS) as u8,
            burn_header_hash: block_125_hash.clone(),
        };

        let mut db = SortitionDB::connect_test(first_block_height, &first_burn_hash).unwrap();
        let block_ops = [
            // 122
            vec![],
            // 123
            vec![],
            // 124
            vec![
                BlockstackOperationType::LeaderKeyRegister(leader_key_1.clone()),
                BlockstackOperationType::LeaderKeyRegister(leader_key_2.clone()),
            ],
            // 125
            vec![BlockstackOperationType::LeaderBlockCommit(
                block_commit_1.clone(),
            )],
            // 126
            vec![],
        ];

        let tip_index_root = {
            let mut prev_snapshot = SortitionDB::get_first_block_snapshot(db.conn()).unwrap();
            for i in 0..block_header_hashes.len() {
                let mut snapshot_row = BlockSnapshot {
                    accumulated_coinbase_ustx: 0,
                    pox_valid: true,
                    block_height: (i + 1 + first_block_height as usize) as u64,
                    burn_header_timestamp: get_epoch_time_secs(),
                    burn_header_hash: block_header_hashes[i].clone(),
                    sortition_id: SortitionId(block_header_hashes[i].0.clone()),
                    parent_sortition_id: prev_snapshot.sortition_id.clone(),
                    parent_burn_header_hash: prev_snapshot.burn_header_hash.clone(),
                    consensus_hash: ConsensusHash::from_bytes(&[
                        0,
                        0,
                        0,
                        0,
                        0,
                        0,
                        0,
                        0,
                        0,
                        0,
                        0,
                        0,
                        0,
                        0,
                        0,
                        0,
                        0,
                        0,
                        0,
                        (i + 1) as u8,
                    ])
                    .unwrap(),
                    ops_hash: OpsHash::from_bytes(&[
                        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                        0, 0, 0, 0, 0, 0, i as u8,
                    ])
                    .unwrap(),
                    total_burn: i as u64,
                    sortition: true,
                    sortition_hash: SortitionHash::initial(),
                    winning_block_txid: Txid::from_hex(
                        "0000000000000000000000000000000000000000000000000000000000000000",
                    )
                    .unwrap(),
                    winning_stacks_block_hash: BlockHeaderHash::from_hex(
                        "0000000000000000000000000000000000000000000000000000000000000000",
                    )
                    .unwrap(),
                    index_root: TrieHash::from_empty_data(),
                    num_sortitions: (i + 1) as u64,
                    stacks_block_accepted: false,
                    stacks_block_height: 0,
                    arrival_index: 0,
                    canonical_stacks_tip_height: 0,
                    canonical_stacks_tip_hash: BlockHeaderHash([0u8; 32]),
                    canonical_stacks_tip_consensus_hash: ConsensusHash([0u8; 20]),
                    ..BlockSnapshot::initial(0, &first_burn_hash, 0)
                };
                let mut tx =
                    SortitionHandleTx::begin(&mut db, &prev_snapshot.sortition_id).unwrap();
                let next_index_root = tx
                    .append_chain_tip_snapshot(
                        &prev_snapshot,
                        &snapshot_row,
                        &block_ops[i],
                        &[],
                        None,
                        None,
                        None,
                    )
                    .unwrap();

                snapshot_row.index_root = next_index_root;
                tx.commit().unwrap();

                prev_snapshot = snapshot_row;
            }

            prev_snapshot.index_root.clone()
        };

        let block_height = 124;

        let mut fixtures = vec![
            CheckFixture {
                // reject -- predates start block
                op: LeaderBlockCommitOp {
                    treatment: vec![],
                    sunset_burn: 0,
                    block_header_hash: BlockHeaderHash::from_bytes(
                        &hex_bytes(
                            "2222222222222222222222222222222222222222222222222222222222222222",
                        )
                        .unwrap(),
                    )
                    .unwrap(),
                    new_seed: VRFSeed::from_bytes(
                        &hex_bytes(
                            "3333333333333333333333333333333333333333333333333333333333333333",
                        )
                        .unwrap(),
                    )
                    .unwrap(),
                    parent_block_ptr: 50,
                    parent_vtxindex: 456,
                    key_block_ptr: 1,
                    key_vtxindex: 457,
                    memo: vec![0x80],
                    commit_outs: vec![],

                    burn_fee: 12345,
                    input: (Txid([0; 32]), 0),
                    apparent_sender: BurnchainSigner::mock_parts(
                        AddressHashMode::SerializeP2PKH,
                        1,
                        vec![StacksPublicKey::from_hex(
                            "02d8015134d9db8178ac93acbc43170a2f20febba5087a5b0437058765ad5133d0",
                        )
                        .unwrap()],
                    ),

                    txid: Txid::from_bytes_be(
                        &hex_bytes(
                            "3c07a0a93360bc85047bbaadd49e30c8af770f73a37e10fec400174d2e5f27cf",
                        )
                        .unwrap(),
                    )
                    .unwrap(),
                    vtxindex: 444,
                    block_height: 80,
                    burn_parent_modulus: (79 % BURN_BLOCK_MINED_AT_MODULUS) as u8,
                    burn_header_hash: block_126_hash.clone(),
                },
                res: Err(op_error::BlockCommitPredatesGenesis),
            },
            CheckFixture {
                // reject -- no such leader key
                op: LeaderBlockCommitOp {
                    sunset_burn: 0,
                    treatment: vec![],
                    block_header_hash: BlockHeaderHash::from_bytes(
                        &hex_bytes(
                            "2222222222222222222222222222222222222222222222222222222222222222",
                        )
                        .unwrap(),
                    )
                    .unwrap(),
                    new_seed: VRFSeed::from_bytes(
                        &hex_bytes(
                            "3333333333333333333333333333333333333333333333333333333333333333",
                        )
                        .unwrap(),
                    )
                    .unwrap(),
                    parent_block_ptr: 1,
                    parent_vtxindex: 444,
                    key_block_ptr: 2,
                    key_vtxindex: 400,
                    memo: vec![0x80],
                    commit_outs: vec![],

                    burn_fee: 12345,
                    input: (Txid([0; 32]), 0),
                    apparent_sender: BurnchainSigner::mock_parts(
                        AddressHashMode::SerializeP2PKH,
                        1,
                        vec![StacksPublicKey::from_hex(
                            "02d8015134d9db8178ac93acbc43170a2f20febba5087a5b0437058765ad5133d0",
                        )
                        .unwrap()],
                    ),

                    txid: Txid::from_bytes_be(
                        &hex_bytes(
                            "3c07a0a93360bc85047bbaadd49e30c8af770f73a37e10fec400174d2e5f27cf",
                        )
                        .unwrap(),
                    )
                    .unwrap(),
                    vtxindex: 444,
                    block_height: 126,
                    burn_parent_modulus: (125 % BURN_BLOCK_MINED_AT_MODULUS) as u8,
                    burn_header_hash: block_126_hash.clone(),
                },
                res: Err(op_error::BlockCommitNoLeaderKey),
            },
            CheckFixture {
                // reject -- previous block must exist
                op: LeaderBlockCommitOp {
                    treatment: vec![],
                    sunset_burn: 0,
                    block_header_hash: BlockHeaderHash::from_bytes(
                        &hex_bytes(
                            "2222222222222222222222222222222222222222222222222222222222222222",
                        )
                        .unwrap(),
                    )
                    .unwrap(),
                    new_seed: VRFSeed::from_bytes(
                        &hex_bytes(
                            "3333333333333333333333333333333333333333333333333333333333333333",
                        )
                        .unwrap(),
                    )
                    .unwrap(),
                    parent_block_ptr: 125,
                    parent_vtxindex: 445,
                    key_block_ptr: 124,
                    key_vtxindex: 457,
                    commit_outs: vec![],
                    memo: vec![0x80],

                    burn_fee: 12345,
                    input: (Txid([0; 32]), 0),
                    apparent_sender: BurnchainSigner::mock_parts(
                        AddressHashMode::SerializeP2PKH,
                        1,
                        vec![StacksPublicKey::from_hex(
                            "02d8015134d9db8178ac93acbc43170a2f20febba5087a5b0437058765ad5133d0",
                        )
                        .unwrap()],
                    ),

                    txid: Txid::from_bytes_be(
                        &hex_bytes(
                            "3c07a0a93360bc85047bbaadd49e30c8af770f73a37e10fec400174d2e5f27cf",
                        )
                        .unwrap(),
                    )
                    .unwrap(),
                    vtxindex: 445,
                    block_height: 126,
                    burn_parent_modulus: (125 % BURN_BLOCK_MINED_AT_MODULUS) as u8,
                    burn_header_hash: block_126_hash.clone(),
                },
                res: Err(op_error::BlockCommitNoParent),
            },
            CheckFixture {
                // reject -- previous block must exist in a different block
                op: LeaderBlockCommitOp {
                    treatment: vec![],
                    sunset_burn: 0,
                    block_header_hash: BlockHeaderHash::from_bytes(
                        &hex_bytes(
                            "2222222222222222222222222222222222222222222222222222222222222222",
                        )
                        .unwrap(),
                    )
                    .unwrap(),
                    new_seed: VRFSeed::from_bytes(
                        &hex_bytes(
                            "3333333333333333333333333333333333333333333333333333333333333333",
                        )
                        .unwrap(),
                    )
                    .unwrap(),
                    parent_block_ptr: 126,
                    parent_vtxindex: 444,
                    key_block_ptr: 124,
                    key_vtxindex: 457,
                    memo: vec![0x80],
                    commit_outs: vec![],

                    burn_fee: 12345,
                    input: (Txid([0; 32]), 0),
                    apparent_sender: BurnchainSigner::mock_parts(
                        AddressHashMode::SerializeP2PKH,
                        1,
                        vec![StacksPublicKey::from_hex(
                            "02d8015134d9db8178ac93acbc43170a2f20febba5087a5b0437058765ad5133d0",
                        )
                        .unwrap()],
                    ),

                    txid: Txid::from_bytes_be(
                        &hex_bytes(
                            "3c07a0a93360bc85047bbaadd49e30c8af770f73a37e10fec400174d2e5f27cf",
                        )
                        .unwrap(),
                    )
                    .unwrap(),
                    vtxindex: 445,
                    block_height: 126,
                    burn_parent_modulus: (125 % BURN_BLOCK_MINED_AT_MODULUS) as u8,
                    burn_header_hash: block_126_hash.clone(),
                },
                res: Err(op_error::BlockCommitNoParent),
            },
            CheckFixture {
                // accept -- we can have a different burnchain signer (but whether or not it links
                // to another block-commit's UTXO chain is a different story, and is not checked
                // here)
                op: LeaderBlockCommitOp {
                    sunset_burn: 0,
                    treatment: vec![],
                    block_header_hash: BlockHeaderHash::from_bytes(
                        &hex_bytes(
                            "2222222222222222222222222222222222222222222222222222222222222222",
                        )
                        .unwrap(),
                    )
                    .unwrap(),
                    new_seed: VRFSeed::from_bytes(
                        &hex_bytes(
                            "3333333333333333333333333333333333333333333333333333333333333333",
                        )
                        .unwrap(),
                    )
                    .unwrap(),
                    parent_block_ptr: 125,
                    parent_vtxindex: 444,
                    key_block_ptr: 124,
                    key_vtxindex: 457,
                    memo: vec![0x80],
                    commit_outs: vec![],

                    burn_fee: 12345,
                    input: (Txid([0; 32]), 0),
                    apparent_sender: BurnchainSigner::mock_parts(
                        AddressHashMode::SerializeP2PKH,
                        1,
                        vec![StacksPublicKey::from_hex(
                            "03984286096373539ae529bd997c92792d4e5b5967be72979a42f587a625394116",
                        )
                        .unwrap()],
                    ),

                    txid: Txid::from_bytes_be(
                        &hex_bytes(
                            "3c07a0a93360bc85047bbaadd49e30c8af770f73a37e10fec400174d2e5f27cf",
                        )
                        .unwrap(),
                    )
                    .unwrap(),
                    vtxindex: 445,
                    block_height: 126,
                    burn_parent_modulus: (125 % BURN_BLOCK_MINED_AT_MODULUS) as u8,
                    burn_header_hash: block_126_hash.clone(),
                },
                res: Ok(()),
            },
            CheckFixture {
                // reject -- fee is 0
                op: LeaderBlockCommitOp {
                    treatment: vec![],
                    sunset_burn: 0,
                    block_header_hash: BlockHeaderHash::from_bytes(
                        &hex_bytes(
                            "2222222222222222222222222222222222222222222222222222222222222222",
                        )
                        .unwrap(),
                    )
                    .unwrap(),
                    new_seed: VRFSeed::from_bytes(
                        &hex_bytes(
                            "3333333333333333333333333333333333333333333333333333333333333333",
                        )
                        .unwrap(),
                    )
                    .unwrap(),
                    parent_block_ptr: 125,
                    parent_vtxindex: 444,
                    key_block_ptr: 124,
                    key_vtxindex: 457,
                    memo: vec![0x80],
                    commit_outs: vec![],

                    burn_fee: 0,
                    input: (Txid([0; 32]), 0),
                    apparent_sender: BurnchainSigner::mock_parts(
                        AddressHashMode::SerializeP2PKH,
                        1,
                        vec![StacksPublicKey::from_hex(
                            "02d8015134d9db8178ac93acbc43170a2f20febba5087a5b0437058765ad5133d0",
                        )
                        .unwrap()],
                    ),

                    txid: Txid::from_bytes_be(
                        &hex_bytes(
                            "3c07a0a93360bc85047bbaadd49e30c8af770f73a37e10fec400174d2e5f27cf",
                        )
                        .unwrap(),
                    )
                    .unwrap(),
                    vtxindex: 445,
                    block_height: 126,
                    burn_parent_modulus: (125 % BURN_BLOCK_MINED_AT_MODULUS) as u8,
                    burn_header_hash: block_126_hash.clone(),
                },
                res: Err(op_error::BlockCommitBadInput),
            },
            CheckFixture {
                // accept -- consumes leader_key_2
                op: LeaderBlockCommitOp {
                    treatment: vec![],
                    sunset_burn: 0,
                    block_header_hash: BlockHeaderHash::from_bytes(
                        &hex_bytes(
                            "2222222222222222222222222222222222222222222222222222222222222222",
                        )
                        .unwrap(),
                    )
                    .unwrap(),
                    new_seed: VRFSeed::from_bytes(
                        &hex_bytes(
                            "3333333333333333333333333333333333333333333333333333333333333333",
                        )
                        .unwrap(),
                    )
                    .unwrap(),
                    parent_block_ptr: 125,
                    parent_vtxindex: 444,
                    key_block_ptr: 124,
                    key_vtxindex: 457,
                    memo: vec![0x80],
                    commit_outs: vec![],

                    burn_fee: 12345,
                    input: (Txid([0; 32]), 0),
                    apparent_sender: BurnchainSigner::mock_parts(
                        AddressHashMode::SerializeP2PKH,
                        1,
                        vec![StacksPublicKey::from_hex(
                            "02d8015134d9db8178ac93acbc43170a2f20febba5087a5b0437058765ad5133d0",
                        )
                        .unwrap()],
                    ),

                    txid: Txid::from_bytes_be(
                        &hex_bytes(
                            "3c07a0a93360bc85047bbaadd49e30c8af770f73a37e10fec400174d2e5f27cf",
                        )
                        .unwrap(),
                    )
                    .unwrap(),
                    vtxindex: 445,
                    block_height: 126,
                    burn_parent_modulus: (125 % BURN_BLOCK_MINED_AT_MODULUS) as u8,
                    burn_header_hash: block_126_hash.clone(),
                },
                res: Ok(()),
            },
            CheckFixture {
                // accept -- builds directly off of genesis block and consumes leader_key_2
                op: LeaderBlockCommitOp {
                    treatment: vec![],
                    sunset_burn: 0,
                    block_header_hash: BlockHeaderHash::from_bytes(
                        &hex_bytes(
                            "2222222222222222222222222222222222222222222222222222222222222222",
                        )
                        .unwrap(),
                    )
                    .unwrap(),
                    new_seed: VRFSeed::from_bytes(
                        &hex_bytes(
                            "3333333333333333333333333333333333333333333333333333333333333333",
                        )
                        .unwrap(),
                    )
                    .unwrap(),
                    parent_block_ptr: 0,
                    parent_vtxindex: 0,
                    key_block_ptr: 124,
                    key_vtxindex: 457,
                    memo: vec![0x80],
                    commit_outs: vec![],

                    burn_fee: 12345,
                    input: (Txid([0; 32]), 0),
                    apparent_sender: BurnchainSigner::mock_parts(
                        AddressHashMode::SerializeP2PKH,
                        1,
                        vec![StacksPublicKey::from_hex(
                            "02d8015134d9db8178ac93acbc43170a2f20febba5087a5b0437058765ad5133d0",
                        )
                        .unwrap()],
                    ),

                    txid: Txid::from_bytes_be(
                        &hex_bytes(
                            "3c07a0a93360bc85047bbaadd49e30c8af770f73a37e10fec400174d2e5f27cf",
                        )
                        .unwrap(),
                    )
                    .unwrap(),
                    vtxindex: 445,
                    block_height: 126,
                    burn_parent_modulus: (125 % BURN_BLOCK_MINED_AT_MODULUS) as u8,
                    burn_header_hash: block_126_hash.clone(),
                },
                res: Ok(()),
            },
            CheckFixture {
                // accept -- also consumes leader_key_1
                op: LeaderBlockCommitOp {
                    treatment: vec![],
                    sunset_burn: 0,
                    block_header_hash: BlockHeaderHash::from_bytes(
                        &hex_bytes(
                            "2222222222222222222222222222222222222222222222222222222222222222",
                        )
                        .unwrap(),
                    )
                    .unwrap(),
                    new_seed: VRFSeed::from_bytes(
                        &hex_bytes(
                            "3333333333333333333333333333333333333333333333333333333333333333",
                        )
                        .unwrap(),
                    )
                    .unwrap(),
                    parent_block_ptr: 0,
                    parent_vtxindex: 0,
                    key_block_ptr: 124,
                    key_vtxindex: 456,
                    memo: vec![0x80],
                    commit_outs: vec![],

                    burn_fee: 12345,
                    input: (Txid([0; 32]), 0),
                    apparent_sender: BurnchainSigner::mock_parts(
                        AddressHashMode::SerializeP2PKH,
                        1,
                        vec![StacksPublicKey::from_hex(
                            "02d8015134d9db8178ac93acbc43170a2f20febba5087a5b0437058765ad5133d0",
                        )
                        .unwrap()],
                    ),

                    txid: Txid::from_bytes_be(
                        &hex_bytes(
                            "3c07a0a93360bc85047bbaadd49e30c8af770f73a37e10fec400174d2e5f27cf",
                        )
                        .unwrap(),
                    )
                    .unwrap(),
                    vtxindex: 444,
                    block_height: 126,
                    burn_parent_modulus: (125 % BURN_BLOCK_MINED_AT_MODULUS) as u8,
                    burn_header_hash: block_126_hash.clone(),
                },
                res: Ok(()),
            },
        ];

        for (ix, fixture) in fixtures.iter_mut().enumerate() {
            eprintln!("Processing {}", ix);
            let header = BurnchainBlockHeader {
                block_height: fixture.op.block_height,
                block_hash: fixture.op.burn_header_hash.clone(),
                parent_block_hash: fixture.op.burn_header_hash.clone(),
                num_txs: 1,
                timestamp: get_epoch_time_secs(),
            };
            let mut ic = SortitionHandleTx::begin(
                &mut db,
                &SortitionId::stubbed(&fixture.op.burn_header_hash),
            )
            .unwrap();
            assert_eq!(
                format!("{:?}", &fixture.res),
                format!("{:?}", &fixture.op.check(&burnchain, &mut ic, None))
            );
        }
    }

    pub enum DescendencyStubbedSortitionHandle {
        Descended,
        NotDescended,
    }

    impl SortitionHandle for DescendencyStubbedSortitionHandle {
        fn sqlite(&self) -> &Connection {
            panic!("Cannot evaluate");
        }

        fn get_block_snapshot_by_height(
            &mut self,
            _block_height: u64,
        ) -> Result<Option<BlockSnapshot>, db_error> {
            panic!("Cannot evaluate");
        }

        fn first_burn_block_height(&self) -> u64 {
            panic!("Cannot evaluate");
        }

        fn pox_constants(&self) -> &PoxConstants {
            panic!("Cannot evaluate");
        }

        fn tip(&self) -> SortitionId {
            panic!("Cannot evaluate");
        }

        fn get_nakamoto_tip(
            &self,
        ) -> Result<Option<(ConsensusHash, BlockHeaderHash, u64)>, db_error> {
            panic!("Cannot evaluate");
        }

        fn descended_from(
            &mut self,
            _block_at_burn_height: u64,
            _potential_ancestor: &BlockHeaderHash,
        ) -> Result<bool, db_error> {
            match self {
                DescendencyStubbedSortitionHandle::Descended => Ok(true),
                DescendencyStubbedSortitionHandle::NotDescended => Ok(false),
            }
        }
    }

    #[test]
    fn pox_reward_punish() {
        let burnchain = Burnchain {
            pox_constants: pox_constants(),
            peer_version: 0x012345678,
            network_id: 0x9abcdef0,
            chain_name: "bitcoin".to_string(),
            network_name: "testnet".to_string(),
            working_dir: "/nope".to_string(),
            consensus_hash_lifetime: 24,
            stable_confirmations: 7,
            initial_reward_start_block: 0,
            first_block_height: 0,
            first_block_timestamp: 0,
            first_block_hash: BurnchainHeaderHash([0x05; 32]),
        };

        let default_block_commit = LeaderBlockCommitOp {
            treatment: vec![],
            sunset_burn: 0,
            block_header_hash: BlockHeaderHash([0x22; 32]),
            new_seed: VRFSeed([0x33; 32]),
            parent_block_ptr: 125,
            parent_vtxindex: 0,
            key_block_ptr: 124,
            key_vtxindex: 456,
            memo: vec![0x80],
            commit_outs: vec![],

            burn_fee: 12345,
            input: (Txid([0; 32]), 0),
            apparent_sender: BurnchainSigner::mock_parts(
                AddressHashMode::SerializeP2PKH,
                1,
                vec![StacksPublicKey::from_hex(
                    "02d8015134d9db8178ac93acbc43170a2f20febba5087a5b0437058765ad5133d0",
                )
                .unwrap()],
            ),

            txid: Txid([0xab; 32]),
            vtxindex: 444,
            block_height: 128,
            burn_parent_modulus: (128 % BURN_BLOCK_MINED_AT_MODULUS) as u8,
            burn_header_hash: BurnchainHeaderHash([0x11; 32]),
        };

        let anchor_block_hash = BlockHeaderHash([0xaa; 32]);

        fn reward_addrs(i: usize) -> PoxAddress {
            let addr = StacksAddress::new(1, Hash160::from_data(&i.to_be_bytes()));
            PoxAddress::Standard(addr, None)
        }
        let burn_addr_0 = PoxAddress::Standard(StacksAddress::burn_address(false), None);
        let burn_addr_1 = PoxAddress::Standard(StacksAddress::burn_address(true), None);
        let rs_pox_addrs = RewardSetInfo {
            anchor_block: anchor_block_hash.clone(),
            recipients: vec![(reward_addrs(0), 0), (reward_addrs(1), 1)],
            allow_nakamoto_punishment: true,
        };
        let rs_pox_addrs_0b = RewardSetInfo {
            anchor_block: anchor_block_hash.clone(),
            recipients: vec![(reward_addrs(0), 0), (burn_addr_0.clone(), 5)],
            allow_nakamoto_punishment: true,
        };
        let rs_pox_addrs_1b = RewardSetInfo {
            anchor_block: anchor_block_hash.clone(),
            recipients: vec![(reward_addrs(1), 1), (burn_addr_1.clone(), 5)],
            allow_nakamoto_punishment: true,
        };

        fn rev(rs: &RewardSetInfo) -> RewardSetInfo {
            let mut out = rs.clone();
            out.recipients.reverse();
            out
        }

        fn no_punish(rs: &RewardSetInfo) -> RewardSetInfo {
            let mut out = rs.clone();
            out.allow_nakamoto_punishment = false;
            out
        }

        let mut test_vectors = vec![
            (
                LeaderBlockCommitOp {
                    commit_outs: vec![burn_addr_0.clone(), burn_addr_1.clone()],
                    ..default_block_commit.clone()
                },
                None,
                Ok(vec![]),
            ),
            (
                LeaderBlockCommitOp {
                    commit_outs: vec![burn_addr_0.clone(), burn_addr_1.clone()],
                    ..default_block_commit.clone()
                },
                Some(rs_pox_addrs.clone()),
                Ok(vec![
                    Treatment::Punish(reward_addrs(1)),
                    Treatment::Punish(reward_addrs(0)),
                ]),
            ),
            (
                LeaderBlockCommitOp {
                    commit_outs: vec![reward_addrs(0), burn_addr_1.clone()],
                    ..default_block_commit.clone()
                },
                Some(rs_pox_addrs.clone()),
                Ok(vec![
                    Treatment::Punish(reward_addrs(1)),
                    Treatment::Reward(reward_addrs(0)),
                ]),
            ),
            (
                LeaderBlockCommitOp {
                    commit_outs: vec![reward_addrs(1), burn_addr_1.clone()],
                    ..default_block_commit.clone()
                },
                Some(rs_pox_addrs.clone()),
                Ok(vec![
                    Treatment::Punish(reward_addrs(0)),
                    Treatment::Reward(reward_addrs(1)),
                ]),
            ),
            (
                LeaderBlockCommitOp {
                    commit_outs: vec![reward_addrs(0), reward_addrs(1)],
                    ..default_block_commit.clone()
                },
                Some(rs_pox_addrs.clone()),
                Ok(vec![
                    Treatment::Reward(reward_addrs(1)),
                    Treatment::Reward(reward_addrs(0)),
                ]),
            ),
            (
                LeaderBlockCommitOp {
                    commit_outs: vec![burn_addr_0.clone(), burn_addr_1.clone()],
                    ..default_block_commit.clone()
                },
                Some(rs_pox_addrs.clone()),
                Ok(vec![
                    Treatment::Punish(reward_addrs(1)),
                    Treatment::Punish(reward_addrs(0)),
                ]),
            ),
            (
                LeaderBlockCommitOp {
                    commit_outs: vec![burn_addr_0.clone(), burn_addr_1.clone()],
                    ..default_block_commit.clone()
                },
                Some(rs_pox_addrs_1b.clone()),
                // it doesn't matter if we call burn_addr_1 punished or rewarded!
                Ok(vec![
                    Treatment::Punish(reward_addrs(1)),
                    Treatment::Punish(burn_addr_1.clone()),
                ]),
            ),
            (
                LeaderBlockCommitOp {
                    commit_outs: vec![burn_addr_0.clone(), burn_addr_1.clone()],
                    ..default_block_commit.clone()
                },
                Some(rs_pox_addrs_0b.clone()),
                // it doesn't matter if we call burn_addr_1 punished or rewarded!
                Ok(vec![
                    Treatment::Punish(reward_addrs(0)),
                    Treatment::Punish(burn_addr_0.clone()),
                ]),
            ),
            (
                LeaderBlockCommitOp {
                    commit_outs: vec![burn_addr_0.clone(), burn_addr_1.clone()],
                    ..default_block_commit.clone()
                },
                Some(no_punish(&rs_pox_addrs)),
                Err(op_error::BlockCommitBadOutputs),
            ),
            (
                LeaderBlockCommitOp {
                    commit_outs: vec![burn_addr_0.clone(), burn_addr_1.clone()],
                    ..default_block_commit.clone()
                },
                Some(no_punish(&rs_pox_addrs_1b)),
                Err(op_error::BlockCommitBadOutputs),
            ),
            (
                LeaderBlockCommitOp {
                    commit_outs: vec![burn_addr_0.clone(), burn_addr_1.clone()],
                    ..default_block_commit.clone()
                },
                Some(no_punish(&rs_pox_addrs_0b)),
                Err(op_error::BlockCommitBadOutputs),
            ),
            (
                LeaderBlockCommitOp {
                    commit_outs: vec![reward_addrs(0)],
                    ..default_block_commit.clone()
                },
                Some(rs_pox_addrs.clone()),
                Err(op_error::BlockCommitBadOutputs),
            ),
            (
                LeaderBlockCommitOp {
                    commit_outs: vec![reward_addrs(0), reward_addrs(3)],
                    ..default_block_commit.clone()
                },
                Some(rs_pox_addrs.clone()),
                Err(op_error::BlockCommitBadOutputs),
            ),
            (
                LeaderBlockCommitOp {
                    commit_outs: vec![reward_addrs(1), reward_addrs(3)],
                    ..default_block_commit.clone()
                },
                Some(rs_pox_addrs.clone()),
                Err(op_error::BlockCommitBadOutputs),
            ),
            (
                LeaderBlockCommitOp {
                    commit_outs: vec![burn_addr_0.clone(), reward_addrs(3)],
                    ..default_block_commit.clone()
                },
                Some(rs_pox_addrs.clone()),
                Err(op_error::BlockCommitBadOutputs),
            ),
        ];

        for (ix, (op, reward_set_info, expected)) in test_vectors.iter_mut().enumerate() {
            for should_reverse in [false, true] {
                let reward_set_info = if should_reverse {
                    reward_set_info.as_ref().map(rev)
                } else {
                    reward_set_info.clone()
                };
                eprintln!("Processing {}", ix);
                let mut ic = DescendencyStubbedSortitionHandle::Descended;
                let output = op.check_pox(
                    StacksEpochId::Epoch30,
                    &burnchain,
                    &mut ic,
                    reward_set_info.as_ref(),
                );
                eprintln!("{:?} <=?=> {:?}", expected, output);
                match expected {
                    Err(e) => {
                        assert_eq!(format!("{e:?}"), format!("{:?}", &output.unwrap_err()));
                    }
                    Ok(expected_treatment) => {
                        assert!(output.is_ok());
                        let actual_treatment = output.unwrap();
                        assert_eq!(actual_treatment.len(), expected_treatment.len());
                        for i in actual_treatment.iter() {
                            assert!(expected_treatment.contains(i));
                        }
                    }
                }
            }
        }
    }

    #[test]
    fn test_epoch_marker() {
        let first_block_height = 121;
        let first_burn_hash = BurnchainHeaderHash::from_hex(
            "0000000000000000000000000000000000000000000000000000000000000001",
        )
        .unwrap();

        let burnchain = Burnchain {
            pox_constants: pox_constants(),
            peer_version: 0x012345678,
            network_id: 0x9abcdef0,
            chain_name: "bitcoin".to_string(),
            network_name: "testnet".to_string(),
            working_dir: "/nope".to_string(),
            consensus_hash_lifetime: 24,
            stable_confirmations: 7,
            first_block_height,
            initial_reward_start_block: first_block_height,
            first_block_timestamp: 0,
            first_block_hash: first_burn_hash.clone(),
        };

        let epoch_2_05_start = 125;
        let epoch_2_1_start = 130;

        let mut rng = rand::thread_rng();
        let mut buf = [0u8; 32];
        rng.fill_bytes(&mut buf);
        let db_path_dir = format!(
            "/tmp/stacks-node-tests/unit-tests-sortdb/db-{}",
            to_hex(&buf)
        );

        let mut db = SortitionDB::connect(
            &db_path_dir,
            first_block_height,
            &first_burn_hash,
            get_epoch_time_secs(),
            &[
                StacksEpoch {
                    epoch_id: StacksEpochId::Epoch10,
                    start_height: 0,
                    end_height: first_block_height,
                    block_limit: ExecutionCost::max_value(),
                    network_epoch: PEER_VERSION_EPOCH_1_0,
                },
                StacksEpoch {
                    epoch_id: StacksEpochId::Epoch20,
                    start_height: first_block_height,
                    end_height: epoch_2_05_start,
                    block_limit: ExecutionCost::max_value(),
                    network_epoch: PEER_VERSION_EPOCH_2_0,
                },
                StacksEpoch {
                    epoch_id: StacksEpochId::Epoch2_05,
                    start_height: epoch_2_05_start,
                    end_height: epoch_2_1_start,
                    block_limit: ExecutionCost::max_value(),
                    network_epoch: PEER_VERSION_EPOCH_2_05,
                },
                StacksEpoch {
                    epoch_id: StacksEpochId::Epoch21,
                    start_height: epoch_2_1_start,
                    end_height: STACKS_EPOCH_MAX,
                    block_limit: ExecutionCost::max_value(),
                    network_epoch: PEER_VERSION_EPOCH_2_1,
                },
            ],
            PoxConstants::test_default(),
            None,
            true,
        )
        .unwrap();

        let leader_key = LeaderKeyRegisterOp {
            consensus_hash: ConsensusHash([0x01; 20]),
            public_key: VRFPublicKey::from_bytes(
                &hex_bytes("a366b51292bef4edd64063d9145c617fec373bceb0758e98cd72becd84d54c7a")
                    .unwrap(),
            )
            .unwrap(),
            memo: vec![1, 2, 3, 4, 5],
            txid: Txid([0x01; 32]),
            vtxindex: 456,
            block_height: first_block_height + 1,
            burn_header_hash: BurnchainHeaderHash([0x00; 32]), // to be filled in
        };

        let block_commit_pre_2_05 = LeaderBlockCommitOp {
            treatment: vec![],
            sunset_burn: 0,
            block_header_hash: BlockHeaderHash([0x02; 32]),
            new_seed: VRFSeed([0x03; 32]),
            parent_block_ptr: 0,
            parent_vtxindex: 0,
            key_block_ptr: leader_key.block_height as u32,
            key_vtxindex: leader_key.vtxindex as u16,
            memo: vec![0x80],
            commit_outs: vec![],

            burn_fee: 12345,
            input: (Txid([0; 32]), 0),
            apparent_sender: BurnchainSigner::mock_parts(
                AddressHashMode::SerializeP2PKH,
                1,
                vec![StacksPublicKey::from_hex(
                    "02d8015134d9db8178ac93acbc43170a2f20febba5087a5b0437058765ad5133d0",
                )
                .unwrap()],
            ),

            txid: Txid([0x02; 32]),
            vtxindex: 444,
            block_height: first_block_height + 2,
            burn_parent_modulus: ((first_block_height + 1) % BURN_BLOCK_MINED_AT_MODULUS) as u8,
            burn_header_hash: BurnchainHeaderHash([0x00; 32]), // to be filled in
        };

        let block_commit_post_2_05_valid = LeaderBlockCommitOp {
            treatment: vec![],
            sunset_burn: 0,
            block_header_hash: BlockHeaderHash([0x03; 32]),
            new_seed: VRFSeed([0x04; 32]),
            parent_block_ptr: 0,
            parent_vtxindex: 0,
            key_block_ptr: leader_key.block_height as u32,
            key_vtxindex: leader_key.vtxindex as u16,
            memo: vec![STACKS_EPOCH_2_05_MARKER],
            commit_outs: vec![],

            burn_fee: 12345,
            input: (Txid([0; 32]), 0),
            apparent_sender: BurnchainSigner::mock_parts(
                AddressHashMode::SerializeP2PKH,
                1,
                vec![StacksPublicKey::from_hex(
                    "02d8015134d9db8178ac93acbc43170a2f20febba5087a5b0437058765ad5133d0",
                )
                .unwrap()],
            ),

            txid: Txid([0x03; 32]),
            vtxindex: 444,
            block_height: epoch_2_05_start,
            burn_parent_modulus: ((epoch_2_05_start - 1) % BURN_BLOCK_MINED_AT_MODULUS) as u8,
            burn_header_hash: BurnchainHeaderHash([0x00; 32]), // to be filled in
        };

        let block_commit_post_2_05_valid_bigger_epoch = LeaderBlockCommitOp {
            treatment: vec![],
            sunset_burn: 0,
            block_header_hash: BlockHeaderHash([0x03; 32]),
            new_seed: VRFSeed([0x04; 32]),
            parent_block_ptr: 0,
            parent_vtxindex: 0,
            key_block_ptr: leader_key.block_height as u32,
            key_vtxindex: leader_key.vtxindex as u16,
            memo: vec![STACKS_EPOCH_2_05_MARKER + 1],
            commit_outs: vec![],

            burn_fee: 12345,
            input: (Txid([0; 32]), 0),
            apparent_sender: BurnchainSigner::mock_parts(
                AddressHashMode::SerializeP2PKH,
                1,
                vec![StacksPublicKey::from_hex(
                    "02d8015134d9db8178ac93acbc43170a2f20febba5087a5b0437058765ad5133d0",
                )
                .unwrap()],
            ),

            txid: Txid([0x13; 32]),
            vtxindex: 444,
            block_height: epoch_2_05_start,
            burn_parent_modulus: ((epoch_2_05_start - 1) % BURN_BLOCK_MINED_AT_MODULUS) as u8,
            burn_header_hash: BurnchainHeaderHash([0x00; 32]), // to be filled in
        };

        let block_commit_post_2_05_invalid_bad_memo = LeaderBlockCommitOp {
            treatment: vec![],
            sunset_burn: 0,
            block_header_hash: BlockHeaderHash([0x04; 32]),
            new_seed: VRFSeed([0x05; 32]),
            parent_block_ptr: 0,
            parent_vtxindex: 0,
            key_block_ptr: leader_key.block_height as u32,
            key_vtxindex: leader_key.vtxindex as u16,
            memo: vec![STACKS_EPOCH_2_05_MARKER - 1],
            commit_outs: vec![],

            burn_fee: 12345,
            input: (Txid([0; 32]), 0),
            apparent_sender: BurnchainSigner::mock_parts(
                AddressHashMode::SerializeP2PKH,
                1,
                vec![StacksPublicKey::from_hex(
                    "02d8015134d9db8178ac93acbc43170a2f20febba5087a5b0437058765ad5133d0",
                )
                .unwrap()],
            ),

            txid: Txid([0x04; 32]),
            vtxindex: 445,
            block_height: epoch_2_05_start,
            burn_parent_modulus: ((epoch_2_05_start - 1) % BURN_BLOCK_MINED_AT_MODULUS) as u8,
            burn_header_hash: BurnchainHeaderHash([0x00; 32]), // to be filled in
        };

        let block_commit_post_2_05_invalid_no_memo = LeaderBlockCommitOp {
            treatment: vec![],
            sunset_burn: 0,
            block_header_hash: BlockHeaderHash([0x05; 32]),
            new_seed: VRFSeed([0x06; 32]),
            parent_block_ptr: 0,
            parent_vtxindex: 0,
            key_block_ptr: leader_key.block_height as u32,
            key_vtxindex: leader_key.vtxindex as u16,
            memo: vec![],
            commit_outs: vec![],

            burn_fee: 12345,
            input: (Txid([0; 32]), 0),
            apparent_sender: BurnchainSigner::mock_parts(
                AddressHashMode::SerializeP2PKH,
                1,
                vec![StacksPublicKey::from_hex(
                    "02d8015134d9db8178ac93acbc43170a2f20febba5087a5b0437058765ad5133d0",
                )
                .unwrap()],
            ),

            txid: Txid([0x05; 32]),
            vtxindex: 446,
            block_height: epoch_2_05_start,
            burn_parent_modulus: ((epoch_2_05_start - 1) % BURN_BLOCK_MINED_AT_MODULUS) as u8,
            burn_header_hash: BurnchainHeaderHash([0x00; 32]), // to be filled in
        };

        let block_commit_post_2_1_valid = LeaderBlockCommitOp {
            treatment: vec![],
            sunset_burn: 0,
            block_header_hash: BlockHeaderHash([0x03; 32]),
            new_seed: VRFSeed([0x04; 32]),
            parent_block_ptr: 0,
            parent_vtxindex: 0,
            key_block_ptr: leader_key.block_height as u32,
            key_vtxindex: leader_key.vtxindex as u16,
            memo: vec![STACKS_EPOCH_2_1_MARKER],
            commit_outs: vec![],

            burn_fee: 12345,
            input: (Txid([0; 32]), 0),
            apparent_sender: BurnchainSigner::mock_parts(
                AddressHashMode::SerializeP2PKH,
                1,
                vec![StacksPublicKey::from_hex(
                    "024d8cdaef508d665dd9dd50ca7e9fbd9e7984ec8bfac8f02dea9f02a9232af1d7",
                )
                .unwrap()],
            ),

            txid: Txid([0x03; 32]),
            vtxindex: 444,
            block_height: epoch_2_1_start,
            burn_parent_modulus: ((epoch_2_1_start - 1) % BURN_BLOCK_MINED_AT_MODULUS) as u8,
            burn_header_hash: BurnchainHeaderHash([0x00; 32]), // to be filled in
        };

        let block_commit_post_2_1_valid_bigger_epoch = LeaderBlockCommitOp {
            treatment: vec![],
            sunset_burn: 0,
            block_header_hash: BlockHeaderHash([0x03; 32]),
            new_seed: VRFSeed([0x04; 32]),
            parent_block_ptr: 0,
            parent_vtxindex: 0,
            key_block_ptr: leader_key.block_height as u32,
            key_vtxindex: leader_key.vtxindex as u16,
            memo: vec![STACKS_EPOCH_2_1_MARKER + 1],
            commit_outs: vec![],

            burn_fee: 12345,
            input: (Txid([0; 32]), 0),
            apparent_sender: BurnchainSigner::mock_parts(
                AddressHashMode::SerializeP2PKH,
                1,
                vec![StacksPublicKey::from_hex(
                    "024d8cdaef508d665dd9dd50ca7e9fbd9e7984ec8bfac8f02dea9f02a9232af1d7",
                )
                .unwrap()],
            ),

            txid: Txid([0x13; 32]),
            vtxindex: 444,
            block_height: epoch_2_1_start,
            burn_parent_modulus: ((epoch_2_1_start - 1) % BURN_BLOCK_MINED_AT_MODULUS) as u8,
            burn_header_hash: BurnchainHeaderHash([0x00; 32]), // to be filled in
        };

        let block_commit_post_2_1_invalid_bad_memo = LeaderBlockCommitOp {
            treatment: vec![],
            sunset_burn: 0,
            block_header_hash: BlockHeaderHash([0x04; 32]),
            new_seed: VRFSeed([0x05; 32]),
            parent_block_ptr: 0,
            parent_vtxindex: 0,
            key_block_ptr: leader_key.block_height as u32,
            key_vtxindex: leader_key.vtxindex as u16,
            memo: vec![STACKS_EPOCH_2_1_MARKER - 1],
            commit_outs: vec![],

            burn_fee: 12345,
            input: (Txid([0; 32]), 0),
            apparent_sender: BurnchainSigner::mock_parts(
                AddressHashMode::SerializeP2PKH,
                1,
                vec![StacksPublicKey::from_hex(
                    "02b20f7d690afa0464d7eb17bdd86820261fb1acfdf489b2442a205a693da231ac",
                )
                .unwrap()],
            ),

            txid: Txid([0x04; 32]),
            vtxindex: 445,
            block_height: epoch_2_1_start,
            burn_parent_modulus: ((epoch_2_1_start - 1) % BURN_BLOCK_MINED_AT_MODULUS) as u8,
            burn_header_hash: BurnchainHeaderHash([0x00; 32]), // to be filled in
        };

        let block_commit_post_2_1_invalid_no_memo = LeaderBlockCommitOp {
            treatment: vec![],
            sunset_burn: 0,
            block_header_hash: BlockHeaderHash([0x05; 32]),
            new_seed: VRFSeed([0x06; 32]),
            parent_block_ptr: 0,
            parent_vtxindex: 0,
            key_block_ptr: leader_key.block_height as u32,
            key_vtxindex: leader_key.vtxindex as u16,
            memo: vec![],
            commit_outs: vec![],

            burn_fee: 12345,
            input: (Txid([0; 32]), 0),
            apparent_sender: BurnchainSigner::mock_parts(
                AddressHashMode::SerializeP2PKH,
                1,
                vec![StacksPublicKey::from_hex(
                    "02e371309f1c25abc5f00353d74632c6f5b95eb80e1e1edb9ba53e14b0d47bc0de",
                )
                .unwrap()],
            ),

            txid: Txid([0x05; 32]),
            vtxindex: 446,
            block_height: epoch_2_1_start,
            burn_parent_modulus: ((epoch_2_1_start - 1) % BURN_BLOCK_MINED_AT_MODULUS) as u8,
            burn_header_hash: BurnchainHeaderHash([0x00; 32]), // to be filled in
        };

        let all_leader_key_ops = vec![leader_key];

        let mut all_block_commit_ops = vec![
            (block_commit_pre_2_05, true),
            (block_commit_post_2_05_valid, true),
            (block_commit_post_2_05_valid_bigger_epoch, true),
            (block_commit_post_2_05_invalid_bad_memo, false),
            (block_commit_post_2_05_invalid_no_memo, false),
            (block_commit_post_2_1_valid, true),
            (block_commit_post_2_1_valid_bigger_epoch, true),
            (block_commit_post_2_1_invalid_bad_memo, false),
            (block_commit_post_2_1_invalid_no_memo, false),
        ];

        let mut sn = SortitionDB::get_first_block_snapshot(db.conn()).unwrap();
        for i in sn.block_height..(epoch_2_1_start + 2) {
            eprintln!("Block {}", i);
            let mut byte_pattern = [0u8; 32];
            byte_pattern[24..32].copy_from_slice(&i.to_be_bytes());
            let next_hash = BurnchainHeaderHash(byte_pattern);

            let mut block_ops = vec![];
            for op in all_leader_key_ops.iter() {
                if op.block_height == i + 1 {
                    let mut block_op = op.clone();
                    block_op.burn_header_hash = next_hash.clone();
                    block_ops.push(BlockstackOperationType::LeaderKeyRegister(block_op));
                }
            }

            {
                let tip = SortitionDB::get_canonical_burn_chain_tip(db.conn()).unwrap();
                eprintln!("Tip sortition is {}", &tip.sortition_id);
                let mut ic = SortitionHandleTx::begin(&mut db, &tip.sortition_id).unwrap();

                for (op, pass) in all_block_commit_ops.iter_mut() {
                    if op.block_height == i + 1 {
                        match op.check(&burnchain, &mut ic, None) {
                            Ok(_) => {
                                assert!(
                                    *pass,
                                    "Check succeeded when it should have failed: {:?}",
                                    &op
                                );
                                block_ops
                                    .push(BlockstackOperationType::LeaderBlockCommit(op.clone()));
                            }
                            Err(op_error::BlockCommitBadEpoch) => {
                                assert!(
                                    !*pass,
                                    "Check failed when it should have succeeded: {:?}",
                                    &op
                                );
                            }
                            Err(e) => {
                                panic!("Unexpected error variant {}", &e);
                            }
                        }
                    }
                }
            }
            sn = test_append_snapshot(&mut db, next_hash, &block_ops);
        }
    }
}
