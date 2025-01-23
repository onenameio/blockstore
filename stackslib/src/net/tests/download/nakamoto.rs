// Copyright (C) 2013-2020 Blockstack PBC, a public benefit corporation
// Copyright (C) 2020-2024 Stacks Open Internet Foundation
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

use std::collections::{HashMap, VecDeque};
use std::sync::mpsc::sync_channel;
use std::thread;

use stacks_common::bitvec::BitVec;
use stacks_common::types::chainstate::{
    ConsensusHash, StacksAddress, StacksBlockId, StacksPrivateKey, TrieHash,
};
use stacks_common::types::net::PeerAddress;
use stacks_common::types::StacksEpochId;
use stacks_common::util::get_epoch_time_secs;
use stacks_common::util::hash::{hex_bytes, Sha512Trunc256Sum};
use stacks_common::util::secp256k1::MessageSignature;
use stacks_common::util::vrf::VRFProof;

use crate::burnchains::PoxConstants;
use crate::chainstate::burn::db::sortdb::SortitionHandle;
use crate::chainstate::burn::BlockSnapshot;
use crate::chainstate::nakamoto::test_signers::TestSigners;
use crate::chainstate::nakamoto::{
    NakamotoBlock, NakamotoBlockHeader, NakamotoChainState, NakamotoStagingBlocksConnRef,
};
use crate::chainstate::stacks::db::{StacksChainState, StacksHeaderInfo};
use crate::chainstate::stacks::{
    CoinbasePayload, Error as ChainstateError, StacksTransaction, TenureChangeCause,
    TenureChangePayload, TokenTransferMemo, TransactionAnchorMode, TransactionAuth,
    TransactionPayload, TransactionVersion,
};
use crate::clarity::vm::types::StacksAddressExtensions;
use crate::net::api::gettenureinfo::RPCGetTenureInfo;
use crate::net::download::nakamoto::{TenureStartEnd, WantedTenure, *};
use crate::net::inv::nakamoto::NakamotoTenureInv;
use crate::net::test::{dns_thread_start, to_addr, TestEventObserver};
use crate::net::tests::inv::nakamoto::{
    make_nakamoto_peer_from_invs, make_nakamoto_peers_from_invs_ext, peer_get_nakamoto_invs,
};
use crate::net::tests::{NakamotoBootPlan, TestPeer};
use crate::net::{Error as NetError, Hash160, NeighborAddress, SortitionDB};
use crate::stacks_common::types::Address;
use crate::util_lib::db::Error as DBError;

impl NakamotoTenureDownloadState {
    pub fn request_time(&self) -> Option<u128> {
        match self {
            Self::GetTenureStartBlock(_, ts) => Some(*ts),
            Self::GetTenureEndBlock(_, ts) => Some(*ts),
            Self::GetTenureBlocks(_, ts) => Some(*ts),
            Self::Done => None,
        }
    }
}

impl NakamotoDownloadStateMachine {
    /// Find the list of wanted tenures for the given reward cycle.  The reward cycle must
    /// be complete already.  Used for testing.
    ///
    /// Returns a reward cycle's wanted tenures.
    /// Returns a DB error if the snapshot does not correspond to a full reward cycle.
    #[cfg(test)]
    pub(crate) fn load_wanted_tenures_for_reward_cycle(
        cur_rc: u64,
        tip: &BlockSnapshot,
        sortdb: &SortitionDB,
    ) -> Result<Vec<WantedTenure>, NetError> {
        // careful -- need .saturating_sub(1) since this calculation puts the reward cycle start at
        // block height 1 mod reward cycle len, but we really want 0 mod reward cycle len
        let first_block_height = sortdb
            .pox_constants
            .reward_cycle_to_block_height(sortdb.first_block_height, cur_rc)
            .saturating_sub(1);
        let last_block_height = sortdb
            .pox_constants
            .reward_cycle_to_block_height(sortdb.first_block_height, cur_rc.saturating_add(1))
            .saturating_sub(1);

        test_debug!(
            "Load reward cycle sortitions between {} and {} (rc is {})",
            first_block_height,
            last_block_height,
            cur_rc
        );

        // find all sortitions in this reward cycle
        let ih = sortdb.index_handle(&tip.sortition_id);
        Self::load_wanted_tenures(&ih, first_block_height, last_block_height)
    }
}

impl NakamotoStagingBlocksConnRef<'_> {
    pub fn load_nakamoto_tenure(
        &self,
        tip: &StacksBlockId,
    ) -> Result<Option<Vec<NakamotoBlock>>, ChainstateError> {
        let Some((block, ..)) = self.get_nakamoto_block(tip)? else {
            return Ok(None);
        };
        if block.is_wellformed_tenure_start_block().map_err(|_| {
            ChainstateError::InvalidStacksBlock("Malformed tenure-start block".into())
        })? {
            // we're done
            return Ok(Some(vec![block]));
        }

        // this is an intermediate block
        let mut tenure = vec![];
        let mut cursor = block.header.parent_block_id.clone();
        tenure.push(block);
        loop {
            let Some((block, _)) = self.get_nakamoto_block(&cursor)? else {
                return Ok(None);
            };

            let is_tenure_start = block.is_wellformed_tenure_start_block().map_err(|e| {
                ChainstateError::InvalidStacksBlock("Malformed tenure-start block".into())
            })?;
            cursor = block.header.parent_block_id.clone();
            tenure.push(block);

            if is_tenure_start {
                break;
            }
        }
        tenure.reverse();
        Ok(Some(tenure))
    }
}

#[test]
fn test_nakamoto_tenure_downloader() {
    let ch = ConsensusHash([0x11; 20]);
    let private_key = StacksPrivateKey::new();
    let mut test_signers = TestSigners::new(vec![]);

    let reward_set = test_signers.synthesize_reward_set();

    let tenure_start_header = NakamotoBlockHeader {
        version: 1,
        chain_length: 2,
        burn_spent: 3,
        consensus_hash: ConsensusHash([0x04; 20]),
        parent_block_id: StacksBlockId([0x05; 32]),
        tx_merkle_root: Sha512Trunc256Sum([0x06; 32]),
        state_index_root: TrieHash([0x07; 32]),
        timestamp: 8,
        miner_signature: MessageSignature::empty(),
        signer_signature: vec![],
        pox_treatment: BitVec::zeros(1).unwrap(),
    };

    let tenure_change_payload = TenureChangePayload {
        tenure_consensus_hash: ConsensusHash([0x04; 20]),
        prev_tenure_consensus_hash: ConsensusHash([0x03; 20]),
        burn_view_consensus_hash: ConsensusHash([0x04; 20]),
        previous_tenure_end: tenure_start_header.parent_block_id.clone(),
        previous_tenure_blocks: 1,
        cause: TenureChangeCause::BlockFound,
        pubkey_hash: Hash160([0x02; 20]),
    };
    let proof_bytes = hex_bytes("9275df67a68c8745c0ff97b48201ee6db447f7c93b23ae24cdc2400f52fdb08a1a6ac7ec71bf9c9c76e96ee4675ebff60625af28718501047bfd87b810c2d2139b73c23bd69de66360953a642c2a330a").unwrap();
    let proof = VRFProof::from_bytes(&proof_bytes[..].to_vec()).unwrap();

    let coinbase_payload =
        TransactionPayload::Coinbase(CoinbasePayload([0x12; 32]), None, Some(proof.clone()));

    let mut coinbase_tx = StacksTransaction::new(
        TransactionVersion::Testnet,
        TransactionAuth::from_p2pkh(&private_key).unwrap(),
        coinbase_payload.clone(),
    );
    coinbase_tx.chain_id = 0x80000000;
    coinbase_tx.anchor_mode = TransactionAnchorMode::OnChainOnly;

    let mut tenure_change_tx = StacksTransaction::new(
        TransactionVersion::Testnet,
        TransactionAuth::from_p2pkh(&private_key).unwrap(),
        TransactionPayload::TenureChange(tenure_change_payload.clone()),
    );
    tenure_change_tx.chain_id = 0x80000000;
    tenure_change_tx.anchor_mode = TransactionAnchorMode::OnChainOnly;

    let recipient_addr =
        StacksAddress::from_string("ST2YM3J4KQK09V670TD6ZZ1XYNYCNGCWCVTASN5VM").unwrap();
    let mut stx_transfer = StacksTransaction::new(
        TransactionVersion::Testnet,
        TransactionAuth::from_p2pkh(&private_key).unwrap(),
        TransactionPayload::TokenTransfer(
            recipient_addr.to_account_principal(),
            1,
            TokenTransferMemo([0x00; 34]),
        ),
    );
    stx_transfer.chain_id = 0x80000000;
    stx_transfer.anchor_mode = TransactionAnchorMode::OnChainOnly;

    let mut tenure_start_block = NakamotoBlock {
        header: tenure_start_header.clone(),
        txs: vec![tenure_change_tx.clone(), coinbase_tx.clone()],
    };
    test_signers.sign_nakamoto_block(&mut tenure_start_block, 0);

    let mut blocks = vec![tenure_start_block.clone()];
    for i in 0..10 {
        let last_block = blocks.last().unwrap();
        let header = NakamotoBlockHeader {
            version: 1,
            chain_length: last_block.header.chain_length + 1,
            burn_spent: last_block.header.burn_spent + 1,
            consensus_hash: last_block.header.consensus_hash.clone(),
            parent_block_id: last_block.header.block_id(),
            tx_merkle_root: Sha512Trunc256Sum([0x06; 32]),
            state_index_root: TrieHash([0x07; 32]),
            timestamp: 8,
            miner_signature: MessageSignature::empty(),
            signer_signature: vec![],
            pox_treatment: BitVec::zeros(1).unwrap(),
        };

        let mut block = NakamotoBlock {
            header,
            txs: vec![stx_transfer.clone()],
        };
        test_signers.sign_nakamoto_block(&mut block, 0);
        blocks.push(block);
    }

    let next_tenure_start_header = NakamotoBlockHeader {
        version: 1,
        chain_length: blocks.last().unwrap().header.chain_length + 1,
        burn_spent: blocks.last().unwrap().header.burn_spent + 1,
        consensus_hash: ConsensusHash([0x05; 20]),
        parent_block_id: blocks.last().unwrap().header.block_id(),
        tx_merkle_root: Sha512Trunc256Sum([0x07; 32]),
        state_index_root: TrieHash([0x08; 32]),
        timestamp: 9,
        miner_signature: MessageSignature::empty(),
        signer_signature: vec![],
        pox_treatment: BitVec::zeros(1).unwrap(),
    };

    let next_tenure_change_payload = TenureChangePayload {
        tenure_consensus_hash: ConsensusHash([0x05; 20]),
        prev_tenure_consensus_hash: ConsensusHash([0x04; 20]),
        burn_view_consensus_hash: ConsensusHash([0x05; 20]),
        previous_tenure_end: next_tenure_start_header.parent_block_id.clone(),
        previous_tenure_blocks: 11,
        cause: TenureChangeCause::BlockFound,
        pubkey_hash: Hash160([0x02; 20]),
    };

    let mut next_tenure_change_tx = StacksTransaction::new(
        TransactionVersion::Testnet,
        TransactionAuth::from_p2pkh(&private_key).unwrap(),
        TransactionPayload::TenureChange(next_tenure_change_payload.clone()),
    );
    next_tenure_change_tx.chain_id = 0x80000000;
    next_tenure_change_tx.anchor_mode = TransactionAnchorMode::OnChainOnly;

    let mut next_tenure_start_block = NakamotoBlock {
        header: next_tenure_start_header.clone(),
        txs: vec![next_tenure_change_tx.clone(), coinbase_tx.clone()],
    };
    test_signers.sign_nakamoto_block(&mut next_tenure_start_block, 0);

    let naddr = NeighborAddress {
        addrbytes: PeerAddress([0xff; 16]),
        port: 123,
        public_key_hash: Hash160([0xff; 20]),
    };

    let mut td = NakamotoTenureDownloader::new(
        tenure_start_block.header.consensus_hash.clone(),
        tenure_start_block.header.consensus_hash.clone(),
        tenure_start_block.header.block_id(),
        next_tenure_start_block.header.consensus_hash.clone(),
        next_tenure_start_block.header.block_id(),
        naddr.clone(),
        reward_set.clone(),
        reward_set.clone(),
    );

    // must be first block
    assert_eq!(
        td.state,
        NakamotoTenureDownloadState::GetTenureStartBlock(
            tenure_start_block.header.block_id(),
            td.state.request_time().unwrap()
        )
    );
    assert!(td
        .try_accept_tenure_start_block(blocks.last().unwrap().clone())
        .is_err());
    assert!(td
        .try_accept_tenure_start_block(next_tenure_start_block.clone())
        .is_err());

    // advance state
    assert!(td
        .try_accept_tenure_start_block(blocks.first().unwrap().clone())
        .is_ok());

    let NakamotoTenureDownloadState::GetTenureEndBlock(block_id, ..) = td.state else {
        panic!("wrong state");
    };
    assert_eq!(block_id, next_tenure_start_block.header.block_id());
    assert_eq!(td.tenure_start_block, Some(tenure_start_block.clone()));
    assert!(td.tenure_length().is_none());

    // must be last block
    assert!(td.try_accept_tenure_end_block(&tenure_start_block).is_err());
    assert!(td
        .try_accept_tenure_end_block(blocks.last().unwrap())
        .is_err());

    // advance state
    assert!(td
        .try_accept_tenure_end_block(&next_tenure_start_block)
        .is_ok());
    assert_eq!(
        td.state,
        NakamotoTenureDownloadState::GetTenureBlocks(
            next_tenure_start_block.header.parent_block_id.clone(),
            td.state.request_time().unwrap(),
        )
    );
    assert_eq!(td.tenure_end_block, Some(next_tenure_start_block.clone()));
    assert_eq!(td.tenure_length(), Some(11));

    let mut td_one_shot = td.clone();

    // advance state, one block at a time
    for block in blocks.iter().rev() {
        if block.header.block_id() == tenure_start_block.header.block_id() {
            break;
        }
        // must be accepted in order
        assert!(td
            .try_accept_tenure_blocks(vec![next_tenure_start_block.clone()])
            .is_err());

        debug!("Try accept {:?}", &block);
        let res = td.try_accept_tenure_blocks(vec![block.clone()]);
        assert!(res.is_ok());
        assert!(res.unwrap().is_none());

        // tail pointer moved
        assert_eq!(
            td.state,
            NakamotoTenureDownloadState::GetTenureBlocks(
                block.header.parent_block_id.clone(),
                td.state.request_time().unwrap()
            )
        );
    }

    // get full tenure
    let res = td.try_accept_tenure_blocks(vec![tenure_start_block.clone()]);
    assert!(res.is_ok());
    let res_blocks = res.unwrap().unwrap();
    assert_eq!(res_blocks.len(), blocks.len() + 1); // includes tenure-end block

    let mut all_blocks = blocks.clone();
    all_blocks.push(next_tenure_start_block.clone());
    assert_eq!(res_blocks, all_blocks);
    assert_eq!(td.state, NakamotoTenureDownloadState::Done);

    // also works if we give blocks in one shot
    let res = td_one_shot.try_accept_tenure_blocks(blocks.clone().into_iter().rev().collect());
    assert!(res.is_ok());
    assert_eq!(res.unwrap().unwrap(), all_blocks);
    assert_eq!(td_one_shot.state, NakamotoTenureDownloadState::Done);

    // TODO:
    // * bad signature
    // * too many blocks
}

#[test]
fn test_nakamoto_unconfirmed_tenure_downloader() {
    let observer = TestEventObserver::new();
    let bitvecs = vec![vec![
        true, true, true, true, true, true, true, true, true, true,
    ]];

    let rc_len = 10u64;
    let peer = make_nakamoto_peer_from_invs(
        function_name!(),
        &observer,
        rc_len as u32,
        3,
        bitvecs.clone(),
    );
    let (mut peer, reward_cycle_invs) =
        peer_get_nakamoto_invs(peer, &[0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12]);
    peer.mine_malleablized_blocks = false;

    let nakamoto_start =
        NakamotoBootPlan::nakamoto_first_tenure_height(&peer.config.burnchain.pox_constants);

    let all_sortitions = peer.sortdb().get_all_snapshots().unwrap();
    let tip = SortitionDB::get_canonical_burn_chain_tip(peer.sortdb().conn()).unwrap();

    assert_eq!(tip.block_height, 51);

    let test_signers = TestSigners::new(vec![]);

    let naddr = NeighborAddress {
        addrbytes: PeerAddress([0xff; 16]),
        port: 123,
        public_key_hash: Hash160([0xff; 20]),
    };

    peer.refresh_burnchain_view();
    let tip_block_id = peer.network.stacks_tip.block_id();

    let tip_ch = peer.network.stacks_tip.consensus_hash.clone();
    let parent_tip_ch = peer.network.parent_stacks_tip.consensus_hash.clone();
    let current_reward_sets = peer.network.current_reward_sets.clone();

    let last_block_in_confirmed_tenure = NakamotoChainState::get_highest_block_header_in_tenure(
        &mut peer.chainstate().index_conn(),
        &tip_block_id,
        &parent_tip_ch,
    )
    .unwrap()
    .unwrap();

    // NOTE: we have to account for malleablized blocks!
    let unconfirmed_tenure = peer
        .chainstate()
        .nakamoto_blocks_db()
        .get_all_blocks_in_tenure(&tip_ch, &tip_block_id)
        .unwrap();
    let last_confirmed_tenure = peer
        .chainstate()
        .nakamoto_blocks_db()
        .get_all_blocks_in_tenure(
            &parent_tip_ch,
            &last_block_in_confirmed_tenure.index_block_hash(),
        )
        .unwrap();

    let parent_parent_header = NakamotoChainState::get_block_header_nakamoto(
        peer.chainstate().db(),
        &last_confirmed_tenure
            .first()
            .as_ref()
            .unwrap()
            .header
            .parent_block_id,
    )
    .unwrap()
    .unwrap();
    let parent_parent_start_header = NakamotoChainState::get_nakamoto_tenure_start_block_header(
        &mut peer.chainstate().index_conn(),
        &tip_block_id,
        &parent_parent_header.consensus_hash,
    )
    .unwrap()
    .unwrap();

    assert!(!unconfirmed_tenure.is_empty());
    assert!(!last_confirmed_tenure.is_empty());

    assert_eq!(
        unconfirmed_tenure.first().as_ref().unwrap().block_id(),
        peer.network.tenure_start_block_id
    );
    assert_eq!(
        unconfirmed_tenure
            .first()
            .as_ref()
            .unwrap()
            .header
            .parent_block_id,
        last_confirmed_tenure.last().as_ref().unwrap().block_id()
    );

    let tip_rc = peer
        .network
        .burnchain
        .block_height_to_reward_cycle(peer.network.burnchain_tip.block_height)
        .expect("FATAL: burnchain tip before system start");

    let highest_confirmed_wanted_tenure = WantedTenure {
        tenure_id_consensus_hash: peer.network.parent_stacks_tip.consensus_hash.clone(),
        winning_block_id: parent_parent_start_header.index_block_hash(),
        processed: false,
        burn_height: peer.network.burnchain_tip.block_height - 1,
    };

    let unconfirmed_wanted_tenure = WantedTenure {
        tenure_id_consensus_hash: peer.network.stacks_tip.consensus_hash.clone(),
        winning_block_id: last_confirmed_tenure
            .first()
            .as_ref()
            .unwrap()
            .header
            .block_id(),
        processed: false,
        burn_height: peer.network.burnchain_tip.block_height,
    };

    // we can make unconfirmed tenure downloaders
    {
        let mut empty_schedule = VecDeque::new();
        let mut full_schedule = {
            let mut sched = VecDeque::new();
            sched.push_back(naddr.clone());
            sched
        };
        let mut empty_downloaders = HashMap::new();
        let mut full_downloaders = {
            let mut dl = HashMap::new();
            let utd = NakamotoUnconfirmedTenureDownloader::new(naddr.clone(), Some(tip_block_id));
            dl.insert(naddr.clone(), utd);
            dl
        };
        assert_eq!(
            NakamotoDownloadStateMachine::make_unconfirmed_tenure_downloaders(
                &mut empty_schedule,
                10,
                &mut empty_downloaders,
                None
            ),
            0
        );
        assert_eq!(
            NakamotoDownloadStateMachine::make_unconfirmed_tenure_downloaders(
                &mut empty_schedule,
                10,
                &mut full_downloaders,
                None
            ),
            0
        );
        assert_eq!(
            NakamotoDownloadStateMachine::make_unconfirmed_tenure_downloaders(
                &mut full_schedule,
                10,
                &mut full_downloaders,
                None
            ),
            0
        );
        assert_eq!(full_schedule.len(), 1);
        assert_eq!(
            NakamotoDownloadStateMachine::make_unconfirmed_tenure_downloaders(
                &mut full_schedule,
                10,
                &mut empty_downloaders,
                None
            ),
            1
        );
        assert_eq!(full_schedule.len(), 0);
        assert_eq!(empty_downloaders.len(), 1);
    }

    // we've processed the tip already, so we transition straight to the Done state
    {
        let mut utd = NakamotoUnconfirmedTenureDownloader::new(naddr.clone(), Some(tip_block_id));
        assert_eq!(utd.state, NakamotoUnconfirmedDownloadState::GetTenureInfo);

        utd.confirmed_signer_keys = Some(
            current_reward_sets
                .get(&tip_rc)
                .cloned()
                .unwrap()
                .reward_cycle_info
                .known_selected_anchor_block_owned()
                .unwrap(),
        );
        utd.unconfirmed_signer_keys = Some(
            current_reward_sets
                .get(&tip_rc)
                .cloned()
                .unwrap()
                .reward_cycle_info
                .known_selected_anchor_block_owned()
                .unwrap(),
        );

        let tenure_tip = RPCGetTenureInfo {
            consensus_hash: peer.network.stacks_tip.consensus_hash.clone(),
            tenure_start_block_id: peer.network.tenure_start_block_id.clone(),
            parent_consensus_hash: peer.network.parent_stacks_tip.consensus_hash.clone(),
            parent_tenure_start_block_id: StacksBlockId::new(
                &peer.network.parent_stacks_tip.consensus_hash,
                &peer.network.parent_stacks_tip.block_hash,
            ),
            tip_block_id: StacksBlockId::new(
                &peer.network.stacks_tip.consensus_hash,
                &peer.network.stacks_tip.block_hash,
            ),
            tip_height: peer.network.stacks_tip.height,
            reward_cycle: tip_rc,
        };

        let sortdb = peer.sortdb.take().unwrap();
        let sort_tip = SortitionDB::get_canonical_burn_chain_tip(sortdb.conn()).unwrap();
        utd.try_accept_tenure_info(
            &sortdb,
            &sort_tip,
            peer.chainstate(),
            tenure_tip.clone(),
            &current_reward_sets,
        )
        .unwrap();

        peer.sortdb = Some(sortdb);

        assert!(utd.unconfirmed_tenure_start_block.is_some());

        // because the highest processed block is the same as .tip_block_id, we're done
        assert_eq!(utd.state, NakamotoUnconfirmedDownloadState::Done);

        // we can request the highest-complete tenure
        assert!(!utd.need_highest_complete_tenure(peer.chainstate()).unwrap());

        let ntd = utd.make_highest_complete_tenure_downloader().unwrap();
        assert_eq!(
            ntd.state,
            NakamotoTenureDownloadState::GetTenureStartBlock(
                unconfirmed_wanted_tenure.winning_block_id.clone(),
                ntd.state.request_time().unwrap()
            )
        );
    }

    // we've processed the first block in the unconfirmed tenure, but not the tip, so we transition to
    // the GetUnconfirmedTenureBlocks(..) state.
    {
        let mid_tip_block_id = unconfirmed_tenure.first().as_ref().unwrap().block_id();

        let mut utd =
            NakamotoUnconfirmedTenureDownloader::new(naddr.clone(), Some(mid_tip_block_id));
        utd.confirmed_signer_keys = Some(
            current_reward_sets
                .get(&tip_rc)
                .cloned()
                .unwrap()
                .reward_cycle_info
                .known_selected_anchor_block_owned()
                .unwrap(),
        );
        utd.unconfirmed_signer_keys = Some(
            current_reward_sets
                .get(&tip_rc)
                .cloned()
                .unwrap()
                .reward_cycle_info
                .known_selected_anchor_block_owned()
                .unwrap(),
        );

        assert_eq!(utd.state, NakamotoUnconfirmedDownloadState::GetTenureInfo);

        let tenure_tip = RPCGetTenureInfo {
            consensus_hash: peer.network.stacks_tip.consensus_hash.clone(),
            tenure_start_block_id: peer.network.tenure_start_block_id.clone(),
            parent_consensus_hash: peer.network.parent_stacks_tip.consensus_hash.clone(),
            parent_tenure_start_block_id: StacksBlockId::new(
                &peer.network.parent_stacks_tip.consensus_hash,
                &peer.network.parent_stacks_tip.block_hash,
            ),
            tip_block_id: StacksBlockId::new(
                &peer.network.stacks_tip.consensus_hash,
                &peer.network.stacks_tip.block_hash,
            ),
            tip_height: peer.network.stacks_tip.height,
            reward_cycle: tip_rc,
        };

        let sortdb = peer.sortdb.take().unwrap();
        let sort_tip = SortitionDB::get_canonical_burn_chain_tip(sortdb.conn()).unwrap();
        utd.try_accept_tenure_info(
            &sortdb,
            &sort_tip,
            peer.chainstate(),
            tenure_tip.clone(),
            &current_reward_sets,
        )
        .unwrap();

        peer.sortdb = Some(sortdb);

        assert!(utd.unconfirmed_tenure_start_block.is_some());

        // because we already have processed the start-block of this unconfirmed tenure, we'll
        // advance straight to getting more unconfirmed tenure blocks
        assert_eq!(
            utd.state,
            NakamotoUnconfirmedDownloadState::GetUnconfirmedTenureBlocks(
                tenure_tip.tip_block_id.clone(),
            )
        );
        assert_eq!(utd.tenure_tip, Some(tenure_tip.clone()));

        // fill in blocks
        for (i, block) in unconfirmed_tenure.iter().enumerate().rev() {
            let res = utd
                .try_accept_unconfirmed_tenure_blocks(vec![block.clone()])
                .unwrap();
            if i == 0 {
                // res won't contain the first block because it stopped processing once it reached
                // a block that the node knew
                assert_eq!(res.unwrap(), unconfirmed_tenure[1..].to_vec());
                break;
            } else {
                assert!(res.is_none());
            }
        }

        assert_eq!(utd.state, NakamotoUnconfirmedDownloadState::Done);

        // we can request the highest-complete tenure
        assert!(!utd.need_highest_complete_tenure(peer.chainstate()).unwrap());

        let ntd = utd.make_highest_complete_tenure_downloader().unwrap();
        assert_eq!(
            ntd.state,
            NakamotoTenureDownloadState::GetTenureStartBlock(
                unconfirmed_wanted_tenure.winning_block_id.clone(),
                ntd.state.request_time().unwrap()
            )
        );
    }

    // we've processed the middle block in the unconfirmed tenure, but not the tip, so we transition to
    // the GetUnconfirmedTenureBlocks(..) state.
    {
        let mid_tip_block_id = unconfirmed_tenure.get(5).unwrap().block_id();

        let mut utd =
            NakamotoUnconfirmedTenureDownloader::new(naddr.clone(), Some(mid_tip_block_id));
        utd.confirmed_signer_keys = Some(
            current_reward_sets
                .get(&tip_rc)
                .cloned()
                .unwrap()
                .reward_cycle_info
                .known_selected_anchor_block_owned()
                .unwrap(),
        );
        utd.unconfirmed_signer_keys = Some(
            current_reward_sets
                .get(&tip_rc)
                .cloned()
                .unwrap()
                .reward_cycle_info
                .known_selected_anchor_block_owned()
                .unwrap(),
        );

        assert_eq!(utd.state, NakamotoUnconfirmedDownloadState::GetTenureInfo);

        let tenure_tip = RPCGetTenureInfo {
            consensus_hash: peer.network.stacks_tip.consensus_hash.clone(),
            tenure_start_block_id: peer.network.tenure_start_block_id.clone(),
            parent_consensus_hash: peer.network.parent_stacks_tip.consensus_hash.clone(),
            parent_tenure_start_block_id: StacksBlockId::new(
                &peer.network.parent_stacks_tip.consensus_hash,
                &peer.network.parent_stacks_tip.block_hash,
            ),
            tip_block_id: StacksBlockId::new(
                &peer.network.stacks_tip.consensus_hash,
                &peer.network.stacks_tip.block_hash,
            ),
            tip_height: peer.network.stacks_tip.height,
            reward_cycle: tip_rc,
        };

        let sortdb = peer.sortdb.take().unwrap();
        let sort_tip = SortitionDB::get_canonical_burn_chain_tip(sortdb.conn()).unwrap();
        utd.try_accept_tenure_info(
            &sortdb,
            &sort_tip,
            peer.chainstate(),
            tenure_tip.clone(),
            &current_reward_sets,
        )
        .unwrap();

        peer.sortdb = Some(sortdb);

        assert!(utd.unconfirmed_tenure_start_block.is_some());

        // because we already have processed the start-block of this unconfirmed tenure, we'll
        // advance straight to getting more unconfirmed tenure blocks
        assert_eq!(
            utd.state,
            NakamotoUnconfirmedDownloadState::GetUnconfirmedTenureBlocks(
                tenure_tip.tip_block_id.clone(),
            )
        );
        assert_eq!(utd.tenure_tip, Some(tenure_tip.clone()));

        // fill in blocks
        for (i, block) in unconfirmed_tenure.iter().enumerate().rev() {
            let res = utd
                .try_accept_unconfirmed_tenure_blocks(vec![block.clone()])
                .unwrap();
            if i == unconfirmed_tenure.len() - 5 {
                // got back only the blocks we were missing
                assert_eq!(
                    res.unwrap(),
                    unconfirmed_tenure[(unconfirmed_tenure.len() - 4)..].to_vec()
                );
                break;
            } else {
                assert!(res.is_none());
            }
        }

        assert_eq!(utd.state, NakamotoUnconfirmedDownloadState::Done);

        // we can request the highest-complete tenure
        assert!(!utd.need_highest_complete_tenure(peer.chainstate()).unwrap());

        let ntd = utd.make_highest_complete_tenure_downloader().unwrap();
        assert_eq!(
            ntd.state,
            NakamotoTenureDownloadState::GetTenureStartBlock(
                unconfirmed_wanted_tenure.winning_block_id.clone(),
                ntd.state.request_time().unwrap()
            )
        );
    }

    // we haven't processed anything yet.
    // serve all of the unconfirmed blocks in one shot.
    {
        let mut utd = NakamotoUnconfirmedTenureDownloader::new(naddr.clone(), None);
        utd.confirmed_signer_keys = Some(
            current_reward_sets
                .get(&tip_rc)
                .cloned()
                .unwrap()
                .reward_cycle_info
                .known_selected_anchor_block_owned()
                .unwrap(),
        );
        utd.unconfirmed_signer_keys = Some(
            current_reward_sets
                .get(&tip_rc)
                .cloned()
                .unwrap()
                .reward_cycle_info
                .known_selected_anchor_block_owned()
                .unwrap(),
        );

        assert_eq!(utd.state, NakamotoUnconfirmedDownloadState::GetTenureInfo);

        let tenure_tip = RPCGetTenureInfo {
            consensus_hash: peer.network.stacks_tip.consensus_hash.clone(),
            tenure_start_block_id: peer.network.tenure_start_block_id.clone(),
            parent_consensus_hash: peer.network.parent_stacks_tip.consensus_hash.clone(),
            parent_tenure_start_block_id: StacksBlockId::new(
                &peer.network.parent_stacks_tip.consensus_hash,
                &peer.network.parent_stacks_tip.block_hash,
            ),
            tip_block_id: StacksBlockId::new(
                &peer.network.stacks_tip.consensus_hash,
                &peer.network.stacks_tip.block_hash,
            ),
            tip_height: peer.network.stacks_tip.height,
            reward_cycle: tip_rc,
        };

        let sortdb = peer.sortdb.take().unwrap();
        let sort_tip = SortitionDB::get_canonical_burn_chain_tip(sortdb.conn()).unwrap();
        utd.try_accept_tenure_info(
            &sortdb,
            &sort_tip,
            peer.chainstate(),
            tenure_tip.clone(),
            &current_reward_sets,
        )
        .unwrap();

        peer.sortdb = Some(sortdb);

        assert!(utd.unconfirmed_tenure_start_block.is_some());

        let res = utd
            .try_accept_unconfirmed_tenure_blocks(
                unconfirmed_tenure.clone().into_iter().rev().collect(),
            )
            .unwrap();
        assert_eq!(res.unwrap(), unconfirmed_tenure);

        assert_eq!(utd.state, NakamotoUnconfirmedDownloadState::Done);

        // we can request the highest-complete tenure
        assert!(!utd.need_highest_complete_tenure(peer.chainstate()).unwrap());

        let ntd = utd.make_highest_complete_tenure_downloader().unwrap();
        assert_eq!(
            ntd.state,
            NakamotoTenureDownloadState::GetTenureStartBlock(
                unconfirmed_wanted_tenure.winning_block_id.clone(),
                ntd.state.request_time().unwrap()
            )
        );
    }

    // bad block signature
    {
        let mut utd = NakamotoUnconfirmedTenureDownloader::new(naddr.clone(), None);
        utd.confirmed_signer_keys = Some(
            current_reward_sets
                .get(&tip_rc)
                .cloned()
                .unwrap()
                .reward_cycle_info
                .known_selected_anchor_block_owned()
                .unwrap(),
        );
        utd.unconfirmed_signer_keys = Some(
            current_reward_sets
                .get(&tip_rc)
                .cloned()
                .unwrap()
                .reward_cycle_info
                .known_selected_anchor_block_owned()
                .unwrap(),
        );

        assert_eq!(utd.state, NakamotoUnconfirmedDownloadState::GetTenureInfo);

        let tenure_tip = RPCGetTenureInfo {
            consensus_hash: peer.network.stacks_tip.consensus_hash.clone(),
            tenure_start_block_id: peer.network.tenure_start_block_id.clone(),
            parent_consensus_hash: peer.network.parent_stacks_tip.consensus_hash.clone(),
            parent_tenure_start_block_id: StacksBlockId::new(
                &peer.network.parent_stacks_tip.consensus_hash,
                &peer.network.parent_stacks_tip.block_hash,
            ),
            tip_block_id: StacksBlockId::new(
                &peer.network.stacks_tip.consensus_hash,
                &peer.network.stacks_tip.block_hash,
            ),
            tip_height: peer.network.stacks_tip.height,
            reward_cycle: tip_rc,
        };

        let sortdb = peer.sortdb.take().unwrap();
        let sort_tip = SortitionDB::get_canonical_burn_chain_tip(sortdb.conn()).unwrap();
        utd.try_accept_tenure_info(
            &sortdb,
            &sort_tip,
            peer.chainstate(),
            tenure_tip.clone(),
            &current_reward_sets,
        )
        .unwrap();

        peer.sortdb = Some(sortdb);

        assert!(utd.unconfirmed_tenure_start_block.is_some());

        let mut bad_block = unconfirmed_tenure.last().cloned().unwrap();
        bad_block.header.version += 1;

        assert!(utd
            .try_accept_unconfirmed_tenure_blocks(vec![bad_block])
            .is_err());
    }

    // Does not consume blocks beyond the highest processed block ID
    {
        let mut utd = NakamotoUnconfirmedTenureDownloader::new(naddr.clone(), None);
        utd.confirmed_signer_keys = Some(
            current_reward_sets
                .get(&tip_rc)
                .cloned()
                .unwrap()
                .reward_cycle_info
                .known_selected_anchor_block_owned()
                .unwrap(),
        );
        utd.unconfirmed_signer_keys = Some(
            current_reward_sets
                .get(&tip_rc)
                .cloned()
                .unwrap()
                .reward_cycle_info
                .known_selected_anchor_block_owned()
                .unwrap(),
        );

        assert_eq!(utd.state, NakamotoUnconfirmedDownloadState::GetTenureInfo);

        let tenure_tip = RPCGetTenureInfo {
            consensus_hash: peer.network.stacks_tip.consensus_hash.clone(),
            tenure_start_block_id: peer.network.tenure_start_block_id.clone(),
            parent_consensus_hash: peer.network.parent_stacks_tip.consensus_hash.clone(),
            parent_tenure_start_block_id: StacksBlockId::new(
                &peer.network.parent_stacks_tip.consensus_hash,
                &peer.network.parent_stacks_tip.block_hash,
            ),
            tip_block_id: StacksBlockId::new(
                &peer.network.stacks_tip.consensus_hash,
                &peer.network.stacks_tip.block_hash,
            ),
            tip_height: peer.network.stacks_tip.height,
            reward_cycle: tip_rc,
        };

        let sortdb = peer.sortdb.take().unwrap();
        let sort_tip = SortitionDB::get_canonical_burn_chain_tip(sortdb.conn()).unwrap();
        utd.try_accept_tenure_info(
            &sortdb,
            &sort_tip,
            peer.chainstate(),
            tenure_tip.clone(),
            &current_reward_sets,
        )
        .unwrap();

        peer.sortdb = Some(sortdb);

        assert!(utd.unconfirmed_tenure_start_block.is_some());

        utd.highest_processed_block_id = Some(unconfirmed_tenure[1].header.block_id());
        let res = utd
            .try_accept_unconfirmed_tenure_blocks(
                unconfirmed_tenure.clone().into_iter().rev().collect(),
            )
            .unwrap();
        assert_eq!(res.unwrap().as_slice(), &unconfirmed_tenure[1..]);

        assert_eq!(utd.state, NakamotoUnconfirmedDownloadState::Done);

        // we can request the highest-complete tenure
        assert!(!utd.need_highest_complete_tenure(peer.chainstate()).unwrap());

        let ntd = utd.make_highest_complete_tenure_downloader().unwrap();
        assert_eq!(
            ntd.state,
            NakamotoTenureDownloadState::GetTenureStartBlock(
                unconfirmed_wanted_tenure.winning_block_id.clone(),
                ntd.state.request_time().unwrap()
            )
        );
    }
}

#[test]
fn test_tenure_start_end_from_inventory() {
    let naddr = NeighborAddress {
        addrbytes: PeerAddress([0xff; 16]),
        port: 123,
        public_key_hash: Hash160([0xff; 20]),
    };
    let rc_len = 12u16;
    let mut invs = NakamotoTenureInv::new(0, u64::from(rc_len), 0, naddr.clone());
    let pox_constants = PoxConstants::new(
        rc_len.into(),
        5,
        3,
        0,
        25,
        u64::MAX,
        u64::MAX,
        u32::MAX,
        u32::MAX,
        u32::MAX,
        u32::MAX,
    );
    let first_burn_height = 100u64;

    // make some invs
    let num_rcs = 6;
    invs.merge_tenure_inv(
        BitVec::<2100>::try_from(
            vec![
                true, true, true, true, true, true, true, true, true, true, true, true,
            ]
            .as_slice(),
        )
        .unwrap(),
        0,
    );
    invs.merge_tenure_inv(
        BitVec::<2100>::try_from(
            vec![
                false, false, false, false, false, false, false, true, true, true, false, false,
            ]
            .as_slice(),
        )
        .unwrap(),
        1,
    );
    invs.merge_tenure_inv(
        BitVec::<2100>::try_from(
            vec![
                true, false, false, false, false, false, false, true, true, true, false, true,
            ]
            .as_slice(),
        )
        .unwrap(),
        2,
    );
    invs.merge_tenure_inv(
        BitVec::<2100>::try_from(
            vec![
                true, false, true, false, true, false, true, true, true, true, true, false,
            ]
            .as_slice(),
        )
        .unwrap(),
        3,
    );
    invs.merge_tenure_inv(
        BitVec::<2100>::try_from(
            vec![
                false, true, false, true, false, true, true, true, true, true, false, true,
            ]
            .as_slice(),
        )
        .unwrap(),
        4,
    );
    invs.merge_tenure_inv(
        BitVec::<2100>::try_from(
            vec![
                false, false, true, true, true, true, true, true, true, true, true, true,
            ]
            .as_slice(),
        )
        .unwrap(),
        5,
    );

    let mut wanted_tenures = vec![];
    let mut next_wanted_tenures = vec![];
    for i in 0..rc_len {
        wanted_tenures.push(WantedTenure::new(
            ConsensusHash([i as u8; 20]),
            StacksBlockId([i as u8; 32]),
            u64::from(i) + first_burn_height + 1,
        ));
        next_wanted_tenures.push(WantedTenure::new(
            ConsensusHash([(i + 128) as u8; 20]),
            StacksBlockId([(i + 128) as u8; 32]),
            u64::from(i) + first_burn_height + 1,
        ));
    }
    let mut all_tenures = wanted_tenures.clone();
    all_tenures.append(&mut next_wanted_tenures.clone());

    // check the case where we only have one Nakamoto rewrad cycle
    for rc in 0..num_rcs {
        let available = TenureStartEnd::from_inventory(
            rc,
            &wanted_tenures,
            None,
            &pox_constants,
            first_burn_height,
            &invs,
        )
        .unwrap();
        let bits = invs.tenures_inv.get(&rc).unwrap();
        for (i, wt) in wanted_tenures.iter().enumerate() {
            if i >= (rc_len - 1).into() {
                // nothing here
                assert!(!available.contains_key(&wt.tenure_id_consensus_hash));
                continue;
            }

            let tenure_start_end_opt = available.get(&wt.tenure_id_consensus_hash);
            if bits.get(i as u16).unwrap() {
                // this sortition had a tenure
                let mut j = (i + 1) as u16;
                let mut tenure_start_index = None;
                let mut tenure_end_index = None;

                while j < bits.len() {
                    if bits.get(j).unwrap() {
                        tenure_start_index = Some(j);
                        j += 1;
                        break;
                    }
                    j += 1;
                }

                while j < bits.len() {
                    if bits.get(j).unwrap() {
                        tenure_end_index = Some(j);
                        break;
                    }
                    j += 1;
                }

                if tenure_start_index.is_some() && tenure_end_index.is_some() {
                    let tenure_start_end = tenure_start_end_opt.unwrap();
                    assert_eq!(
                        wanted_tenures[tenure_start_index.unwrap() as usize].winning_block_id,
                        tenure_start_end.start_block_id
                    );
                    assert_eq!(
                        wanted_tenures[tenure_end_index.unwrap() as usize].winning_block_id,
                        tenure_start_end.end_block_id
                    );
                } else {
                    assert!(tenure_start_end_opt.is_none());
                }
            } else {
                // no tenure here
                assert!(
                    tenure_start_end_opt.is_none(),
                    "{}",
                    format!(
                        "tenure_start_end = {:?}, rc = {}, i = {}, wt = {:?}",
                        &tenure_start_end_opt, rc, i, &wt
                    )
                );
            }
        }
    }

    // check the case where we have at least two Nakamoto rewrad cycles.
    // the available tenures should straddle the reward cycle boundary.
    for rc in 0..(num_rcs - 1) {
        debug!("rc = {}", rc);
        let available = TenureStartEnd::from_inventory(
            rc,
            &wanted_tenures,
            Some(&next_wanted_tenures),
            &pox_constants,
            first_burn_height,
            &invs,
        )
        .unwrap();

        // need to check across two reward cycles
        let bits_cur_rc = invs.tenures_inv.get(&rc).unwrap();
        let bits_next_rc = invs.tenures_inv.get(&(rc + 1)).unwrap();
        let mut bits = BitVec::<2100>::zeros(rc_len * 2).unwrap();
        for i in 0..rc_len {
            if bits_cur_rc.get(i).unwrap() {
                bits.set(i, true).unwrap();
            }
            if bits_next_rc.get(i).unwrap() {
                bits.set(i + rc_len, true).unwrap();
            }
        }

        for (i, wt) in wanted_tenures.iter().enumerate() {
            let tenure_start_end_opt = available.get(&wt.tenure_id_consensus_hash);
            if bits
                .get(i as u16)
                .expect(&format!("failed to get bit {}: {:?}", i, &wt))
            {
                // this sortition had a tenure
                let mut j = (i + 1) as u16;
                let mut tenure_start_index = None;
                let mut tenure_end_index = None;

                while j < bits.len() {
                    if bits.get(j).unwrap() {
                        tenure_start_index = Some(j);
                        j += 1;
                        break;
                    }
                    j += 1;
                }

                while j < bits.len() {
                    if bits.get(j).unwrap() {
                        tenure_end_index = Some(j);
                        break;
                    }
                    j += 1;
                }

                if tenure_start_index.is_some() && tenure_end_index.is_some() {
                    debug!(
                        "rc = {}, i = {}, tenure_start_index = {:?}, tenure_end_index = {:?}",
                        rc, i, &tenure_start_index, &tenure_end_index
                    );
                    let tenure_start_end = tenure_start_end_opt.expect(&format!(
                        "failed to get tenure_start_end_opt: i = {}, wt = {:?}",
                        i, &wt
                    ));
                    assert_eq!(
                        all_tenures[tenure_start_index.unwrap() as usize].winning_block_id,
                        tenure_start_end.start_block_id
                    );
                    assert_eq!(
                        all_tenures[tenure_end_index.unwrap() as usize].winning_block_id,
                        tenure_start_end.end_block_id
                    );
                } else {
                    assert!(tenure_start_end_opt.is_none());
                }
            } else {
                // no tenure here
                assert!(
                    tenure_start_end_opt.is_none(),
                    "{}",
                    format!(
                        "tenure_start_end = {:?}, rc = {}, i = {}, wt = {:?}",
                        &tenure_start_end_opt, rc, i, &wt
                    )
                );
            }
        }
    }
}

/// Test all of the functionality needed to transform a peer's reported tenure inventory into a
/// tenure downloader and download schedule.
#[test]
fn test_make_tenure_downloaders() {
    let observer = TestEventObserver::new();
    let bitvecs = vec![vec![
        true, true, true, true, true, true, true, true, true, true,
    ]];

    let rc_len = 10u64;
    let peer = make_nakamoto_peer_from_invs(
        function_name!(),
        &observer,
        rc_len as u32,
        3,
        bitvecs.clone(),
    );
    let (mut peer, reward_cycle_invs) =
        peer_get_nakamoto_invs(peer, &[0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12]);

    let nakamoto_start =
        NakamotoBootPlan::nakamoto_first_tenure_height(&peer.config.burnchain.pox_constants);

    let all_sortitions = peer.sortdb().get_all_snapshots().unwrap();
    let tip = SortitionDB::get_canonical_burn_chain_tip(peer.sortdb().conn()).unwrap();

    assert_eq!(tip.block_height, 51);

    let test_signers = TestSigners::new(vec![]);
    let current_reward_sets = peer.network.current_reward_sets.clone();
    let stacks_tip = peer.network.stacks_tip.block_id();

    // test load_wanted_tenures()
    {
        let ih = peer.sortdb().index_handle(&tip.sortition_id);
        let wanted_tenures = NakamotoDownloadStateMachine::load_wanted_tenures(
            &ih,
            tip.block_height - rc_len,
            tip.block_height,
        )
        .unwrap();
        assert_eq!(wanted_tenures.len(), rc_len as usize);

        for i in (tip.block_height - rc_len)..tip.block_height {
            let w = (i - (tip.block_height - rc_len)) as usize;
            let i = i as usize;
            assert_eq!(
                wanted_tenures[w].tenure_id_consensus_hash,
                all_sortitions[i].consensus_hash
            );
            assert_eq!(
                wanted_tenures[w].winning_block_id.0,
                all_sortitions[i].winning_stacks_block_hash.0
            );
            assert_eq!(wanted_tenures[w].processed, false);
        }

        let Err(NetError::DBError(DBError::NotFoundError)) =
            NakamotoDownloadStateMachine::load_wanted_tenures(
                &ih,
                tip.block_height + 1,
                tip.block_height + 2,
            )
        else {
            panic!()
        };

        let wanted_tenures = NakamotoDownloadStateMachine::load_wanted_tenures(
            &ih,
            tip.block_height + 3,
            tip.block_height,
        )
        .unwrap();
        assert_eq!(wanted_tenures.len(), 0);
    }

    // test load_wanted_tenures_for_reward_cycle
    {
        let sortdb = peer.sortdb();
        let rc = sortdb
            .pox_constants
            .block_height_to_reward_cycle(sortdb.first_block_height, tip.block_height)
            .unwrap()
            - 1;
        let wanted_tenures = NakamotoDownloadStateMachine::load_wanted_tenures_for_reward_cycle(
            rc,
            &tip,
            peer.sortdb(),
        )
        .unwrap();
        assert_eq!(wanted_tenures.len(), rc_len as usize);

        for i in (tip.block_height - 1 - rc_len)..(tip.block_height - 1) {
            let w = (i - (tip.block_height - 1 - rc_len)) as usize;
            let i = i as usize;
            assert_eq!(
                wanted_tenures[w].tenure_id_consensus_hash,
                all_sortitions[i].consensus_hash
            );
            assert_eq!(
                wanted_tenures[w].winning_block_id.0,
                all_sortitions[i].winning_stacks_block_hash.0
            );
            assert_eq!(wanted_tenures[w].processed, false);
        }

        let Err(NetError::DBError(DBError::NotFoundError)) =
            NakamotoDownloadStateMachine::load_wanted_tenures_for_reward_cycle(
                rc + 1,
                &tip,
                peer.sortdb(),
            )
        else {
            panic!()
        };
    }

    // test load_wanted_tenures_at_tip
    {
        let sortdb = peer.sortdb();
        let wanted_tenures =
            NakamotoDownloadStateMachine::load_wanted_tenures_at_tip(None, &tip, sortdb, &[])
                .unwrap();
        assert_eq!(wanted_tenures.len(), 2);
        for i in (tip.block_height - 1)..=(tip.block_height) {
            let w = (i - (tip.block_height - 1)) as usize;
            let i = i as usize;
            assert_eq!(
                wanted_tenures[w].tenure_id_consensus_hash,
                all_sortitions[i].consensus_hash
            );
            assert_eq!(
                wanted_tenures[w].winning_block_id.0,
                all_sortitions[i].winning_stacks_block_hash.0
            );
            assert_eq!(wanted_tenures[w].processed, false);
        }

        let all_wanted_tenures = wanted_tenures;
        let wanted_tenures = NakamotoDownloadStateMachine::load_wanted_tenures_at_tip(
            None,
            &tip,
            sortdb,
            &[all_wanted_tenures[0].clone()],
        )
        .unwrap();
        assert_eq!(wanted_tenures.len(), 1);

        assert_eq!(
            wanted_tenures[0].tenure_id_consensus_hash,
            all_sortitions[tip.block_height as usize].consensus_hash
        );
        assert_eq!(
            wanted_tenures[0].winning_block_id.0,
            all_sortitions[tip.block_height as usize]
                .winning_stacks_block_hash
                .0
        );
        assert_eq!(wanted_tenures[0].processed, false);

        let wanted_tenures = NakamotoDownloadStateMachine::load_wanted_tenures_at_tip(
            None,
            &tip,
            sortdb,
            &all_wanted_tenures,
        )
        .unwrap();
        assert_eq!(wanted_tenures.len(), 0);
    }

    // test inner_update_processed_wanted_tenures
    {
        let sortdb = peer.sortdb();
        let ih = peer.sortdb().index_handle(&tip.sortition_id);
        let mut wanted_tenures = NakamotoDownloadStateMachine::load_wanted_tenures(
            &ih,
            nakamoto_start,
            tip.block_height,
        )
        .unwrap();

        let nakamoto_tip = peer.network.stacks_tip.block_id();
        let chainstate = peer.chainstate();
        NakamotoDownloadStateMachine::inner_update_processed_wanted_tenures(
            nakamoto_start,
            &mut wanted_tenures,
            chainstate,
            &nakamoto_tip,
        )
        .unwrap();

        for wt in wanted_tenures {
            if !wt.processed {
                warn!("not processed: {:?}", &wt);
            }
            assert!(wt.processed);
        }
    }

    // test find_available_tenures
    {
        // test for reward cycle
        let sortdb = peer.sortdb();
        let rc = sortdb
            .pox_constants
            .block_height_to_reward_cycle(sortdb.first_block_height, tip.block_height)
            .unwrap()
            - 1;
        let rc_wanted_tenures =
            NakamotoDownloadStateMachine::load_wanted_tenures_for_reward_cycle(rc, &tip, sortdb)
                .unwrap();
        assert_eq!(rc_wanted_tenures.len(), rc_len as usize);

        // also test for tip
        let tip_wanted_tenures =
            NakamotoDownloadStateMachine::load_wanted_tenures_at_tip(None, &tip, sortdb, &[])
                .unwrap();

        let naddr = NeighborAddress {
            addrbytes: PeerAddress([0xff; 16]),
            port: 123,
            public_key_hash: Hash160([0xff; 20]),
        };

        // full invs
        let mut full_invs = NakamotoTenureInv::new(0, rc_len, 0, naddr.clone());
        full_invs.merge_tenure_inv(
            BitVec::<2100>::try_from(
                vec![
                    true, true, true, true, true, true, true, true, true, true, true, true,
                ]
                .as_slice(),
            )
            .unwrap(),
            rc,
        );

        let mut full_inventories = HashMap::new();
        full_inventories.insert(naddr.clone(), full_invs.clone());

        let available = NakamotoDownloadStateMachine::find_available_tenures(
            rc,
            &rc_wanted_tenures,
            full_inventories.iter(),
        );
        assert_eq!(available.len(), rc_len as usize);
        for wt in rc_wanted_tenures.iter() {
            assert_eq!(
                available.get(&wt.tenure_id_consensus_hash).unwrap(),
                &vec![naddr.clone()]
            );
        }

        // sparse invs
        let mut sparse_invs = NakamotoTenureInv::new(0, rc_len, 0, naddr.clone());
        sparse_invs.merge_tenure_inv(
            BitVec::<2100>::try_from(
                vec![
                    false, true, false, true, false, true, false, true, false, true, false, true,
                ]
                .as_slice(),
            )
            .unwrap(),
            rc,
        );

        let mut sparse_inventories = HashMap::new();
        sparse_inventories.insert(naddr.clone(), sparse_invs.clone());

        let available = NakamotoDownloadStateMachine::find_available_tenures(
            rc,
            &rc_wanted_tenures,
            sparse_inventories.iter(),
        );
        assert_eq!(available.len(), rc_len as usize);
        for (i, wt) in rc_wanted_tenures.iter().enumerate() {
            if i % 2 == 0 {
                assert_eq!(
                    available.get(&wt.tenure_id_consensus_hash).unwrap(),
                    &vec![]
                );
            } else {
                assert_eq!(
                    available.get(&wt.tenure_id_consensus_hash).unwrap(),
                    &vec![naddr.clone()]
                );
            }
        }

        // no invs
        let available = NakamotoDownloadStateMachine::find_available_tenures(
            rc + 1,
            &rc_wanted_tenures,
            full_inventories.iter(),
        );
        assert_eq!(available.len(), rc_len as usize);

        // tip full invs
        full_invs.merge_tenure_inv(
            BitVec::<2100>::try_from(
                vec![
                    true, true, true, true, true, true, true, true, true, true, true, true,
                ]
                .as_slice(),
            )
            .unwrap(),
            rc + 1,
        );
        full_inventories.insert(naddr.clone(), full_invs.clone());

        let available = NakamotoDownloadStateMachine::find_available_tenures(
            rc + 1,
            &tip_wanted_tenures,
            full_inventories.iter(),
        );
        assert_eq!(available.len(), tip_wanted_tenures.len());
        for wt in tip_wanted_tenures.iter() {
            assert_eq!(
                available.get(&wt.tenure_id_consensus_hash).unwrap(),
                &vec![naddr.clone()]
            );
        }

        // tip sparse invs
        sparse_invs.merge_tenure_inv(
            BitVec::<2100>::try_from(
                vec![
                    false, true, false, true, false, true, false, true, false, true, false, true,
                ]
                .as_slice(),
            )
            .unwrap(),
            rc + 1,
        );
        sparse_inventories.insert(naddr.clone(), sparse_invs.clone());

        let available = NakamotoDownloadStateMachine::find_available_tenures(
            rc + 1,
            &tip_wanted_tenures,
            sparse_inventories.iter(),
        );
        assert_eq!(available.len(), tip_wanted_tenures.len());
        for (i, wt) in tip_wanted_tenures.iter().enumerate() {
            if i % 2 == 0 {
                assert_eq!(
                    available.get(&wt.tenure_id_consensus_hash).unwrap(),
                    &vec![]
                );
            } else {
                assert_eq!(
                    available.get(&wt.tenure_id_consensus_hash).unwrap(),
                    &vec![naddr.clone()]
                );
            }
        }
    }

    // test find_tenure_block_ids
    {
        let sortdb = peer.sortdb();
        let rc = sortdb
            .pox_constants
            .block_height_to_reward_cycle(sortdb.first_block_height, tip.block_height)
            .unwrap()
            - 1;
        let pox_constants = sortdb.pox_constants.clone();
        let first_burn_height = sortdb.first_block_height;

        let rc_wanted_tenures =
            NakamotoDownloadStateMachine::load_wanted_tenures_for_reward_cycle(rc, &tip, sortdb)
                .unwrap();
        assert_eq!(rc_wanted_tenures.len(), rc_len as usize);

        let tip_wanted_tenures =
            NakamotoDownloadStateMachine::load_wanted_tenures_at_tip(None, &tip, sortdb, &[])
                .unwrap();

        let naddr = NeighborAddress {
            addrbytes: PeerAddress([0xff; 16]),
            port: 123,
            public_key_hash: Hash160([0xff; 20]),
        };

        let mut full_invs = NakamotoTenureInv::new(0, rc_len, 0, naddr.clone());

        full_invs.merge_tenure_inv(
            BitVec::<2100>::try_from(
                vec![
                    true, true, true, true, true, true, true, true, true, true, true, true,
                ]
                .as_slice(),
            )
            .unwrap(),
            rc,
        );
        full_invs.merge_tenure_inv(
            BitVec::<2100>::try_from(
                vec![
                    true, true, true, true, true, true, true, true, true, true, true, true,
                ]
                .as_slice(),
            )
            .unwrap(),
            rc + 1,
        );

        let mut full_inventories = HashMap::new();
        full_inventories.insert(naddr.clone(), full_invs.clone());

        let tenure_block_ids = NakamotoDownloadStateMachine::find_tenure_block_ids(
            rc,
            &rc_wanted_tenures,
            Some(&tip_wanted_tenures),
            &pox_constants,
            first_burn_height,
            full_inventories.iter(),
        );
        assert_eq!(tenure_block_ids.len(), 1);

        let available_tenures = tenure_block_ids.get(&naddr).unwrap();

        // every tenure in rc_wanted_tenures maps to a start/end
        for (i, wt) in rc_wanted_tenures.iter().enumerate() {
            let start_end = available_tenures.get(&wt.tenure_id_consensus_hash).unwrap();
            if i + 1 < rc_wanted_tenures.len() {
                assert_eq!(
                    start_end.start_block_id,
                    rc_wanted_tenures[i + 1].winning_block_id
                );
            } else {
                assert_eq!(
                    start_end.start_block_id,
                    tip_wanted_tenures[i - (rc_wanted_tenures.len() - 1)].winning_block_id
                );
            }
            if i + 2 < rc_wanted_tenures.len() {
                assert_eq!(
                    start_end.end_block_id,
                    rc_wanted_tenures[i + 2].winning_block_id
                );
            } else {
                assert_eq!(
                    start_end.end_block_id,
                    tip_wanted_tenures[i - (rc_wanted_tenures.len() - 2)].winning_block_id
                );
            }
        }

        // the tenure-start blocks correspond to the wanted tenure ID consensus hash
        for (i, wt) in rc_wanted_tenures.iter().enumerate() {
            // this may be before epoch 3.0
            let sortdb = peer.sortdb();
            let sn = SortitionDB::get_block_snapshot_consensus(
                sortdb.conn(),
                &wt.tenure_id_consensus_hash,
            )
            .unwrap()
            .unwrap();
            if sn.block_height < nakamoto_start {
                continue;
            }

            let chainstate = peer.chainstate();
            let start_end = available_tenures.get(&wt.tenure_id_consensus_hash).unwrap();
            let hdr = NakamotoChainState::get_nakamoto_tenure_start_block_header(
                &mut chainstate.index_conn(),
                &stacks_tip,
                &wt.tenure_id_consensus_hash,
            )
            .unwrap()
            .unwrap();
            assert_eq!(hdr.index_block_hash(), start_end.start_block_id);
        }

        // none of the tip ones do, since there are only two
        let tenure_block_ids = NakamotoDownloadStateMachine::find_tenure_block_ids(
            rc + 1,
            &tip_wanted_tenures,
            None,
            &pox_constants,
            first_burn_height,
            full_inventories.iter(),
        );
        assert_eq!(tenure_block_ids.len(), 1);

        let available_tenures = tenure_block_ids.get(&naddr).unwrap();
        assert_eq!(available_tenures.len(), 0);
    }

    // test make_ibd_download_schedule
    // test make_rarest_first_download_schedule
    {
        let sortdb = peer.sortdb();
        let rc = sortdb
            .pox_constants
            .block_height_to_reward_cycle(sortdb.first_block_height, tip.block_height)
            .unwrap()
            - 1;
        let rc_wanted_tenures =
            NakamotoDownloadStateMachine::load_wanted_tenures_for_reward_cycle(rc, &tip, sortdb)
                .unwrap();
        assert_eq!(rc_wanted_tenures.len(), rc_len as usize);

        let mut available: HashMap<ConsensusHash, Vec<NeighborAddress>> = HashMap::new();
        for (i, wt) in rc_wanted_tenures.iter().enumerate() {
            for j in i..(rc_len as usize) {
                let naddr = NeighborAddress {
                    addrbytes: PeerAddress([0xff; 16]),
                    port: (i * (rc_len as usize) + j + 123) as u16,
                    public_key_hash: Hash160([0xff; 20]),
                };
                if let Some(addrs) = available.get_mut(&wt.tenure_id_consensus_hash) {
                    addrs.push(naddr);
                } else {
                    available.insert(wt.tenure_id_consensus_hash.clone(), vec![naddr]);
                }
            }
        }

        // sanity check -- the ith wanted tenure is available from rc_len - i neighbors
        for (i, wt) in rc_wanted_tenures.iter().enumerate() {
            let addrs = available.get(&wt.tenure_id_consensus_hash).unwrap();
            assert_eq!(addrs.len(), (rc_len as usize) - i);
        }

        // check full schedule -- assume nakamoto_start is 0
        let ibd_schedule = NakamotoDownloadStateMachine::make_ibd_download_schedule(
            0,
            &rc_wanted_tenures,
            &available,
        );
        assert_eq!(ibd_schedule.len(), rc_len as usize);
        for (i, ch) in ibd_schedule.iter().enumerate() {
            // in IBD, we download in sortiiton order
            assert_eq!(&rc_wanted_tenures[i].tenure_id_consensus_hash, ch);
        }

        // check full schedule -- assume nakamoto_start is 0
        let rarest_first_schedule =
            NakamotoDownloadStateMachine::make_rarest_first_download_schedule(
                0,
                &rc_wanted_tenures,
                &available,
            );
        assert_eq!(rarest_first_schedule.len(), rc_len as usize);
        for (i, ch) in rarest_first_schedule.iter().enumerate() {
            // in steady-state, we download in rarest-first order.
            // Per the above sanity check, this would be in reverse order due to the way we
            // constructed `available`.
            assert_eq!(
                &rc_wanted_tenures[(rc_len as usize) - i - 1].tenure_id_consensus_hash,
                ch
            );
        }

        // check partial schedule -- assume nakamoto_start is not 0
        let ibd_schedule = NakamotoDownloadStateMachine::make_ibd_download_schedule(
            nakamoto_start,
            &rc_wanted_tenures,
            &available,
        );
        let offset = (nakamoto_start % rc_len) as usize;
        assert_eq!(ibd_schedule.len(), (rc_len as usize) - offset);
        for (i, ch) in ibd_schedule.iter().enumerate() {
            // in IBD, we download in sortiiton order
            assert_eq!(&rc_wanted_tenures[i + offset].tenure_id_consensus_hash, ch);
            assert!(rc_wanted_tenures[i + offset].burn_height >= nakamoto_start);
        }

        // check partial schedule -- assume nakamoto_start is not 0
        let rarest_first_schedule =
            NakamotoDownloadStateMachine::make_rarest_first_download_schedule(
                nakamoto_start,
                &rc_wanted_tenures,
                &available,
            );
        assert_eq!(rarest_first_schedule.len(), (rc_len as usize) - offset);
        for (i, ch) in rarest_first_schedule.iter().enumerate() {
            // in steady-state, we download in rarest-first order.
            // Per the above sanity check, this would be in reverse order due to the way we
            // constructed `available`.
            assert_eq!(
                &rc_wanted_tenures[(rc_len as usize) - 1 - i].tenure_id_consensus_hash,
                ch
            );
            assert!(rc_wanted_tenures[i + offset].burn_height >= nakamoto_start);
        }
    }

    // test make_tenure_downloaders
    {
        let mut downloaders = NakamotoTenureDownloaderSet::new();

        let sortdb = peer.sortdb();
        let rc = sortdb
            .pox_constants
            .block_height_to_reward_cycle(sortdb.first_block_height, tip.block_height)
            .unwrap()
            - 1;
        let rc_wanted_tenures =
            NakamotoDownloadStateMachine::load_wanted_tenures_for_reward_cycle(rc, &tip, sortdb)
                .unwrap();
        assert_eq!(rc_wanted_tenures.len(), rc_len as usize);

        let tip_wanted_tenures =
            NakamotoDownloadStateMachine::load_wanted_tenures_at_tip(None, &tip, sortdb, &[])
                .unwrap();

        let naddr = NeighborAddress {
            addrbytes: PeerAddress([0xff; 16]),
            port: 123,
            public_key_hash: Hash160([0xff; 20]),
        };

        let mut full_invs = NakamotoTenureInv::new(0, rc_len, 0, naddr.clone());

        full_invs.merge_tenure_inv(
            BitVec::<2100>::try_from(
                vec![
                    true, true, true, true, true, true, true, true, true, true, true, true,
                ]
                .as_slice(),
            )
            .unwrap(),
            rc,
        );
        full_invs.merge_tenure_inv(
            BitVec::<2100>::try_from(
                vec![
                    true, true, true, true, true, true, true, true, true, true, true, true,
                ]
                .as_slice(),
            )
            .unwrap(),
            rc + 1,
        );

        let mut full_inventories = HashMap::new();
        full_inventories.insert(naddr.clone(), full_invs.clone());

        let mut tenure_block_ids = NakamotoDownloadStateMachine::find_tenure_block_ids(
            rc,
            &rc_wanted_tenures,
            Some(&tip_wanted_tenures),
            &sortdb.pox_constants,
            sortdb.first_block_height,
            full_inventories.iter(),
        );
        assert_eq!(tenure_block_ids.len(), 1);

        let availability = tenure_block_ids.get(&naddr).cloned().unwrap();

        let mut available: HashMap<ConsensusHash, Vec<NeighborAddress>> = HashMap::new();
        let mut available_by_index = vec![];
        for (i, wt) in rc_wanted_tenures.iter().enumerate() {
            for j in i..=(rc_len as usize) {
                let naddr = NeighborAddress {
                    addrbytes: PeerAddress([0xff; 16]),
                    port: (i * (rc_len as usize) + j + 123) as u16,
                    public_key_hash: Hash160([0xff; 20]),
                };

                // expand availability -- each neighbor has the same invs
                tenure_block_ids.insert(naddr.clone(), availability.clone());

                if let Some(addrs) = available.get_mut(&wt.tenure_id_consensus_hash) {
                    addrs.push(naddr);
                } else {
                    available.insert(wt.tenure_id_consensus_hash.clone(), vec![naddr]);
                }
            }
            available_by_index.push(
                available
                    .get(&wt.tenure_id_consensus_hash)
                    .cloned()
                    .unwrap(),
            );
        }

        // sanity check -- the ith wanted tenure is available from rc_len - i neighbors
        for (i, wt) in rc_wanted_tenures.iter().enumerate() {
            let addrs = available.get(&wt.tenure_id_consensus_hash).unwrap();
            assert_eq!(addrs.len(), (rc_len as usize) - i + 1);
        }

        // pretend nakamoto_start is 0 for now, so we can treat this like a full reward cycle
        let mut ibd_schedule = NakamotoDownloadStateMachine::make_ibd_download_schedule(
            0,
            &rc_wanted_tenures,
            &available,
        );

        let old_schedule = ibd_schedule.clone();
        let sched_len = ibd_schedule.len();

        // make 6 downloaders
        downloaders.make_tenure_downloaders(
            &mut ibd_schedule,
            &mut available,
            &tenure_block_ids,
            6,
            &current_reward_sets,
        );

        // made all 6 downloaders
        assert_eq!(ibd_schedule.len() + 6, sched_len);
        assert_eq!(downloaders.downloaders.len(), 6);
        for (i, wt) in rc_wanted_tenures.iter().enumerate() {
            let naddrs = available.get(&wt.tenure_id_consensus_hash).unwrap();
            if i < 6 {
                assert_eq!(naddrs.len(), (rc_len as usize) - i);
            } else {
                assert_eq!(naddrs.len(), (rc_len as usize) - i + 1);
            }
        }

        for (i, wt) in rc_wanted_tenures.iter().enumerate() {
            let possible_addrs = available_by_index.get(i).unwrap();
            let mut found = false;
            for addr in possible_addrs.iter() {
                if downloaders.has_downloader(addr) {
                    found = true;
                    break;
                }
            }

            if i < 6 {
                assert!(found);
            } else {
                assert!(!found);
            }
        }

        // make 6 more downloaders
        downloaders.make_tenure_downloaders(
            &mut ibd_schedule,
            &mut available,
            &tenure_block_ids,
            12,
            &current_reward_sets,
        );

        // only made 4 downloaders got created
        assert_eq!(ibd_schedule.len(), 0);
        assert_eq!(downloaders.downloaders.len(), 10);
        for (i, wt) in rc_wanted_tenures.iter().enumerate() {
            let naddrs = available.get(&wt.tenure_id_consensus_hash).unwrap();
            assert_eq!(naddrs.len(), (rc_len as usize) - i);
        }

        for (i, wt) in rc_wanted_tenures.iter().enumerate() {
            let possible_addrs = available_by_index.get(i).unwrap();
            let mut found = false;
            for addr in possible_addrs.iter() {
                if downloaders.has_downloader(addr) {
                    found = true;
                    break;
                }
            }

            assert!(found);
        }
    }
}

#[test]
fn test_nakamoto_download_run_2_peers() {
    let observer = TestEventObserver::new();
    let bitvecs = vec![
        // a reward cycle with one prepare phase sortition at the start
        vec![
            true, true, true, true, true, true, true, false, false, false,
        ],
        // a reward cycle with one prepare phase sortition at the end,
        // and no tenures in the first three reward phase sortitions
        vec![
            false, false, false, true, true, false, false, true, true, false,
        ],
        // full reward cycle, minus the first three tenures
        vec![
            false, false, false, true, true, true, true, true, true, true,
        ],
        // full reward cycle
        vec![true, true, true, true, true, true, true, true, true, true],
        // alternating reward cycle, but with a full prepare phase
        vec![true, false, true, false, true, true, true, true, true, true],
        // minimum viable reward cycle -- empty reward phase, an anchor block sortition, and two subsequent
        // sortitions to ensure that the anchor block's start/end blocks are written to the burnchain.
        vec![
            false, false, false, false, true, true, false, true, false, false,
        ],
        // a long period of no sortitions that spans a reward cycle boundary
        vec![false, false, true, true, true, true, true, true, true, true],
    ];

    let rc_len = 10u64;
    let peer = make_nakamoto_peer_from_invs(
        function_name!(),
        &observer,
        rc_len as u32,
        5,
        bitvecs.clone(),
    );
    let (mut peer, reward_cycle_invs) =
        peer_get_nakamoto_invs(peer, &[0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12]);

    let nakamoto_start =
        NakamotoBootPlan::nakamoto_first_tenure_height(&peer.config.burnchain.pox_constants);

    let all_sortitions = peer.sortdb().get_all_snapshots().unwrap();
    let tip = SortitionDB::get_canonical_burn_chain_tip(peer.sortdb().conn()).unwrap();
    let nakamoto_tip = peer
        .sortdb()
        .index_handle(&tip.sortition_id)
        .get_nakamoto_tip_block_id()
        .unwrap()
        .unwrap();
    assert_eq!(
        tip.block_height,
        41 + bitvecs.iter().map(|x| x.len() as u64).sum::<u64>()
    );

    // make a neighbor from this peer
    let boot_observer = TestEventObserver::new();
    let privk = StacksPrivateKey::from_seed(&[0, 1, 2, 3, 4]);
    let mut boot_peer = peer.neighbor_with_observer(privk, Some(&boot_observer));

    let (canonical_stacks_tip_ch, canonical_stacks_tip_bhh) =
        SortitionDB::get_canonical_stacks_chain_tip_hash(peer.sortdb().conn()).unwrap();

    // boot up the boot peer's burnchain
    for height in 25..tip.block_height {
        let ops = peer
            .get_burnchain_block_ops_at_height(height + 1)
            .unwrap_or(vec![]);
        let sn = {
            let ih = peer.sortdb().index_handle(&tip.sortition_id);
            let sn = ih.get_block_snapshot_by_height(height).unwrap().unwrap();
            sn
        };
        test_debug!(
            "boot_peer tip height={} hash={}",
            sn.block_height,
            &sn.burn_header_hash
        );
        test_debug!("ops = {:?}", &ops);
        let block_header = TestPeer::make_next_burnchain_block(
            &boot_peer.config.burnchain,
            sn.block_height,
            &sn.burn_header_hash,
            ops.len() as u64,
            false,
        );
        TestPeer::add_burnchain_block(&boot_peer.config.burnchain, &block_header, ops.clone());
    }

    let (mut boot_dns_client, boot_dns_thread_handle) = dns_thread_start(100);

    // start running that peer so we can boot off of it
    let (term_sx, term_rx) = sync_channel(1);
    thread::scope(|s| {
        s.spawn(move || {
            let (mut last_stacks_tip_ch, mut last_stacks_tip_bhh) =
                SortitionDB::get_canonical_stacks_chain_tip_hash(boot_peer.sortdb().conn())
                    .unwrap();
            loop {
                boot_peer
                    .run_with_ibd(true, Some(&mut boot_dns_client))
                    .unwrap();

                let (stacks_tip_ch, stacks_tip_bhh) =
                    SortitionDB::get_canonical_stacks_chain_tip_hash(boot_peer.sortdb().conn())
                        .unwrap();

                last_stacks_tip_ch = stacks_tip_ch;
                last_stacks_tip_bhh = stacks_tip_bhh;

                debug!(
                    "Booting peer's stacks tip is now {:?}",
                    &boot_peer.network.stacks_tip
                );
                if stacks_tip_ch == canonical_stacks_tip_ch
                    && stacks_tip_bhh == canonical_stacks_tip_bhh
                {
                    break;
                }
            }

            term_sx.send(()).unwrap();
        });

        loop {
            if term_rx.try_recv().is_ok() {
                break;
            }
            peer.step_with_ibd(false).unwrap();
        }
    });

    boot_dns_thread_handle.join().unwrap();
}

#[test]
fn test_nakamoto_unconfirmed_download_run_2_peers() {
    let observer = TestEventObserver::new();
    let bitvecs = vec![
        // full reward cycle
        vec![true, true, true, true, true, true, true, true, true, true],
    ];

    let rc_len = 10u64;
    let peer = make_nakamoto_peer_from_invs(
        function_name!(),
        &observer,
        rc_len as u32,
        5,
        bitvecs.clone(),
    );
    let (mut peer, reward_cycle_invs) =
        peer_get_nakamoto_invs(peer, &[0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12]);

    let nakamoto_start =
        NakamotoBootPlan::nakamoto_first_tenure_height(&peer.config.burnchain.pox_constants);

    let all_sortitions = peer.sortdb().get_all_snapshots().unwrap();
    let tip = SortitionDB::get_canonical_burn_chain_tip(peer.sortdb().conn()).unwrap();
    let nakamoto_tip = peer
        .sortdb()
        .index_handle(&tip.sortition_id)
        .get_nakamoto_tip_block_id()
        .unwrap()
        .unwrap();

    assert_eq!(tip.block_height, 51);

    // make a neighbor from this peer
    let boot_observer = TestEventObserver::new();
    let privk = StacksPrivateKey::from_seed(&[0, 1, 2, 3, 4]);
    let mut boot_peer = peer.neighbor_with_observer(privk, Some(&boot_observer));

    let (canonical_stacks_tip_ch, canonical_stacks_tip_bhh) =
        SortitionDB::get_canonical_stacks_chain_tip_hash(peer.sortdb().conn()).unwrap();

    // boot up the boot peer's burnchain
    for height in 25..tip.block_height {
        let ops = peer
            .get_burnchain_block_ops_at_height(height + 1)
            .unwrap_or(vec![]);
        let sn = {
            let ih = peer.sortdb().index_handle(&tip.sortition_id);
            let sn = ih.get_block_snapshot_by_height(height).unwrap().unwrap();
            sn
        };
        test_debug!(
            "boot_peer tip height={} hash={}",
            sn.block_height,
            &sn.burn_header_hash
        );
        test_debug!("ops = {:?}", &ops);
        let block_header = TestPeer::make_next_burnchain_block(
            &boot_peer.config.burnchain,
            sn.block_height,
            &sn.burn_header_hash,
            ops.len() as u64,
            false,
        );
        TestPeer::add_burnchain_block(&boot_peer.config.burnchain, &block_header, ops.clone());
    }

    let (mut boot_dns_client, boot_dns_thread_handle) = dns_thread_start(100);

    // start running that peer so we can boot off of it
    let (term_sx, term_rx) = sync_channel(1);
    thread::scope(|s| {
        s.spawn(move || {
            let (mut last_stacks_tip_ch, mut last_stacks_tip_bhh) =
                SortitionDB::get_canonical_stacks_chain_tip_hash(boot_peer.sortdb().conn())
                    .unwrap();
            loop {
                boot_peer
                    .run_with_ibd(true, Some(&mut boot_dns_client))
                    .unwrap();

                let (stacks_tip_ch, stacks_tip_bhh) =
                    SortitionDB::get_canonical_stacks_chain_tip_hash(boot_peer.sortdb().conn())
                        .unwrap();

                last_stacks_tip_ch = stacks_tip_ch;
                last_stacks_tip_bhh = stacks_tip_bhh;

                debug!(
                    "Booting peer's stacks tip is now {:?}",
                    &boot_peer.network.stacks_tip
                );
                if stacks_tip_ch == canonical_stacks_tip_ch
                    && stacks_tip_bhh == canonical_stacks_tip_bhh
                {
                    break;
                }
            }

            term_sx.send(()).unwrap();
        });

        loop {
            if term_rx.try_recv().is_ok() {
                break;
            }
            peer.step_with_ibd(false).unwrap();
        }
    });

    boot_dns_thread_handle.join().unwrap();
}

/// Test the case where one or more blocks from tenure _T_ get orphend by a tenure-start block in
/// tenure _T + 1_.  The unconfirmed downloader should be able to handle this case.
#[test]
fn test_nakamoto_microfork_download_run_2_peers() {
    let sender_key = StacksPrivateKey::new();
    let sender_addr = to_addr(&sender_key);
    let initial_balances = vec![(sender_addr.to_account_principal(), 1000000000)];

    let observer = TestEventObserver::new();
    let bitvecs = vec![
        // full rc
        vec![true, true, true, true, true, true, true, true, true, true],
    ];

    let rc_len = 10u64;

    let (mut peer, _) = make_nakamoto_peers_from_invs_ext(
        function_name!(),
        &observer,
        bitvecs.clone(),
        |boot_plan| {
            boot_plan
                .with_pox_constants(rc_len as u32, 5)
                .with_extra_peers(0)
                .with_initial_balances(initial_balances)
                .with_malleablized_blocks(false)
        },
    );
    peer.refresh_burnchain_view();

    let nakamoto_start =
        NakamotoBootPlan::nakamoto_first_tenure_height(&peer.config.burnchain.pox_constants);

    // create a microfork
    let naka_tip_ch = peer.network.stacks_tip.consensus_hash.clone();
    let naka_tip_bh = peer.network.stacks_tip.block_hash.clone();
    let naka_tip = peer.network.stacks_tip.block_id();

    let sortdb = peer.sortdb_ref().reopen().unwrap();
    let (chainstate, _) = peer.chainstate_ref().reopen().unwrap();

    let naka_tip_header = NakamotoChainState::get_block_header_nakamoto(chainstate.db(), &naka_tip)
        .unwrap()
        .unwrap();

    // load the full tenure for this tip
    let mut naka_tip_tenure = chainstate
        .nakamoto_blocks_db()
        .load_nakamoto_tenure(&naka_tip)
        .unwrap()
        .unwrap();

    assert!(naka_tip_tenure.len() > 1);

    // make a microfork -- orphan naka_tip_tenure.last()
    naka_tip_tenure.pop();

    debug!("test: mine off of tenure");
    debug!(
        "test: first {}: {:?}",
        &naka_tip_tenure.first().as_ref().unwrap().block_id(),
        &naka_tip_tenure.first().as_ref().unwrap()
    );
    debug!(
        "test: last {}: {:?}",
        &naka_tip_tenure.last().as_ref().unwrap().block_id(),
        &naka_tip_tenure.last().as_ref().unwrap()
    );

    peer.mine_nakamoto_on(naka_tip_tenure);
    let (fork_naka_block, ..) = peer.single_block_tenure(&sender_key, |_| {}, |_| {}, |_| true);
    debug!(
        "test: produced fork {}: {:?}",
        &fork_naka_block.block_id(),
        &fork_naka_block
    );

    peer.refresh_burnchain_view();

    peer.mine_nakamoto_on(vec![fork_naka_block.clone()]);
    let (fork_naka_block_2, ..) = peer.single_block_tenure(&sender_key, |_| {}, |_| {}, |_| true);
    debug!(
        "test: confirmed fork with {}: {:?}",
        &fork_naka_block_2.block_id(),
        &fork_naka_block_2
    );

    peer.refresh_burnchain_view();

    // get reward cyclce data
    let (mut peer, reward_cycle_invs) =
        peer_get_nakamoto_invs(peer, &[0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12]);

    // make a neighbor from this peer
    let boot_observer = TestEventObserver::new();
    let privk = StacksPrivateKey::from_seed(&[0, 1, 2, 3, 4]);
    let mut boot_peer = peer.neighbor_with_observer(privk, Some(&boot_observer));

    let (canonical_stacks_tip_ch, canonical_stacks_tip_bhh) =
        SortitionDB::get_canonical_stacks_chain_tip_hash(peer.sortdb().conn()).unwrap();

    let all_sortitions = peer.sortdb().get_all_snapshots().unwrap();
    let tip = SortitionDB::get_canonical_burn_chain_tip(peer.sortdb().conn()).unwrap();
    let nakamoto_tip = peer
        .sortdb()
        .index_handle(&tip.sortition_id)
        .get_nakamoto_tip_block_id()
        .unwrap()
        .unwrap();

    assert_eq!(tip.block_height, 53);

    // boot up the boot peer's burnchain
    for height in 25..tip.block_height {
        let ops = peer
            .get_burnchain_block_ops_at_height(height + 1)
            .unwrap_or(vec![]);
        let sn = {
            let ih = peer.sortdb().index_handle(&tip.sortition_id);
            let sn = ih.get_block_snapshot_by_height(height).unwrap().unwrap();
            sn
        };
        test_debug!(
            "boot_peer tip height={} hash={}",
            sn.block_height,
            &sn.burn_header_hash
        );
        test_debug!("ops = {:?}", &ops);
        let block_header = TestPeer::make_next_burnchain_block(
            &boot_peer.config.burnchain,
            sn.block_height,
            &sn.burn_header_hash,
            ops.len() as u64,
            false,
        );
        TestPeer::add_burnchain_block(&boot_peer.config.burnchain, &block_header, ops.clone());
    }

    let (mut boot_dns_client, boot_dns_thread_handle) = dns_thread_start(100);

    // start running that peer so we can boot off of it
    let (term_sx, term_rx) = sync_channel(1);
    thread::scope(|s| {
        s.spawn(move || {
            let (mut last_stacks_tip_ch, mut last_stacks_tip_bhh) =
                SortitionDB::get_canonical_stacks_chain_tip_hash(boot_peer.sortdb().conn())
                    .unwrap();
            loop {
                boot_peer
                    .run_with_ibd(true, Some(&mut boot_dns_client))
                    .unwrap();

                let (stacks_tip_ch, stacks_tip_bhh) =
                    SortitionDB::get_canonical_stacks_chain_tip_hash(boot_peer.sortdb().conn())
                        .unwrap();

                last_stacks_tip_ch = stacks_tip_ch;
                last_stacks_tip_bhh = stacks_tip_bhh;

                debug!(
                    "Booting peer's stacks tip is now {:?}",
                    &boot_peer.network.stacks_tip
                );
                if stacks_tip_ch == canonical_stacks_tip_ch
                    && stacks_tip_bhh == canonical_stacks_tip_bhh
                {
                    break;
                }
            }

            term_sx.send(()).unwrap();
        });

        loop {
            if term_rx.try_recv().is_ok() {
                break;
            }
            peer.step_with_ibd(false).unwrap();
        }
    });

    boot_dns_thread_handle.join().unwrap();
}

/// Test booting up a node where there is one shadow block in the prepare phase, as well as some
/// blocks that mine atop it.
#[test]
fn test_nakamoto_download_run_2_peers_with_one_shadow_block() {
    let observer = TestEventObserver::new();
    let sender_key = StacksPrivateKey::new();
    let sender_addr = to_addr(&sender_key);
    let initial_balances = vec![(sender_addr.to_account_principal(), 1000000000)];
    let bitvecs = vec![vec![true, true, false, false]];

    let rc_len = 10u64;
    let (mut peer, _) = make_nakamoto_peers_from_invs_ext(
        function_name!(),
        &observer,
        bitvecs.clone(),
        |boot_plan| {
            boot_plan
                .with_pox_constants(rc_len as u32, 5)
                .with_extra_peers(0)
                .with_initial_balances(initial_balances)
                .with_malleablized_blocks(false)
        },
    );
    peer.refresh_burnchain_view();
    let (mut peer, reward_cycle_invs) =
        peer_get_nakamoto_invs(peer, &[0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12]);

    let nakamoto_start =
        NakamotoBootPlan::nakamoto_first_tenure_height(&peer.config.burnchain.pox_constants);

    // create a shadow block
    let naka_tip_ch = peer.network.stacks_tip.consensus_hash.clone();
    let naka_tip_bh = peer.network.stacks_tip.block_hash.clone();
    let naka_tip = peer.network.stacks_tip.block_id();

    let sortdb = peer.sortdb_ref().reopen().unwrap();
    let (chainstate, _) = peer.chainstate_ref().reopen().unwrap();

    let naka_tip_header = NakamotoChainState::get_block_header_nakamoto(chainstate.db(), &naka_tip)
        .unwrap()
        .unwrap();

    let naka_tip_tenure = chainstate
        .nakamoto_blocks_db()
        .load_nakamoto_tenure(&naka_tip)
        .unwrap()
        .unwrap();

    assert!(naka_tip_tenure.len() > 1);

    peer.mine_nakamoto_on(naka_tip_tenure);
    let shadow_block = peer.make_shadow_tenure(None);
    debug!(
        "test: produced shadow block {}: {:?}",
        &shadow_block.block_id(),
        &shadow_block
    );

    peer.refresh_burnchain_view();

    peer.mine_nakamoto_on(vec![shadow_block.clone()]);
    let (next_block, ..) = peer.single_block_tenure(&sender_key, |_| {}, |_| {}, |_| true);
    debug!(
        "test: confirmed shadow block with {}: {:?}",
        &next_block.block_id(),
        &next_block
    );

    peer.refresh_burnchain_view();
    peer.mine_nakamoto_on(vec![next_block.clone()]);

    for _ in 0..9 {
        let (next_block, ..) = peer.single_block_tenure(&sender_key, |_| {}, |_| {}, |_| true);
        debug!(
            "test: confirmed shadow block with {}: {:?}",
            &next_block.block_id(),
            &next_block
        );

        peer.refresh_burnchain_view();
        peer.mine_nakamoto_on(vec![next_block.clone()]);
    }

    let all_sortitions = peer.sortdb().get_all_snapshots().unwrap();
    let tip = SortitionDB::get_canonical_burn_chain_tip(peer.sortdb().conn()).unwrap();
    let nakamoto_tip = peer
        .sortdb()
        .index_handle(&tip.sortition_id)
        .get_nakamoto_tip_block_id()
        .unwrap()
        .unwrap();

    /*
    assert_eq!(
        tip.block_height,
        56
    );
    */

    // make a neighbor from this peer
    let boot_observer = TestEventObserver::new();
    let privk = StacksPrivateKey::from_seed(&[0, 1, 2, 3, 4]);
    let mut boot_peer = peer.neighbor_with_observer(privk, Some(&boot_observer));

    let (canonical_stacks_tip_ch, canonical_stacks_tip_bhh) =
        SortitionDB::get_canonical_stacks_chain_tip_hash(peer.sortdb().conn()).unwrap();

    // boot up the boot peer's burnchain
    for height in 25..tip.block_height {
        let ops = peer
            .get_burnchain_block_ops_at_height(height + 1)
            .unwrap_or(vec![]);
        let sn = {
            let ih = peer.sortdb().index_handle(&tip.sortition_id);
            let sn = ih.get_block_snapshot_by_height(height).unwrap().unwrap();
            sn
        };
        test_debug!(
            "boot_peer tip height={} hash={}",
            sn.block_height,
            &sn.burn_header_hash
        );
        test_debug!("ops = {:?}", &ops);
        let block_header = TestPeer::make_next_burnchain_block(
            &boot_peer.config.burnchain,
            sn.block_height,
            &sn.burn_header_hash,
            ops.len() as u64,
            false,
        );
        TestPeer::add_burnchain_block(&boot_peer.config.burnchain, &block_header, ops.clone());
    }

    {
        let mut node = boot_peer.stacks_node.take().unwrap();
        let tx = node.chainstate.staging_db_tx_begin().unwrap();
        tx.add_shadow_block(&shadow_block).unwrap();
        tx.commit().unwrap();
        boot_peer.stacks_node = Some(node);
    }

    let (mut boot_dns_client, boot_dns_thread_handle) = dns_thread_start(100);

    // start running that peer so we can boot off of it
    let (term_sx, term_rx) = sync_channel(1);
    thread::scope(|s| {
        s.spawn(move || {
            let (mut last_stacks_tip_ch, mut last_stacks_tip_bhh) =
                SortitionDB::get_canonical_stacks_chain_tip_hash(boot_peer.sortdb().conn())
                    .unwrap();
            loop {
                boot_peer
                    .run_with_ibd(true, Some(&mut boot_dns_client))
                    .unwrap();

                let (stacks_tip_ch, stacks_tip_bhh) =
                    SortitionDB::get_canonical_stacks_chain_tip_hash(boot_peer.sortdb().conn())
                        .unwrap();

                last_stacks_tip_ch = stacks_tip_ch;
                last_stacks_tip_bhh = stacks_tip_bhh;

                debug!(
                    "Booting peer's stacks tip is now {:?}",
                    &boot_peer.network.stacks_tip
                );
                if stacks_tip_ch == canonical_stacks_tip_ch {
                    break;
                }
            }

            term_sx.send(()).unwrap();
        });

        loop {
            if term_rx.try_recv().is_ok() {
                break;
            }
            peer.step_with_ibd(false).unwrap();
        }
    });

    boot_dns_thread_handle.join().unwrap();
}

/// Test booting up a node where the whole prepare phase is shadow blocks
#[test]
fn test_nakamoto_download_run_2_peers_shadow_prepare_phase() {
    let observer = TestEventObserver::new();
    let sender_key = StacksPrivateKey::new();
    let sender_addr = to_addr(&sender_key);
    let initial_balances = vec![(sender_addr.to_account_principal(), 1000000000)];
    let bitvecs = vec![vec![true, true]];

    let rc_len = 10u64;
    let (mut peer, _) = make_nakamoto_peers_from_invs_ext(
        function_name!(),
        &observer,
        bitvecs.clone(),
        |boot_plan| {
            boot_plan
                .with_pox_constants(rc_len as u32, 5)
                .with_extra_peers(0)
                .with_initial_balances(initial_balances)
                .with_malleablized_blocks(false)
        },
    );
    peer.refresh_burnchain_view();
    let (mut peer, reward_cycle_invs) =
        peer_get_nakamoto_invs(peer, &[0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12]);

    let nakamoto_start =
        NakamotoBootPlan::nakamoto_first_tenure_height(&peer.config.burnchain.pox_constants);

    // create a shadow block
    let naka_tip_ch = peer.network.stacks_tip.consensus_hash.clone();
    let naka_tip_bh = peer.network.stacks_tip.block_hash.clone();
    let naka_tip = peer.network.stacks_tip.block_id();

    let sortdb = peer.sortdb_ref().reopen().unwrap();
    let (chainstate, _) = peer.chainstate_ref().reopen().unwrap();

    let naka_tip_header = NakamotoChainState::get_block_header_nakamoto(chainstate.db(), &naka_tip)
        .unwrap()
        .unwrap();

    let naka_tip_tenure = chainstate
        .nakamoto_blocks_db()
        .load_nakamoto_tenure(&naka_tip)
        .unwrap()
        .unwrap();

    assert!(naka_tip_tenure.len() > 1);

    peer.mine_nakamoto_on(naka_tip_tenure);

    let mut shadow_blocks = vec![];
    for _ in 0..10 {
        let shadow_block = peer.make_shadow_tenure(None);
        debug!(
            "test: produced shadow block {}: {:?}",
            &shadow_block.block_id(),
            &shadow_block
        );
        shadow_blocks.push(shadow_block.clone());
        peer.refresh_burnchain_view();

        peer.mine_nakamoto_on(vec![shadow_block.clone()]);
    }

    match peer.single_block_tenure_fallible(&sender_key, |_| {}, |_| {}, |_| true) {
        Ok((next_block, ..)) => {
            debug!(
                "test: confirmed shadow block with {}: {:?}",
                &next_block.block_id(),
                &next_block
            );

            peer.refresh_burnchain_view();
            peer.mine_nakamoto_on(vec![next_block.clone()]);
        }
        Err(ChainstateError::NoSuchBlockError) => {
            // tried to mine but our commit was invalid (e.g. because we haven't mined often
            // enough)
            peer.refresh_burnchain_view();
        }
        Err(e) => {
            panic!("FATAL: {:?}", &e);
        }
    };

    for _ in 0..10 {
        let (next_block, ..) =
            match peer.single_block_tenure_fallible(&sender_key, |_| {}, |_| {}, |_| true) {
                Ok(x) => x,
                Err(ChainstateError::NoSuchBlockError) => {
                    // tried to mine but our commit was invalid (e.g. because we haven't mined often
                    // enough)
                    peer.refresh_burnchain_view();
                    continue;
                }
                Err(e) => {
                    panic!("FATAL: {:?}", &e);
                }
            };

        debug!(
            "test: confirmed shadow block with {}: {:?}",
            &next_block.block_id(),
            &next_block
        );

        peer.refresh_burnchain_view();
        peer.mine_nakamoto_on(vec![next_block.clone()]);
    }

    let all_sortitions = peer.sortdb().get_all_snapshots().unwrap();
    let tip = SortitionDB::get_canonical_burn_chain_tip(peer.sortdb().conn()).unwrap();
    let nakamoto_tip = peer
        .sortdb()
        .index_handle(&tip.sortition_id)
        .get_nakamoto_tip_block_id()
        .unwrap()
        .unwrap();

    // make a neighbor from this peer
    let boot_observer = TestEventObserver::new();
    let privk = StacksPrivateKey::from_seed(&[0, 1, 2, 3, 4]);
    let mut boot_peer = peer.neighbor_with_observer(privk, Some(&boot_observer));

    let (canonical_stacks_tip_ch, canonical_stacks_tip_bhh) =
        SortitionDB::get_canonical_stacks_chain_tip_hash(peer.sortdb().conn()).unwrap();

    // boot up the boot peer's burnchain
    for height in 25..tip.block_height {
        let ops = peer
            .get_burnchain_block_ops_at_height(height + 1)
            .unwrap_or(vec![]);
        let sn = {
            let ih = peer.sortdb().index_handle(&tip.sortition_id);
            let sn = ih.get_block_snapshot_by_height(height).unwrap().unwrap();
            sn
        };
        test_debug!(
            "boot_peer tip height={} hash={}",
            sn.block_height,
            &sn.burn_header_hash
        );
        test_debug!("ops = {:?}", &ops);
        let block_header = TestPeer::make_next_burnchain_block(
            &boot_peer.config.burnchain,
            sn.block_height,
            &sn.burn_header_hash,
            ops.len() as u64,
            false,
        );
        TestPeer::add_burnchain_block(&boot_peer.config.burnchain, &block_header, ops.clone());
    }
    {
        let mut node = boot_peer.stacks_node.take().unwrap();
        let tx = node.chainstate.staging_db_tx_begin().unwrap();
        for shadow_block in shadow_blocks.into_iter() {
            tx.add_shadow_block(&shadow_block).unwrap();
        }
        tx.commit().unwrap();
        boot_peer.stacks_node = Some(node);
    }

    let (mut boot_dns_client, boot_dns_thread_handle) = dns_thread_start(100);

    // start running that peer so we can boot off of it
    let (term_sx, term_rx) = sync_channel(1);
    thread::scope(|s| {
        s.spawn(move || {
            let (mut last_stacks_tip_ch, mut last_stacks_tip_bhh) =
                SortitionDB::get_canonical_stacks_chain_tip_hash(boot_peer.sortdb().conn())
                    .unwrap();
            loop {
                boot_peer
                    .run_with_ibd(true, Some(&mut boot_dns_client))
                    .unwrap();

                let (stacks_tip_ch, stacks_tip_bhh) =
                    SortitionDB::get_canonical_stacks_chain_tip_hash(boot_peer.sortdb().conn())
                        .unwrap();

                last_stacks_tip_ch = stacks_tip_ch;
                last_stacks_tip_bhh = stacks_tip_bhh;

                debug!(
                    "Booting peer's stacks tip is now {:?}",
                    &boot_peer.network.stacks_tip
                );
                if stacks_tip_ch == canonical_stacks_tip_ch {
                    break;
                }
            }

            term_sx.send(()).unwrap();
        });

        loop {
            if term_rx.try_recv().is_ok() {
                break;
            }
            peer.step_with_ibd(false).unwrap();
        }
    });

    boot_dns_thread_handle.join().unwrap();
}

/// Test booting up a node where multiple reward cycles are shadow blocks
#[test]
fn test_nakamoto_download_run_2_peers_shadow_reward_cycles() {
    let observer = TestEventObserver::new();
    let sender_key = StacksPrivateKey::new();
    let sender_addr = to_addr(&sender_key);
    let initial_balances = vec![(sender_addr.to_account_principal(), 1000000000)];
    let bitvecs = vec![vec![true, true]];

    let rc_len = 10u64;
    let (mut peer, _) = make_nakamoto_peers_from_invs_ext(
        function_name!(),
        &observer,
        bitvecs.clone(),
        |boot_plan| {
            boot_plan
                .with_pox_constants(rc_len as u32, 5)
                .with_extra_peers(0)
                .with_initial_balances(initial_balances)
                .with_malleablized_blocks(false)
        },
    );
    peer.refresh_burnchain_view();
    let (mut peer, reward_cycle_invs) =
        peer_get_nakamoto_invs(peer, &[0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12]);

    let nakamoto_start =
        NakamotoBootPlan::nakamoto_first_tenure_height(&peer.config.burnchain.pox_constants);

    // create a shadow block
    let naka_tip_ch = peer.network.stacks_tip.consensus_hash.clone();
    let naka_tip_bh = peer.network.stacks_tip.block_hash.clone();
    let naka_tip = peer.network.stacks_tip.block_id();

    let sortdb = peer.sortdb_ref().reopen().unwrap();
    let (chainstate, _) = peer.chainstate_ref().reopen().unwrap();

    let naka_tip_header = NakamotoChainState::get_block_header_nakamoto(chainstate.db(), &naka_tip)
        .unwrap()
        .unwrap();

    let naka_tip_tenure = chainstate
        .nakamoto_blocks_db()
        .load_nakamoto_tenure(&naka_tip)
        .unwrap()
        .unwrap();

    assert!(naka_tip_tenure.len() > 1);

    peer.mine_nakamoto_on(naka_tip_tenure);

    let mut shadow_blocks = vec![];
    for _ in 0..30 {
        let shadow_block = peer.make_shadow_tenure(None);
        debug!(
            "test: produced shadow block {}: {:?}",
            &shadow_block.block_id(),
            &shadow_block
        );
        shadow_blocks.push(shadow_block.clone());
        peer.refresh_burnchain_view();

        peer.mine_nakamoto_on(vec![shadow_block.clone()]);
    }

    match peer.single_block_tenure_fallible(&sender_key, |_| {}, |_| {}, |_| true) {
        Ok((next_block, ..)) => {
            debug!(
                "test: confirmed shadow block with {}: {:?}",
                &next_block.block_id(),
                &next_block
            );

            peer.refresh_burnchain_view();
            peer.mine_nakamoto_on(vec![next_block.clone()]);
        }
        Err(ChainstateError::NoSuchBlockError) => {
            // tried to mine but our commit was invalid (e.g. because we haven't mined often
            // enough)
            peer.refresh_burnchain_view();
        }
        Err(e) => {
            panic!("FATAL: {:?}", &e);
        }
    };

    for _ in 0..10 {
        let (next_block, ..) =
            match peer.single_block_tenure_fallible(&sender_key, |_| {}, |_| {}, |_| true) {
                Ok(x) => x,
                Err(ChainstateError::NoSuchBlockError) => {
                    // tried to mine but our commit was invalid (e.g. because we haven't mined often
                    // enough)
                    peer.refresh_burnchain_view();
                    continue;
                }
                Err(e) => {
                    panic!("FATAL: {:?}", &e);
                }
            };

        debug!(
            "test: confirmed shadow block with {}: {:?}",
            &next_block.block_id(),
            &next_block
        );

        peer.refresh_burnchain_view();
        peer.mine_nakamoto_on(vec![next_block.clone()]);
    }

    let all_sortitions = peer.sortdb().get_all_snapshots().unwrap();
    let tip = SortitionDB::get_canonical_burn_chain_tip(peer.sortdb().conn()).unwrap();
    let nakamoto_tip = peer
        .sortdb()
        .index_handle(&tip.sortition_id)
        .get_nakamoto_tip_block_id()
        .unwrap()
        .unwrap();

    assert_eq!(tip.block_height, 84);

    // make a neighbor from this peer
    let boot_observer = TestEventObserver::new();
    let privk = StacksPrivateKey::from_seed(&[0, 1, 2, 3, 4]);
    let mut boot_peer = peer.neighbor_with_observer(privk, Some(&boot_observer));

    let (canonical_stacks_tip_ch, canonical_stacks_tip_bhh) =
        SortitionDB::get_canonical_stacks_chain_tip_hash(peer.sortdb().conn()).unwrap();

    // boot up the boot peer's burnchain
    for height in 25..tip.block_height {
        let ops = peer
            .get_burnchain_block_ops_at_height(height + 1)
            .unwrap_or(vec![]);
        let sn = {
            let ih = peer.sortdb().index_handle(&tip.sortition_id);
            let sn = ih.get_block_snapshot_by_height(height).unwrap().unwrap();
            sn
        };
        test_debug!(
            "boot_peer tip height={} hash={}",
            sn.block_height,
            &sn.burn_header_hash
        );
        test_debug!("ops = {:?}", &ops);
        let block_header = TestPeer::make_next_burnchain_block(
            &boot_peer.config.burnchain,
            sn.block_height,
            &sn.burn_header_hash,
            ops.len() as u64,
            false,
        );
        TestPeer::add_burnchain_block(&boot_peer.config.burnchain, &block_header, ops.clone());
    }
    {
        let mut node = boot_peer.stacks_node.take().unwrap();
        let tx = node.chainstate.staging_db_tx_begin().unwrap();
        for shadow_block in shadow_blocks.into_iter() {
            tx.add_shadow_block(&shadow_block).unwrap();
        }
        tx.commit().unwrap();
        boot_peer.stacks_node = Some(node);
    }

    let (mut boot_dns_client, boot_dns_thread_handle) = dns_thread_start(100);

    // start running that peer so we can boot off of it
    let (term_sx, term_rx) = sync_channel(1);
    thread::scope(|s| {
        s.spawn(move || {
            let (mut last_stacks_tip_ch, mut last_stacks_tip_bhh) =
                SortitionDB::get_canonical_stacks_chain_tip_hash(boot_peer.sortdb().conn())
                    .unwrap();
            loop {
                boot_peer
                    .run_with_ibd(true, Some(&mut boot_dns_client))
                    .unwrap();

                let (stacks_tip_ch, stacks_tip_bhh) =
                    SortitionDB::get_canonical_stacks_chain_tip_hash(boot_peer.sortdb().conn())
                        .unwrap();

                last_stacks_tip_ch = stacks_tip_ch;
                last_stacks_tip_bhh = stacks_tip_bhh;

                debug!(
                    "Booting peer's stacks tip is now {:?}",
                    &boot_peer.network.stacks_tip
                );
                if stacks_tip_ch == canonical_stacks_tip_ch {
                    break;
                }
            }

            term_sx.send(()).unwrap();
        });

        loop {
            if term_rx.try_recv().is_ok() {
                break;
            }
            peer.step_with_ibd(false).unwrap();
        }
    });

    boot_dns_thread_handle.join().unwrap();
}
