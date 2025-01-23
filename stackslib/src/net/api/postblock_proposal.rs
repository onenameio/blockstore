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

use std::io::{Read, Write};
#[cfg(any(test, feature = "testing"))]
use std::sync::LazyLock;
use std::thread::{self, JoinHandle, Thread};
#[cfg(any(test, feature = "testing"))]
use std::time::Duration;
use std::time::Instant;

use clarity::vm::ast::ASTRules;
use clarity::vm::costs::ExecutionCost;
use regex::{Captures, Regex};
use serde::Deserialize;
use stacks_common::codec::{
    read_next, write_next, Error as CodecError, StacksMessageCodec, MAX_PAYLOAD_LEN,
};
use stacks_common::consts::CHAIN_ID_MAINNET;
use stacks_common::types::chainstate::{
    BlockHeaderHash, BurnchainHeaderHash, ConsensusHash, StacksBlockId, StacksPublicKey,
};
use stacks_common::types::net::PeerHost;
use stacks_common::types::StacksPublicKeyBuffer;
use stacks_common::util::hash::{hex_bytes, to_hex, Hash160, Sha256Sum, Sha512Trunc256Sum};
use stacks_common::util::retry::BoundReader;
#[cfg(any(test, feature = "testing"))]
use stacks_common::util::tests::TestFlag;
use stacks_common::util::{get_epoch_time_ms, get_epoch_time_secs};

use crate::burnchains::affirmation::AffirmationMap;
use crate::burnchains::Txid;
use crate::chainstate::burn::db::sortdb::{SortitionDB, SortitionHandleConn};
use crate::chainstate::nakamoto::miner::NakamotoBlockBuilder;
use crate::chainstate::nakamoto::{NakamotoBlock, NakamotoChainState, NAKAMOTO_BLOCK_VERSION};
use crate::chainstate::stacks::db::blocks::MINIMUM_TX_FEE_RATE_PER_BYTE;
use crate::chainstate::stacks::db::{StacksBlockHeaderTypes, StacksChainState};
use crate::chainstate::stacks::miner::{BlockBuilder, BlockLimitFunction, TransactionResult};
use crate::chainstate::stacks::{
    Error as ChainError, StacksBlock, StacksBlockHeader, StacksTransaction, TransactionPayload,
};
use crate::core::mempool::{MemPoolDB, ProposalCallbackReceiver};
use crate::cost_estimates::FeeRateEstimate;
use crate::net::http::{
    http_reason, parse_json, Error, HttpBadRequest, HttpContentType, HttpNotFound, HttpRequest,
    HttpRequestContents, HttpRequestPreamble, HttpResponse, HttpResponseContents,
    HttpResponsePayload, HttpResponsePreamble, HttpServerError,
};
use crate::net::httpcore::{
    request, HttpPreambleExtensions, HttpRequestContentsExtensions, RPCRequestHandler,
    StacksHttpRequest, StacksHttpResponse,
};
use crate::net::p2p::PeerNetwork;
use crate::net::relay::Relayer;
use crate::net::{
    Attachment, BlocksData, BlocksDatum, Error as NetError, StacksMessageType, StacksNodeState,
};
use crate::util_lib::db::Error as DBError;

#[cfg(any(test, feature = "testing"))]
pub static TEST_VALIDATE_STALL: LazyLock<TestFlag<bool>> = LazyLock::new(TestFlag::default);
#[cfg(any(test, feature = "testing"))]
/// Artificial delay to add to block validation.
pub static TEST_VALIDATE_DELAY_DURATION_SECS: LazyLock<TestFlag<u64>> =
    LazyLock::new(TestFlag::default);

// This enum is used to supply a `reason_code` for validation
//  rejection responses. This is serialized as an enum with string
//  type (in jsonschema terminology).
define_u8_enum![ValidateRejectCode {
    BadBlockHash = 0,
    BadTransaction = 1,
    InvalidBlock = 2,
    ChainstateError = 3,
    UnknownParent = 4,
    NonCanonicalTenure = 5,
    NoSuchTenure = 6
}];

pub static TOO_MANY_REQUESTS_STATUS: u16 = 429;

impl TryFrom<u8> for ValidateRejectCode {
    type Error = CodecError;
    fn try_from(value: u8) -> Result<Self, Self::Error> {
        Self::from_u8(value)
            .ok_or_else(|| CodecError::DeserializeError(format!("Unknown type prefix: {value}")))
    }
}

fn hex_ser_block<S: serde::Serializer>(b: &NakamotoBlock, s: S) -> Result<S::Ok, S::Error> {
    let inst = to_hex(&b.serialize_to_vec());
    s.serialize_str(inst.as_str())
}

fn hex_deser_block<'de, D: serde::Deserializer<'de>>(d: D) -> Result<NakamotoBlock, D::Error> {
    let inst_str = String::deserialize(d)?;
    let bytes = hex_bytes(&inst_str).map_err(serde::de::Error::custom)?;
    NakamotoBlock::consensus_deserialize(&mut bytes.as_slice()).map_err(serde::de::Error::custom)
}

/// A response for block proposal validation
///  that the stacks-node thinks should be rejected.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct BlockValidateReject {
    pub signer_signature_hash: Sha512Trunc256Sum,
    pub reason: String,
    pub reason_code: ValidateRejectCode,
}

#[derive(Debug, Clone, PartialEq)]
pub struct BlockValidateRejectReason {
    pub reason: String,
    pub reason_code: ValidateRejectCode,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum BlockProposalResult {
    Accepted,
    Error,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct BlockProposalResponse {
    pub result: BlockProposalResult,
    pub message: String,
}

impl<T> From<T> for BlockValidateRejectReason
where
    T: Into<ChainError>,
{
    fn from(value: T) -> Self {
        let ce: ChainError = value.into();
        Self {
            reason: format!("Chainstate Error: {ce}"),
            reason_code: ValidateRejectCode::ChainstateError,
        }
    }
}

/// A response for block proposal validation
///  that the stacks-node thinks is acceptable.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct BlockValidateOk {
    pub signer_signature_hash: Sha512Trunc256Sum,
    pub cost: ExecutionCost,
    pub size: u64,
    pub validation_time_ms: u64,
}

/// This enum is used for serializing the response to block
/// proposal validation.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "result")]
pub enum BlockValidateResponse {
    Ok(BlockValidateOk),
    Reject(BlockValidateReject),
}

impl From<Result<BlockValidateOk, BlockValidateReject>> for BlockValidateResponse {
    fn from(value: Result<BlockValidateOk, BlockValidateReject>) -> Self {
        match value {
            Ok(o) => BlockValidateResponse::Ok(o),
            Err(e) => BlockValidateResponse::Reject(e),
        }
    }
}

impl BlockValidateResponse {
    /// Get the signer signature hash from the response
    pub fn signer_signature_hash(&self) -> Sha512Trunc256Sum {
        match self {
            BlockValidateResponse::Ok(o) => o.signer_signature_hash,
            BlockValidateResponse::Reject(r) => r.signer_signature_hash,
        }
    }
}

#[cfg(any(test, feature = "testing"))]
fn fault_injection_validation_delay() {
    let delay = TEST_VALIDATE_DELAY_DURATION_SECS.get();
    warn!("Sleeping for {} seconds to simulate slow processing", delay);
    thread::sleep(Duration::from_secs(delay));
}

#[cfg(not(any(test, feature = "testing")))]
fn fault_injection_validation_delay() {}

/// Represents a block proposed to the `v3/block_proposal` endpoint for validation
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct NakamotoBlockProposal {
    /// Proposed block
    #[serde(serialize_with = "hex_ser_block", deserialize_with = "hex_deser_block")]
    pub block: NakamotoBlock,
    /// Identifies which chain block is for (Mainnet, Testnet, etc.)
    pub chain_id: u32,
}

impl NakamotoBlockProposal {
    fn spawn_validation_thread(
        self,
        sortdb: SortitionDB,
        mut chainstate: StacksChainState,
        receiver: Box<dyn ProposalCallbackReceiver>,
    ) -> Result<JoinHandle<()>, std::io::Error> {
        thread::Builder::new()
            .name("block-proposal".into())
            .spawn(move || {
                let result =
                    self.validate(&sortdb, &mut chainstate)
                        .map_err(|reason| BlockValidateReject {
                            signer_signature_hash: self.block.header.signer_signature_hash(),
                            reason_code: reason.reason_code,
                            reason: reason.reason,
                        });
                receiver.notify_proposal_result(result);
            })
    }

    /// DO NOT CALL FROM CONSENSUS CODE
    ///
    /// Check to see if a block builds atop the highest block in a given tenure.
    /// That is:
    /// - its parent must exist, and
    /// - its parent must be as high as the highest block in the given tenure.
    fn check_block_builds_on_highest_block_in_tenure(
        chainstate: &StacksChainState,
        tenure_id: &ConsensusHash,
        parent_block_id: &StacksBlockId,
    ) -> Result<(), BlockValidateRejectReason> {
        let Some(highest_header) = NakamotoChainState::get_highest_known_block_header_in_tenure(
            chainstate.db(),
            tenure_id,
        )
        .map_err(|e| BlockValidateRejectReason {
            reason_code: ValidateRejectCode::ChainstateError,
            reason: format!("Failed to query highest block in tenure ID: {:?}", &e),
        })?
        else {
            warn!(
                "Rejected block proposal";
                "reason" => "Block is not a tenure-start block, and has an unrecognized tenure consensus hash",
                "consensus_hash" => %tenure_id,
            );
            return Err(BlockValidateRejectReason {
                reason_code: ValidateRejectCode::NoSuchTenure,
                reason: "Block is not a tenure-start block, and has an unrecognized tenure consensus hash".into(),
            });
        };
        let Some(parent_header) =
            NakamotoChainState::get_block_header(chainstate.db(), parent_block_id).map_err(
                |e| BlockValidateRejectReason {
                    reason_code: ValidateRejectCode::ChainstateError,
                    reason: format!("Failed to query block header by block ID: {:?}", &e),
                },
            )?
        else {
            warn!(
                "Rejected block proposal";
                "reason" => "Block has no parent",
                "parent_block_id" => %parent_block_id
            );
            return Err(BlockValidateRejectReason {
                reason_code: ValidateRejectCode::UnknownParent,
                reason: "Block has no parent".into(),
            });
        };
        if parent_header.anchored_header.height() != highest_header.anchored_header.height() {
            warn!(
                "Rejected block proposal";
                "reason" => "Block's parent is not the highest block in this tenure",
                "consensus_hash" => %tenure_id,
                "parent_header.height" => parent_header.anchored_header.height(),
                "highest_header.height" => highest_header.anchored_header.height(),
            );
            return Err(BlockValidateRejectReason {
                reason_code: ValidateRejectCode::InvalidBlock,
                reason: "Block is not higher than the highest block in its tenure".into(),
            });
        }
        Ok(())
    }

    /// Verify that the block we received builds upon a valid tenure.
    /// Implemented as a static function to facilitate testing.
    pub(crate) fn check_block_has_valid_tenure(
        db_handle: &SortitionHandleConn,
        tenure_id: &ConsensusHash,
    ) -> Result<(), BlockValidateRejectReason> {
        // Verify that the block's tenure is on the canonical sortition history
        if !db_handle.has_consensus_hash(tenure_id)? {
            warn!(
                "Rejected block proposal";
                "reason" => "Block's tenure consensus hash is not on the canonical Bitcoin fork",
                "consensus_hash" => %tenure_id,
            );
            return Err(BlockValidateRejectReason {
                reason_code: ValidateRejectCode::NonCanonicalTenure,
                reason: "Tenure consensus hash is not on the canonical Bitcoin fork".into(),
            });
        }
        Ok(())
    }

    /// Verify that the block we received builds on the highest block in its tenure.
    /// * For tenure-start blocks, the parent must be as high as the highest block in the parent
    /// block's tenure.
    /// * For all other blocks, the parent must be as high as the highest block in the tenure.
    ///
    /// Implemented as a static function to facilitate testing
    pub(crate) fn check_block_has_valid_parent(
        chainstate: &StacksChainState,
        block: &NakamotoBlock,
    ) -> Result<(), BlockValidateRejectReason> {
        let is_tenure_start =
            block
                .is_wellformed_tenure_start_block()
                .map_err(|_| BlockValidateRejectReason {
                    reason_code: ValidateRejectCode::InvalidBlock,
                    reason: "Block is not well-formed".into(),
                })?;

        if !is_tenure_start {
            // this is a well-formed block that is not the start of a tenure, so it must build
            // atop an existing block in its tenure.
            Self::check_block_builds_on_highest_block_in_tenure(
                chainstate,
                &block.header.consensus_hash,
                &block.header.parent_block_id,
            )?;
        } else {
            // this is a tenure-start block, so it must build atop a parent which has the
            // highest height in the *previous* tenure.
            let parent_header = NakamotoChainState::get_block_header(
                chainstate.db(),
                &block.header.parent_block_id,
            )?
            .ok_or_else(|| BlockValidateRejectReason {
                reason_code: ValidateRejectCode::UnknownParent,
                reason: "No parent block".into(),
            })?;

            Self::check_block_builds_on_highest_block_in_tenure(
                chainstate,
                &parent_header.consensus_hash,
                &block.header.parent_block_id,
            )?;
        }
        Ok(())
    }

    /// Test this block proposal against the current chain state and
    /// either accept or reject the proposal
    ///
    /// This is done in 3 stages:
    /// - Static validation of the block, which checks the following:
    ///   - Block header is well-formed
    ///   - Transactions are well-formed
    ///   - Miner signature is valid
    /// - Validation of transactions by executing them agains current chainstate.
    ///   This is resource intensive, and therefore done only if previous checks pass
    pub fn validate(
        &self,
        sortdb: &SortitionDB,
        chainstate: &mut StacksChainState, // not directly used; used as a handle to open other chainstates
    ) -> Result<BlockValidateOk, BlockValidateRejectReason> {
        #[cfg(any(test, feature = "testing"))]
        {
            if TEST_VALIDATE_STALL.get() {
                // Do an extra check just so we don't log EVERY time.
                warn!("Block validation is stalled due to testing directive.");
                while TEST_VALIDATE_STALL.get() {
                    std::thread::sleep(std::time::Duration::from_millis(10));
                }
                info!(
                    "Block validation is no longer stalled due to testing directive. Continuing..."
                );
            }
        }
        let start = Instant::now();

        fault_injection_validation_delay();

        let mainnet = self.chain_id == CHAIN_ID_MAINNET;
        if self.chain_id != chainstate.chain_id || mainnet != chainstate.mainnet {
            warn!(
                "Rejected block proposal";
                "reason" => "Wrong network/chain_id",
                "expected_chain_id" => chainstate.chain_id,
                "expected_mainnet" => chainstate.mainnet,
                "received_chain_id" => self.chain_id,
                "received_mainnet" => mainnet,
            );
            return Err(BlockValidateRejectReason {
                reason_code: ValidateRejectCode::InvalidBlock,
                reason: "Wrong network/chain_id".into(),
            });
        }

        // Check block version. If it's less than the compiled-in version, just emit a warning
        // because there's a new version of the node / signer binary available that really ought to
        // be used (hint, hint)
        if self.block.header.version != NAKAMOTO_BLOCK_VERSION {
            warn!("Proposed block has unexpected version. Upgrade your node and/or signer ASAP.";
                  "block.header.version" => %self.block.header.version,
                  "expected" => %NAKAMOTO_BLOCK_VERSION);
        }

        // open sortition view to the current burn view.
        // If the block has a TenureChange with an Extend cause, then the burn view is whatever is
        // indicated in the TenureChange.
        // Otherwise, it's the same as the block's parent's burn view.
        let parent_stacks_header = NakamotoChainState::get_block_header(
            chainstate.db(),
            &self.block.header.parent_block_id,
        )?
        .ok_or_else(|| BlockValidateRejectReason {
            reason_code: ValidateRejectCode::InvalidBlock,
            reason: "Invalid parent block".into(),
        })?;

        let burn_view_consensus_hash =
            NakamotoChainState::get_block_burn_view(sortdb, &self.block, &parent_stacks_header)?;
        let sort_tip =
            SortitionDB::get_block_snapshot_consensus(sortdb.conn(), &burn_view_consensus_hash)?
                .ok_or_else(|| BlockValidateRejectReason {
                    reason_code: ValidateRejectCode::NoSuchTenure,
                    reason: "Failed to find sortition for block tenure".to_string(),
                })?;

        let burn_dbconn: SortitionHandleConn = sortdb.index_handle(&sort_tip.sortition_id);
        let db_handle = sortdb.index_handle(&sort_tip.sortition_id);

        // (For the signer)
        // Verify that the block's tenure is on the canonical sortition history
        Self::check_block_has_valid_tenure(&db_handle, &self.block.header.consensus_hash)?;

        // (For the signer)
        // Verify that this block's parent is the highest such block we can build off of
        Self::check_block_has_valid_parent(chainstate, &self.block)?;

        // get the burnchain tokens spent for this block. There must be a record of this (i.e.
        // there must be a block-commit for this), or otherwise this block doesn't correspond to
        // any burnchain chainstate.
        let expected_burn_opt =
            NakamotoChainState::get_expected_burns(&db_handle, chainstate.db(), &self.block)?;
        if expected_burn_opt.is_none() {
            warn!(
                "Rejected block proposal";
                "reason" => "Failed to find parent expected burns",
            );
            return Err(BlockValidateRejectReason {
                reason_code: ValidateRejectCode::UnknownParent,
                reason: "Failed to find parent expected burns".into(),
            });
        };

        // Static validation checks
        NakamotoChainState::validate_normal_nakamoto_block_burnchain(
            chainstate.nakamoto_blocks_db(),
            &db_handle,
            expected_burn_opt,
            &self.block,
            mainnet,
            self.chain_id,
        )?;

        // Validate txs against chainstate

        // Validate the block's timestamp. It must be:
        // - Greater than the parent block's timestamp
        // - At most 15 seconds into the future
        if let StacksBlockHeaderTypes::Nakamoto(parent_nakamoto_header) =
            &parent_stacks_header.anchored_header
        {
            if self.block.header.timestamp <= parent_nakamoto_header.timestamp {
                warn!(
                    "Rejected block proposal";
                    "reason" => "Block timestamp is not greater than parent block",
                    "block_timestamp" => self.block.header.timestamp,
                    "parent_block_timestamp" => parent_nakamoto_header.timestamp,
                );
                return Err(BlockValidateRejectReason {
                    reason_code: ValidateRejectCode::InvalidBlock,
                    reason: "Block timestamp is not greater than parent block".into(),
                });
            }
        }
        if self.block.header.timestamp > get_epoch_time_secs() + 15 {
            warn!(
                "Rejected block proposal";
                "reason" => "Block timestamp is too far into the future",
                "block_timestamp" => self.block.header.timestamp,
                "current_time" => get_epoch_time_secs(),
            );
            return Err(BlockValidateRejectReason {
                reason_code: ValidateRejectCode::InvalidBlock,
                reason: "Block timestamp is too far into the future".into(),
            });
        }

        let tenure_change = self
            .block
            .txs
            .iter()
            .find(|tx| matches!(tx.payload, TransactionPayload::TenureChange(..)));
        let coinbase = self
            .block
            .txs
            .iter()
            .find(|tx| matches!(tx.payload, TransactionPayload::Coinbase(..)));
        let tenure_cause = tenure_change.and_then(|tx| match &tx.payload {
            TransactionPayload::TenureChange(tc) => Some(tc.cause),
            _ => None,
        });

        let mut builder = NakamotoBlockBuilder::new(
            &parent_stacks_header,
            &self.block.header.consensus_hash,
            self.block.header.burn_spent,
            tenure_change,
            coinbase,
            self.block.header.pox_treatment.len(),
            None,
        )?;

        let mut miner_tenure_info =
            builder.load_tenure_info(chainstate, &burn_dbconn, tenure_cause)?;
        let mut tenure_tx = builder.tenure_begin(&burn_dbconn, &mut miner_tenure_info)?;

        for (i, tx) in self.block.txs.iter().enumerate() {
            let tx_len = tx.tx_len();
            let tx_result = builder.try_mine_tx_with_len(
                &mut tenure_tx,
                &tx,
                tx_len,
                &BlockLimitFunction::NO_LIMIT_HIT,
                ASTRules::PrecheckSize,
            );
            let err = match tx_result {
                TransactionResult::Success(_) => Ok(()),
                TransactionResult::Skipped(s) => Err(format!("tx {i} skipped: {}", s.error)),
                TransactionResult::ProcessingError(e) => {
                    Err(format!("Error processing tx {i}: {}", e.error))
                }
                TransactionResult::Problematic(p) => {
                    Err(format!("Problematic tx {i}: {}", p.error))
                }
            };
            if let Err(reason) = err {
                warn!(
                    "Rejected block proposal";
                    "reason" => %reason,
                    "tx" => ?tx,
                );
                return Err(BlockValidateRejectReason {
                    reason,
                    reason_code: ValidateRejectCode::BadTransaction,
                });
            }
        }

        let mut block = builder.mine_nakamoto_block(&mut tenure_tx);
        // Override the block version with the one from the proposal. This must be
        // done before computing the block hash, because the block hash includes the
        // version in its computation.
        block.header.version = self.block.header.version;
        let size = builder.get_bytes_so_far();
        let cost = builder.tenure_finish(tenure_tx)?;

        // Clone signatures from block proposal
        // These have already been validated by `validate_nakamoto_block_burnchain()``
        block.header.miner_signature = self.block.header.miner_signature.clone();
        block
            .header
            .signer_signature
            .clone_from(&self.block.header.signer_signature);

        // Clone the timestamp from the block proposal, which has already been validated
        block.header.timestamp = self.block.header.timestamp;

        // Assuming `tx_merkle_root` has been checked we don't need to hash the whole block
        let expected_block_header_hash = self.block.header.block_hash();
        let computed_block_header_hash = block.header.block_hash();

        if computed_block_header_hash != expected_block_header_hash {
            warn!(
                "Rejected block proposal";
                "reason" => "Block hash is not as expected",
                "expected_block_header_hash" => %expected_block_header_hash,
                "computed_block_header_hash" => %computed_block_header_hash,
                //"expected_block" => %serde_json::to_string(&serde_json::to_value(&self.block).unwrap()).unwrap(),
                //"computed_block" => %serde_json::to_string(&serde_json::to_value(&block).unwrap()).unwrap(),
            );
            return Err(BlockValidateRejectReason {
                reason: "Block hash is not as expected".into(),
                reason_code: ValidateRejectCode::BadBlockHash,
            });
        }

        let validation_time_ms = u64::try_from(start.elapsed().as_millis()).unwrap_or(u64::MAX);

        info!(
            "Participant: validated anchored block";
            "block_header_hash" => %computed_block_header_hash,
            "height" => block.header.chain_length,
            "tx_count" => block.txs.len(),
            "parent_stacks_block_id" => %block.header.parent_block_id,
            "block_size" => size,
            "execution_cost" => %cost,
            "validation_time_ms" => validation_time_ms,
            "tx_fees_microstacks" => block.txs.iter().fold(0, |agg: u64, tx| {
                agg.saturating_add(tx.get_tx_fee())
            })
        );

        Ok(BlockValidateOk {
            signer_signature_hash: block.header.signer_signature_hash(),
            cost,
            size,
            validation_time_ms,
        })
    }
}

#[derive(Clone, Default)]
pub struct RPCBlockProposalRequestHandler {
    pub block_proposal: Option<NakamotoBlockProposal>,
    pub auth: Option<String>,
}

impl RPCBlockProposalRequestHandler {
    pub fn new(auth: Option<String>) -> Self {
        Self {
            block_proposal: None,
            auth,
        }
    }

    /// Decode a JSON-encoded block proposal
    fn parse_json(body: &[u8]) -> Result<NakamotoBlockProposal, Error> {
        serde_json::from_slice(body)
            .map_err(|e| Error::DecodeError(format!("Failed to parse body: {e}")))
    }
}

/// Decode the HTTP request
impl HttpRequest for RPCBlockProposalRequestHandler {
    fn verb(&self) -> &'static str {
        "POST"
    }

    fn path_regex(&self) -> Regex {
        Regex::new(r#"^/v3/block_proposal$"#).unwrap()
    }

    fn metrics_identifier(&self) -> &str {
        "/v3/block_proposal"
    }

    /// Try to decode this request.
    /// There's nothing to load here, so just make sure the request is well-formed.
    fn try_parse_request(
        &mut self,
        preamble: &HttpRequestPreamble,
        _captures: &Captures,
        query: Option<&str>,
        body: &[u8],
    ) -> Result<HttpRequestContents, Error> {
        // If no authorization is set, then the block proposal endpoint is not enabled
        let Some(password) = &self.auth else {
            return Err(Error::Http(400, "Bad Request.".into()));
        };
        let Some(auth_header) = preamble.headers.get("authorization") else {
            return Err(Error::Http(401, "Unauthorized".into()));
        };
        if auth_header != password {
            return Err(Error::Http(401, "Unauthorized".into()));
        }
        if preamble.get_content_length() == 0 {
            return Err(Error::DecodeError(
                "Invalid Http request: expected non-zero-length body for block proposal endpoint"
                    .to_string(),
            ));
        }
        if preamble.get_content_length() > MAX_PAYLOAD_LEN {
            return Err(Error::DecodeError(
                "Invalid Http request: BlockProposal body is too big".to_string(),
            ));
        }

        let block_proposal = match preamble.content_type {
            Some(HttpContentType::JSON) => Self::parse_json(body)?,
            Some(_) => {
                return Err(Error::DecodeError(
                    "Wrong Content-Type for block proposal; expected application/json".to_string(),
                ))
            }
            None => {
                return Err(Error::DecodeError(
                    "Missing Content-Type for block proposal".to_string(),
                ))
            }
        };

        if block_proposal.block.is_shadow_block() {
            return Err(Error::DecodeError(
                "Shadow blocks cannot be submitted for validation".to_string(),
            ));
        }

        self.block_proposal = Some(block_proposal);
        Ok(HttpRequestContents::new().query_string(query))
    }
}

struct ProposalThreadInfo {
    sortdb: SortitionDB,
    chainstate: StacksChainState,
    receiver: Box<dyn ProposalCallbackReceiver>,
}

impl RPCRequestHandler for RPCBlockProposalRequestHandler {
    /// Reset internal state
    fn restart(&mut self) {
        self.block_proposal = None
    }

    /// Make the response
    fn try_handle_request(
        &mut self,
        preamble: HttpRequestPreamble,
        _contents: HttpRequestContents,
        node: &mut StacksNodeState,
    ) -> Result<(HttpResponsePreamble, HttpResponseContents), NetError> {
        let block_proposal = self
            .block_proposal
            .take()
            .ok_or(NetError::SendError("`block_proposal` not set".into()))?;

        info!(
            "Received block proposal request";
            "signer_sighash" => %block_proposal.block.header.signer_signature_hash(),
            "block_header_hash" => %block_proposal.block.header.block_hash(),
            "height" => block_proposal.block.header.chain_length,
            "tx_count" => block_proposal.block.txs.len(),
            "parent_stacks_block_id" => %block_proposal.block.header.parent_block_id,
        );

        let res = node.with_node_state(|network, sortdb, chainstate, _mempool, rpc_args| {
            if network.is_proposal_thread_running() {
                return Err((
                    TOO_MANY_REQUESTS_STATUS,
                    NetError::SendError("Proposal currently being evaluated".into()),
                ));
            }

            if block_proposal
                .block
                .header
                .timestamp
                .saturating_add(network.get_connection_opts().block_proposal_max_age_secs)
                < get_epoch_time_secs()
            {
                return Err((
                    422,
                    NetError::SendError("Block proposal is too old to process.".into()),
                ));
            }

            let (chainstate, _) = chainstate.reopen().map_err(|e| (400, NetError::from(e)))?;
            let sortdb = sortdb.reopen().map_err(|e| (400, NetError::from(e)))?;
            let receiver = rpc_args
                .event_observer
                .and_then(|observer| observer.get_proposal_callback_receiver())
                .ok_or_else(|| {
                    (
                        400,
                        NetError::SendError(
                            "No `observer` registered for receiving proposal callbacks".into(),
                        ),
                    )
                })?;
            let thread_info = block_proposal
                .spawn_validation_thread(sortdb, chainstate, receiver)
                .map_err(|_e| {
                    (
                        TOO_MANY_REQUESTS_STATUS,
                        NetError::SendError(
                            "IO error while spawning proposal callback thread".into(),
                        ),
                    )
                })?;
            network.set_proposal_thread(thread_info);
            Ok(())
        });

        match res {
            Ok(_) => {
                let mut preamble = HttpResponsePreamble::accepted_json(&preamble);
                preamble.set_canonical_stacks_tip_height(Some(node.canonical_stacks_tip_height()));
                let body = HttpResponseContents::try_from_json(&serde_json::json!({
                    "result": "Accepted",
                    "message": "Block proposal is processing, result will be returned via the event observer"
                }))?;
                Ok((preamble, body))
            }
            Err((code, err)) => {
                let mut preamble = HttpResponsePreamble::error_json(code, http_reason(code));
                preamble.set_canonical_stacks_tip_height(Some(node.canonical_stacks_tip_height()));
                let body = HttpResponseContents::try_from_json(&serde_json::json!({
                    "result": "Error",
                    "message": format!("Could not process block proposal request: {err}")
                }))?;
                Ok((preamble, body))
            }
        }
    }
}

/// Decode the HTTP response
impl HttpResponse for RPCBlockProposalRequestHandler {
    fn try_parse_response(
        &self,
        preamble: &HttpResponsePreamble,
        body: &[u8],
    ) -> Result<HttpResponsePayload, Error> {
        let response: BlockProposalResponse = parse_json(preamble, body)?;
        HttpResponsePayload::try_from_json(response)
    }
}
