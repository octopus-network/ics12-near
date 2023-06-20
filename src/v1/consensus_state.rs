use super::{
    error::Error as StateProofVerificationError,
    error::Error as Ics12Error,
    header::Header,
    near_types::{
        hash::{sha256, CryptoHash},
        trie::{verify_not_in_state, verify_state_proof, RawTrieNodeWithSize},
        ValidatorStakeView,
    },
};
use crate::prelude::*;
use alloc::vec::Vec;
use borsh::{BorshDeserialize, BorshSerialize};
use ibc::core::{
    ics02_client::error::ClientError, ics23_commitment::commitment::CommitmentRoot,
    timestamp::Timestamp,
};
use ibc_proto::{
    google::protobuf::Any,
    ibc::lightclients::near::v1::{
        ConsensusState as ProtoConsensusState, ValidatorStakeView as ProtoValidatorStakeView,
    },
    protobuf::Protobuf,
};
use prost::Message;
use serde::{Deserialize, Serialize};

pub const NEAR_CONSENSUS_STATE_TYPE_URL: &str = "/ibc.lightclients.near.v1.ConsensusState";

/// The consensus state of NEAR light client.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq)]
pub struct ConsensusState {
    /// Block producers of current epoch
    pub current_bps: Option<Vec<ValidatorStakeView>>,
    /// Header data
    pub header: Header,
    /// Commitment root
    pub commitment_root: CommitmentRoot,
}

impl ConsensusState {
    /// Returns the block producers corresponding to current epoch or the next.
    pub fn get_block_producers_of(&self, epoch_id: &CryptoHash) -> Option<Vec<ValidatorStakeView>> {
        if *epoch_id == self.header.epoch_id() {
            return self.current_bps.clone();
        } else if *epoch_id == self.header.next_epoch_id() {
            return self.header.light_client_block.next_bps.clone();
        } else {
            return None;
        }
    }

    /// Verify the value of a certain storage key with proof data.
    ///
    /// The `proofs` must be the proof data at `height - 1`.
    pub fn verify_membership(
        &self,
        key: &[u8],
        value: &[u8],
        proofs: &Vec<Vec<u8>>,
    ) -> Result<(), StateProofVerificationError> {
        if proofs.len() == 0 {
            return Err(StateProofVerificationError::MissingProofData);
        }
        let root_hash = CryptoHash(sha256(proofs[0].as_ref()));
        if !self.header.prev_state_root_of_chunks.contains(&root_hash) {
            return Err(StateProofVerificationError::InvalidRootHashOfProofData);
        }
        let mut nodes: Vec<RawTrieNodeWithSize> = Vec::new();
        let mut proof_index: u16 = 0;
        for proof in proofs {
            if let Ok(node) = RawTrieNodeWithSize::decode(proof) {
                nodes.push(node);
            } else {
                return Err(StateProofVerificationError::InvalidProofData { proof_index });
            }
            proof_index += 1;
        }
        return verify_state_proof(&key, &nodes, value, &root_hash);
    }

    /// Verify that the value of a certain storage key is empty with proof data.
    ///
    /// The `proofs` must be the proof data at `height - 1`.
    pub fn verify_non_membership(
        &self,
        key: &[u8],
        proofs: &Vec<Vec<u8>>,
    ) -> Result<bool, StateProofVerificationError> {
        if proofs.len() == 0 {
            return Err(StateProofVerificationError::MissingProofData);
        }
        let root_hash = CryptoHash(sha256(proofs[0].as_ref()));
        if !self.header.prev_state_root_of_chunks.contains(&root_hash) {
            return Err(StateProofVerificationError::InvalidRootHashOfProofData);
        }
        let mut nodes: Vec<RawTrieNodeWithSize> = Vec::new();
        let mut proof_index: u16 = 0;
        for proof in proofs {
            if let Ok(node) = RawTrieNodeWithSize::decode(proof) {
                nodes.push(node);
            } else {
                return Err(StateProofVerificationError::InvalidProofData { proof_index });
            }
            proof_index += 1;
        }
        return verify_not_in_state(&key, &nodes, &root_hash);
    }
}

impl ibc::core::ics02_client::consensus_state::ConsensusState for ConsensusState {
    fn root(&self) -> &CommitmentRoot {
        &self.commitment_root
    }

    fn timestamp(&self) -> Timestamp {
        Timestamp::from_nanoseconds(self.header.light_client_block.inner_lite.timestamp)
            .expect("Invalid timestamp")
    }
}

impl Protobuf<ProtoConsensusState> for ConsensusState {}

impl TryFrom<ProtoConsensusState> for ConsensusState {
    type Error = Ics12Error;

    fn try_from(value: ProtoConsensusState) -> Result<Self, Self::Error> {
        let bps = value
            .current_bps
            .iter()
            .map(|vsv| {
                ValidatorStakeView::try_from_slice(&vsv.raw_data)
                    .map_err(|_| Ics12Error::BorshDeserializeError)
            })
            .collect::<Result<Vec<ValidatorStakeView>, Ics12Error>>()?;
        let current_bps = match bps.len() {
            0 => None,
            _ => Some(bps),
        };
        let header: Header = value.header.ok_or(Ics12Error::MissingHeader)?.try_into()?;
        let mut data = current_bps
            .try_to_vec()
            .map_err(|_| Ics12Error::BorshSerializeError)?;
        data.extend(
            header
                .try_to_vec()
                .map_err(|_| Ics12Error::BorshSerializeError)?,
        );
        Ok(Self {
            current_bps,
            header,
            commitment_root: CommitmentRoot::from(sha256(&data).to_vec()),
        })
    }
}

impl From<ConsensusState> for ProtoConsensusState {
    fn from(value: ConsensusState) -> Self {
        Self {
            current_bps: match value.current_bps {
                None => Vec::new(),
                Some(bps) => bps
                    .into_iter()
                    .map(|vsv| ProtoValidatorStakeView {
                        raw_data: vsv.try_to_vec().unwrap(),
                    })
                    .collect(),
            },
            header: Some(value.header.into()),
        }
    }
}

impl Protobuf<Any> for ConsensusState {}

impl TryFrom<Any> for ConsensusState {
    type Error = ClientError;

    fn try_from(raw: Any) -> Result<Self, Self::Error> {
        use bytes::Buf;
        use core::ops::Deref;

        fn decode_consensus_state<B: Buf>(buf: B) -> Result<ConsensusState, Ics12Error> {
            ProtoConsensusState::decode(buf)
                .map_err(Ics12Error::Decode)?
                .try_into()
        }

        match raw.type_url.as_str() {
            NEAR_CONSENSUS_STATE_TYPE_URL => {
                decode_consensus_state(raw.value.deref()).map_err(Into::into)
            }
            _ => Err(ClientError::UnknownConsensusStateType {
                consensus_state_type: raw.type_url,
            }),
        }
    }
}

impl From<ConsensusState> for Any {
    fn from(consensus_state: ConsensusState) -> Self {
        Any {
            type_url: NEAR_CONSENSUS_STATE_TYPE_URL.to_string(),
            value: Protobuf::<ProtoConsensusState>::encode_vec(&consensus_state),
        }
    }
}
