use super::{
    error::Error as Ics12Error,
    header::Header,
    near_types::{hash::CryptoHash, ValidatorStakeView},
};
use alloc::string::ToString;
use alloc::vec::Vec;
use borsh::to_vec;
use borsh::BorshDeserialize;
use ibc_core::client::types::error::ClientError;
use ibc_core::commitment_types::commitment::CommitmentRoot;
use ibc_proto::{google::protobuf::Any, Protobuf};
use ics12_proto::v1::{
    ConsensusState as RawConsensusState, ValidatorStakeView as RawValidatorStakeView,
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
    ///
    pub fn new(current_bps: Option<Vec<ValidatorStakeView>>, header: Header) -> Self {
        let mut data = to_vec(&current_bps).expect("Failed to serialize current bps.");
        data.extend(to_vec(&header).expect("Failed to serialize header."));
        Self {
            current_bps,
            header: header.clone(),
            commitment_root: CommitmentRoot::from(
                to_vec(&header.prev_state_root_of_chunks)
                    .expect("Failed to serialize `prev_state_root_of_chunks` of header."),
            ),
        }
    }
    /// Returns the block producers corresponding to current epoch or the next.
    pub fn get_block_producers_of(&self, epoch_id: &CryptoHash) -> Option<Vec<ValidatorStakeView>> {
        if *epoch_id == self.header.epoch_id() {
            self.current_bps.clone()
        } else if *epoch_id == self.header.next_epoch_id() {
            return self.header.light_client_block.next_bps.clone();
        } else {
            return None;
        }
    }
}

impl Protobuf<RawConsensusState> for ConsensusState {}

impl TryFrom<RawConsensusState> for ConsensusState {
    type Error = Ics12Error;

    fn try_from(value: RawConsensusState) -> Result<Self, Self::Error> {
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
        Ok(Self::new(current_bps, header))
    }
}

impl From<ConsensusState> for RawConsensusState {
    fn from(value: ConsensusState) -> Self {
        Self {
            current_bps: match value.current_bps {
                None => Vec::new(),
                Some(bps) => bps
                    .into_iter()
                    .map(|vsv| RawValidatorStakeView {
                        raw_data: to_vec(&vsv).expect("never failed"),
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
            RawConsensusState::decode(buf)
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
            value: Protobuf::<RawConsensusState>::encode_vec(consensus_state),
        }
    }
}
