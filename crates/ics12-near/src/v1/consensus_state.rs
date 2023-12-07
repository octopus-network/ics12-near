use alloc::vec::Vec;
use ibc_core::client::types::error::ClientError;
use ibc_core::commitment_types::commitment::CommitmentRoot;
use ibc_core::primitives::Timestamp;
use ibc_proto::{google::protobuf::Any, Protobuf};
use ics12_near_types::v1::consensus_state::ConsensusState as ConsensusStateType;
use ics12_near_types::v1::error::Error;
use ics12_proto::v1::ConsensusState as RawNearConsensusState;

pub const NEAR_CONSENSUS_STATE_TYPE_URL: &str = "/ibc.lightclients.near.v1.ConsensusState";

/// Newtype wrapper around the `ConsensusState` type imported from the
/// `ibc-client-tendermint-types` crate. This wrapper exists so that we can
/// bypass Rust's orphan rules and implement traits from
/// `ibc::core::client::context` on the `ConsensusState` type.
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[derive(Clone, Debug, PartialEq)]
pub struct ConsensusState(ConsensusStateType);

impl ConsensusState {
    pub fn inner(&self) -> &ConsensusStateType {
        &self.0
    }
}

impl From<ConsensusStateType> for ConsensusState {
    fn from(consensus_state: ConsensusStateType) -> Self {
        Self(consensus_state)
    }
}

impl Protobuf<RawNearConsensusState> for ConsensusState {}

impl TryFrom<RawNearConsensusState> for ConsensusState {
    type Error = Error;

    fn try_from(raw: RawNearConsensusState) -> Result<Self, Self::Error> {
        Ok(Self(ConsensusStateType::try_from(raw)?))
    }
}

impl From<ConsensusState> for RawNearConsensusState {
    fn from(consensus_state: ConsensusState) -> Self {
        consensus_state.0.into()
    }
}

impl Protobuf<Any> for ConsensusState {}

impl TryFrom<Any> for ConsensusState {
    type Error = ClientError;

    fn try_from(raw: Any) -> Result<Self, Self::Error> {
        Ok(Self(ConsensusStateType::try_from(raw)?))
    }
}

impl From<ConsensusState> for Any {
    fn from(client_state: ConsensusState) -> Self {
        client_state.0.into()
    }
}

impl ibc_core::client::context::consensus_state::ConsensusState for ConsensusState {
    fn root(&self) -> &CommitmentRoot {
        &self.0.commitment_root
    }

    fn timestamp(&self) -> Timestamp {
        Timestamp::from_nanoseconds(self.0.header.raw_timestamp()).expect("Invalid timestamp")
    }

    /// Serializes the `ConsensusState`. This is expected to be implemented as
    /// first converting to the raw type (i.e. the protobuf definition), and then
    /// serializing that.
    fn encode_vec(self) -> Vec<u8> {
        <Self as Protobuf<Any>>::encode_vec(self)
    }
}
