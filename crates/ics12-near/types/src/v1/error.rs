//! Defines the near light client's error type

use alloc::string::String;
use alloc::string::ToString;
use core::time::Duration;
use displaydoc::Display;
use ibc_core::client::types::error::ClientError;
use ibc_core::client::types::Height;
use ibc_core::host::types::identifiers::{ChainId, ClientId};

/// The main error type
#[derive(Debug, Display)]
pub enum Error {
    /// chain-id is (`{chain_id}`) is too long, got: `{len}`, max allowed: `{max_len}`
    ChainIdTooLong {
        chain_id: ChainId,
        len: usize,
        max_len: usize,
    },
    /// invalid header, failed basic validation: `{reason}`, error: `{error}`
    InvalidHeader { reason: String, error: String },
    /// invalid client state trust threshold: `{reason}`
    InvalidTrustThreshold { reason: String },
    /// invalid client state max clock drift: `{reason}`
    InvalidMaxClockDrift { reason: String },
    /// invalid client state latest height: `{reason}`
    InvalidLatestHeight { reason: String },
    /// missing header
    MissingHeader,
    /// invalid header, failed basic validation: `{reason}`
    Validation { reason: String },
    /// invalid raw client state: `{reason}`
    InvalidRawClientState { reason: String },
    /// missing validator set
    MissingValidatorSet,
    /// missing trusted next validator set
    MissingTrustedNextValidatorSet,
    /// missing trusted height
    MissingTrustedHeight,
    /// missing trusting period
    MissingTrustingPeriod,
    /// missing unbonding period
    MissingUnbondingPeriod,
    /// negative max clock drift
    NegativeMaxClockDrift,
    /// missing latest height
    MissingLatestHeight,
    /// invalid raw misbehaviour: `{reason}`
    InvalidRawMisbehaviour { reason: String },
    /// decode error: `{0}`
    Decode(prost::DecodeError),
    /// given other previous updates, header timestamp should be at most `{max}`, but was `{actual}`
    HeaderTimestampTooHigh { actual: String, max: String },
    /// given other previous updates, header timestamp should be at least `{min}`, but was `{actual}`
    HeaderTimestampTooLow { actual: String, min: String },
    /// header revision height = `{height}` is invalid
    InvalidHeaderHeight { height: u64 },
    /// Disallowed to create a new client with a frozen height
    FrozenHeightNotAllowed,
    /// the header's trusted revision number (`{trusted_revision}`) and the update's revision number (`{header_revision}`) should be the same
    MismatchHeightRevisions {
        trusted_revision: u64,
        header_revision: u64,
    },
    /// the given chain-id (`{given}`) does not match the chain-id of the client (`{expected}`)
    MismatchHeaderChainId { given: String, expected: String },
    /// Processed time for the client `{client_id}` at height `{height}` not found
    ProcessedTimeNotFound { client_id: ClientId, height: Height },
    /// Processed height for the client `{client_id}` at height `{height}` not found
    ProcessedHeightNotFound { client_id: ClientId, height: Height },
    /// current timestamp minus the latest consensus state timestamp is greater than or equal to the trusting period (`{duration_since_consensus_state:?}` >= `{trusting_period:?}`)
    ConsensusStateTimestampGteTrustingPeriod {
        duration_since_consensus_state: Duration,
        trusting_period: Duration,
    },
    /// headers block hashes are equal
    MisbehaviourHeadersBlockHashesEqual,
    /// headers are not at same height and are monotonically increasing
    MisbehaviourHeadersNotAtSameHeight,
    /// invalid raw client id: `{client_id}`
    InvalidRawClientId { client_id: String },
    /// missing proof data
    MissingProofData,
    /// invalid root hash of proof data
    InvalidRootHashOfProofData,
    /// invalid proof data
    InvalidProofData { proof_index: u16 },
    /// invalid proof data length
    InvalidProofDataLength,
    /// specified key has value in state
    SpecifiedKeyHasValueInState,
    /// failed to deserialize with borsh
    BorshDeserializeError,
    /// failed to serialize with borsh
    BorshSerializeError,
}

#[cfg(feature = "std")]
impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match &self {
            Self::Decode(e) => Some(e),
            _ => None,
        }
    }
}

impl From<Error> for ClientError {
    fn from(e: Error) -> Self {
        Self::ClientSpecific {
            description: e.to_string(),
        }
    }
}

pub(crate) trait IntoResult<T, E> {
    fn into_result(self) -> Result<T, E>;
}
