mod misbehaviour;
mod update_client;

use super::{
    consensus_state::ConsensusState as NearConsensusState, error::Error as Ics12Error,
    header::Header as NearHeader, misbehaviour::Misbehaviour as NearMisbehaviour,
};
use crate::v1::context::ExecutionContext as NearExecutionContext;
use crate::v1::context::ValidationContext as NearValidationContext;
use crate::{
    prelude::*,
    v1::near_types::{
        hash::{sha256, CryptoHash},
        trie::{verify_not_in_state, verify_state_proof, RawTrieNodeWithSize},
    },
};
use borsh::BorshDeserialize;
use core::{cmp::max, time::Duration};
use ibc::core::ics02_client::client_state::{
    ClientStateCommon, ClientStateExecution, ClientStateValidation, Status, UpdateKind,
};
use ibc::core::ics02_client::ClientExecutionContext;
use ibc::{
    core::{
        ics02_client::{
            client_type::ClientType, consensus_state::ConsensusState, error::ClientError,
        },
        ics23_commitment::{
            commitment::{CommitmentPrefix, CommitmentProofBytes, CommitmentRoot},
            error::CommitmentError,
        },
        ics24_host::{
            identifier::ClientId,
            path::{ClientConsensusStatePath, ClientStatePath, Path},
        },
        timestamp::ZERO_DURATION,
    },
    Height,
};
use ibc_proto::{google::protobuf::Any, protobuf::Protobuf};
use ics12_proto::v1::ClientState as RawClientState;
use prost::{DecodeError, Message};
use serde::{Deserialize, Serialize};

const NEAR_CLIENT_STATE_TYPE_URL: &str = "/ibc.lightclients.near.v1.ClientState";

#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
pub struct ClientState {
    pub trusting_period: Duration,
    /// Block height when the client was frozen due to a misbehaviour
    pub frozen_height: Option<Height>,
    /// Latest height the client was updated to
    pub latest_height: Height,
    /// Latest timestamp the client was updated to
    pub latest_timestamp: u64,
    ///
    pub upgrade_commitment_prefix: Vec<u8>,
    ///
    pub upgrade_key: Vec<u8>,
}

impl ClientState {
    pub fn new_without_validation(
        trusting_period: Duration,
        latest_height: Height,
        latest_timestamp: u64,
    ) -> Self {
        Self {
            trusting_period,
            frozen_height: None,
            latest_height,
            latest_timestamp,
            upgrade_commitment_prefix: vec![],
            upgrade_key: vec![],
        }
    }
    ///
    pub fn with_header(self, header: &NearHeader) -> Result<Self, Ics12Error> {
        Ok(ClientState {
            latest_height: max(header.height(), self.latest_height),
            ..self
        })
    }
    ///
    pub fn with_timestamp(self, timestamp: u64) -> Self {
        Self {
            latest_timestamp: timestamp,
            ..self
        }
    }
    ///
    pub fn with_frozen_height(self, h: Height) -> Self {
        Self {
            frozen_height: Some(h),
            ..self
        }
    }
    // Resets custom fields to zero values (used in `update_client`)
    pub fn zero_custom_fields(&mut self) {
        self.trusting_period = ZERO_DURATION;
        self.frozen_height = None;
    }

    fn is_frozen(&self) -> bool {
        self.frozen_height.is_some()
    }
}

impl ClientStateCommon for ClientState {
    fn verify_consensus_state(&self, consensus_state: Any) -> Result<(), ClientError> {
        let near_consensus_state = NearConsensusState::try_from(consensus_state)?;
        if near_consensus_state.root().is_empty() {
            return Err(ClientError::Other {
                description: "empty commitment root".into(),
            });
        };

        Ok(())
    }

    fn client_type(&self) -> ClientType {
        crate::v1::client_type()
    }

    fn latest_height(&self) -> Height {
        self.latest_height
    }

    fn validate_proof_height(&self, proof_height: Height) -> Result<(), ClientError> {
        if self.latest_height() < proof_height {
            return Err(ClientError::InvalidProofHeight {
                latest_height: self.latest_height(),
                proof_height,
            });
        }
        Ok(())
    }

    /// Perform client-specific verifications and check all data in the new
    /// client state to be the same across all valid Tendermint clients for the
    /// new chain.
    ///
    /// You can learn more about how to upgrade IBC-connected SDK chains in
    /// [this](https://ibc.cosmos.network/main/ibc/upgrades/quick-guide.html)
    /// guide
    fn verify_upgrade_client(
        &self,
        _upgraded_client_state: Any,
        _upgraded_consensus_state: Any,
        _proof_upgrade_client: CommitmentProofBytes,
        _proof_upgrade_consensus_state: CommitmentProofBytes,
        _root: &CommitmentRoot,
    ) -> Result<(), ClientError> {
        // Since `verify_upgrade_client` function is unavailable in the NEAR Protocol,
        // this function should also not be allowed to be used in order to ensure that
        // all state updates are properly verified.
        Err(ClientError::Other {
            description: "This function is NOT available in NEAR client.".to_string(),
        })
    }

    fn verify_membership(
        &self,
        prefix: &CommitmentPrefix,
        proof: &CommitmentProofBytes,
        root: &CommitmentRoot,
        path: Path,
        value: Vec<u8>,
    ) -> Result<(), ClientError> {
        #[derive(BorshDeserialize)]
        struct Proofs(Vec<Vec<u8>>);
        let proofs = Proofs::try_from_slice(&Vec::<u8>::from(proof.clone())).map_err(|e| {
            ClientError::InvalidCommitmentProof(CommitmentError::CommitmentProofDecodingFailed(
                DecodeError::new(format!("Invalid commitment proof: {:?}", e)),
            ))
        })?;
        if proofs.0.is_empty() {
            return Err(ClientError::InvalidCommitmentProof(
                CommitmentError::EmptyMerkleProof,
            ));
        }
        let root_hash = CryptoHash(sha256(proofs.0[0].as_ref()));
        #[derive(BorshDeserialize)]
        struct StateProofOfChunks(Vec<CryptoHash>);
        let prev_state_root_of_chunks = StateProofOfChunks::try_from_slice(root.as_bytes())
            .map_err(|e| {
                ClientError::InvalidCommitmentProof(CommitmentError::CommitmentProofDecodingFailed(
                    DecodeError::new(format!("Invalid commitment root: {:?}", e)),
                ))
            })?;
        if !prev_state_root_of_chunks.0.contains(&root_hash) {
            return Err(ClientError::InvalidCommitmentProof(
                CommitmentError::VerificationFailure,
            ));
        }
        let mut nodes: Vec<RawTrieNodeWithSize> = Vec::new();
        for proof in &proofs.0 {
            if let Ok(node) = RawTrieNodeWithSize::decode(proof) {
                nodes.push(node);
            } else {
                return Err(ClientError::InvalidCommitmentProof(
                    CommitmentError::CommitmentProofDecodingFailed(DecodeError::new(
                        "Invalid commitment proof: path proof data decode failed.",
                    )),
                ));
            }
        }
        let mut key = vec![];
        key.extend(prefix.as_bytes());
        key.extend(path.to_string().into_bytes());
        verify_state_proof(&key, &nodes, &value, &root_hash).map_err(|e| ClientError::Other {
            description: format!("{:?}", e),
        })
    }

    fn verify_non_membership(
        &self,
        prefix: &CommitmentPrefix,
        proof: &CommitmentProofBytes,
        root: &CommitmentRoot,
        path: Path,
    ) -> Result<(), ClientError> {
        #[derive(BorshDeserialize)]
        struct Proofs(Vec<Vec<u8>>);
        let proofs = Proofs::try_from_slice(&Vec::<u8>::from(proof.clone())).map_err(|e| {
            ClientError::InvalidCommitmentProof(CommitmentError::CommitmentProofDecodingFailed(
                DecodeError::new(format!("Invalid commitment proof: {:?}", e)),
            ))
        })?;
        if proofs.0.is_empty() {
            return Err(ClientError::InvalidCommitmentProof(
                CommitmentError::EmptyMerkleProof,
            ));
        }
        let root_hash = CryptoHash(sha256(proofs.0[0].as_ref()));
        #[derive(BorshDeserialize)]
        struct StateProofOfChunks(Vec<CryptoHash>);
        let prev_state_root_of_chunks = StateProofOfChunks::try_from_slice(root.as_bytes())
            .map_err(|e| {
                ClientError::InvalidCommitmentProof(CommitmentError::CommitmentProofDecodingFailed(
                    DecodeError::new(format!("Invalid commitment root: {:?}", e)),
                ))
            })?;
        if !prev_state_root_of_chunks.0.contains(&root_hash) {
            return Err(ClientError::InvalidCommitmentProof(
                CommitmentError::VerificationFailure,
            ));
        }
        let mut nodes: Vec<RawTrieNodeWithSize> = Vec::new();
        for proof in &proofs.0 {
            if let Ok(node) = RawTrieNodeWithSize::decode(proof) {
                nodes.push(node);
            } else {
                return Err(ClientError::InvalidCommitmentProof(
                    CommitmentError::CommitmentProofDecodingFailed(DecodeError::new(
                        "Invalid commitment proof: path proof data decode failed.",
                    )),
                ));
            }
        }
        let mut key = vec![];
        key.extend(prefix.as_bytes());
        key.extend(path.to_string().into_bytes());
        verify_not_in_state(&key, &nodes, &root_hash).map_err(|e| ClientError::Other {
            description: format!("{:?}", e),
        })
    }
}

impl<ClientValidationContext> ClientStateValidation<ClientValidationContext> for ClientState
where
    ClientValidationContext: NearValidationContext,
    ClientValidationContext::AnyConsensusState: TryInto<NearConsensusState>,
    ClientError:
        From<<ClientValidationContext::AnyConsensusState as TryInto<NearConsensusState>>::Error>,
{
    fn verify_client_message(
        &self,
        ctx: &ClientValidationContext,
        client_id: &ClientId,
        client_message: Any,
        update_kind: &UpdateKind,
    ) -> Result<(), ClientError> {
        match update_kind {
            UpdateKind::UpdateClient => {
                let header = NearHeader::try_from(client_message)?;
                self.verify_header(ctx, client_id, &header)
            }
            UpdateKind::SubmitMisbehaviour => {
                let misbehaviour = NearMisbehaviour::try_from(client_message)?;
                self.verify_misbehaviour(ctx, client_id, misbehaviour)
            }
        }
    }

    fn check_for_misbehaviour(
        &self,
        ctx: &ClientValidationContext,
        client_id: &ClientId,
        client_message: Any,
        update_kind: &UpdateKind,
    ) -> Result<bool, ClientError> {
        match update_kind {
            UpdateKind::UpdateClient => {
                let header = NearHeader::try_from(client_message)?;
                self.check_for_misbehaviour_update_client(ctx, client_id, header)
            }
            UpdateKind::SubmitMisbehaviour => {
                let misbehaviour = NearMisbehaviour::try_from(client_message)?;
                self.check_for_misbehaviour_misbehaviour(&misbehaviour)
            }
        }
    }

    fn status(
        &self,
        ctx: &ClientValidationContext,
        client_id: &ClientId,
    ) -> Result<Status, ClientError> {
        if self.is_frozen() {
            return Ok(Status::Frozen);
        }

        let latest_consensus_state: NearConsensusState = {
            let any_latest_consensus_state = match ctx.consensus_state(
                &ClientConsensusStatePath::new(client_id, &self.latest_height),
            ) {
                Ok(cs) => cs,
                // if the client state does not have an associated consensus state for its latest height
                // then it must be expired
                Err(_) => return Ok(Status::Expired),
            };

            any_latest_consensus_state.try_into()?
        };

        // Note: if the `duration_since()` is `None`, indicating that the latest
        // consensus state is in the future, then we don't consider the client
        // to be expired.
        let now = ctx.host_timestamp()?;
        if let Some(elapsed_since_latest_consensus_state) =
            now.duration_since(&latest_consensus_state.timestamp())
        {
            if elapsed_since_latest_consensus_state > self.trusting_period {
                return Ok(Status::Expired);
            }
        }

        Ok(Status::Active)
    }
}

impl<E> ClientStateExecution<E> for ClientState
where
    E: NearExecutionContext,
    <E as ClientExecutionContext>::AnyClientState: From<ClientState>,
    <E as ClientExecutionContext>::AnyConsensusState: From<NearConsensusState>,
{
    fn initialise(
        &self,
        ctx: &mut E,
        client_id: &ClientId,
        consensus_state: Any,
    ) -> Result<(), ClientError> {
        let near_consensus_state = NearConsensusState::try_from(consensus_state)?;
        if near_consensus_state.root().is_empty() {
            return Err(ClientError::Other {
                description: "empty commitment root".into(),
            });
        };

        ctx.store_client_state(ClientStatePath::new(client_id), self.clone().into())?;
        ctx.store_consensus_state(
            ClientConsensusStatePath::new(client_id, &self.latest_height()),
            near_consensus_state.into(),
        )?;
        Ok(())
    }

    // todo(davirain): refactor reference to [https://github.com/cosmos/ibc-rs/blob/b6ad8ce55954f2678b57caa0b94feaea3f8eddac/crates/ibc/src/clients/ics07_tendermint/client_state.rs#L493]
    fn update_state(
        &self,
        ctx: &mut E,
        client_id: &ClientId,
        header: Any,
    ) -> Result<Vec<Height>, ClientError> {
        let header = NearHeader::try_from(header)?;
        let header_height = header.height();

        let maybe_existing_consensus_state = {
            let path_at_header_height = ClientConsensusStatePath::new(client_id, &header_height);

            ctx.consensus_state(&path_at_header_height).ok()
        };

        if maybe_existing_consensus_state.is_some() {
            // if we already had the header installed by a previous relayer
            // then this is a no-op.
            //
            // Do nothing.
        } else {
            let maybe_prev_cs = ctx.prev_consensus_state(client_id, &header.height())?;

            let new_consensus_state = match maybe_prev_cs {
                Some(prev_cs) => {
                    // New header timestamp cannot occur *before* the
                    // previous consensus state's height
                    let prev_cs: NearConsensusState =
                        prev_cs.try_into().map_err(|err| ClientError::Other {
                            description: err.to_string(),
                        })?;
                    NearConsensusState::new(
                        prev_cs.get_block_producers_of(&header.epoch_id()),
                        header.clone(),
                    )
                }
                None => NearConsensusState::new(None, header.clone()),
            };

            let new_client_state = self
                .clone()
                .with_header(&header)?
                .with_timestamp(new_consensus_state.timestamp().nanoseconds());

            ctx.store_update_time(
                client_id.clone(),
                new_client_state.latest_height(),
                ctx.host_timestamp()?,
            )?;
            ctx.store_update_height(
                client_id.clone(),
                new_client_state.latest_height(),
                ctx.host_height()?,
            )?;

            ctx.store_consensus_state(
                ClientConsensusStatePath::new(client_id, &new_client_state.latest_height),
                new_consensus_state.into(),
            )?;
            ctx.store_client_state(ClientStatePath::new(client_id), new_client_state.into())?;
        }

        let updated_heights = vec![header_height];
        Ok(updated_heights)
    }

    fn update_state_on_misbehaviour(
        &self,
        ctx: &mut E,
        client_id: &ClientId,
        _client_message: Any,
        _update_kind: &UpdateKind,
    ) -> Result<(), ClientError> {
        let frozen_client_state = self.clone().with_frozen_height(Height::min(0));

        ctx.store_client_state(ClientStatePath::new(client_id), frozen_client_state.into())?;
        Ok(())
    }

    // Commit the new client state and consensus state to the store
    fn update_state_on_upgrade(
        &self,
        _ctx: &mut E,
        _client_id: &ClientId,
        _upgraded_client_state: Any,
        _upgraded_consensus_state: Any,
    ) -> Result<Height, ClientError> {
        // Since `verify_upgrade_client` function is unavailable in the NEAR Protocol,
        // this function should also not be allowed to be used in order to ensure that
        // all state updates are properly verified.
        Err(ClientError::Other {
            description: "This function is NOT available in NEAR client.".to_string(),
        })
    }
}

impl Protobuf<RawClientState> for ClientState {}

impl TryFrom<RawClientState> for ClientState {
    type Error = Ics12Error;

    fn try_from(value: RawClientState) -> Result<Self, Self::Error> {
        let trusting_period = value
            .trusting_period
            .ok_or(Ics12Error::MissingTrustingPeriod)?
            .try_into()
            .map_err(|_| Ics12Error::MissingTrustingPeriod)?;

        let latest_height = value
            .latest_height
            .ok_or(Ics12Error::MissingLatestHeight)?
            .try_into()
            .map_err(|_| Ics12Error::MissingLatestHeight)?;

        // In `RawClientState`, a `frozen_height` of `0` means "not frozen".
        // See:
        // https://github.com/cosmos/ibc-go/blob/8422d0c4c35ef970539466c5bdec1cd27369bab3/modules/light-clients/07-tendermint/types/client_state.go#L74
        if value
            .frozen_height
            .and_then(|h| Height::try_from(h).ok())
            .is_some()
        {
            return Err(Ics12Error::FrozenHeightNotAllowed);
        }

        let client_state = ClientState::new_without_validation(
            trusting_period,
            latest_height,
            value.latest_timestamp,
        );

        Ok(client_state)
    }
}

impl From<ClientState> for RawClientState {
    fn from(value: ClientState) -> Self {
        Self {
            trusting_period: Some(value.trusting_period.into()),
            frozen_height: value.frozen_height.map(Into::into),
            latest_height: Some(value.latest_height.into()),
            latest_timestamp: value.latest_timestamp,
            upgrade_commitment_prefix: value.upgrade_commitment_prefix,
            upgrade_key: value.upgrade_key,
        }
    }
}

impl Protobuf<Any> for ClientState {}

impl TryFrom<Any> for ClientState {
    type Error = ClientError;

    fn try_from(raw: Any) -> Result<Self, Self::Error> {
        use bytes::Buf;
        use core::ops::Deref;

        fn decode_client_state<B: Buf>(buf: B) -> Result<ClientState, Ics12Error> {
            RawClientState::decode(buf)
                .map_err(Ics12Error::Decode)?
                .try_into()
        }

        match raw.type_url.as_str() {
            NEAR_CLIENT_STATE_TYPE_URL => {
                decode_client_state(raw.value.deref()).map_err(Into::into)
            }
            _ => Err(ClientError::UnknownClientStateType {
                client_state_type: raw.type_url,
            }),
        }
    }
}

impl From<ClientState> for Any {
    fn from(client_state: ClientState) -> Self {
        Any {
            type_url: NEAR_CLIENT_STATE_TYPE_URL.to_string(),
            value: Protobuf::<RawClientState>::encode_vec(&client_state),
        }
    }
}
