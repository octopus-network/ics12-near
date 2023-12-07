mod misbehaviour;
mod update_client;

use crate::alloc::string::ToString;
use crate::v1::consensus_state::ConsensusState as NearConsensusState;
use crate::v1::context::{
    ExecutionContext as NearExecutionContext, ValidationContext as NearValidationContext,
};
use alloc::format;
use alloc::vec;
use alloc::vec::Vec;
use borsh::BorshDeserialize;
use ibc_core::client::context::client_state::{
    ClientStateCommon, ClientStateExecution, ClientStateValidation,
};
use ibc_core::client::context::consensus_state::ConsensusState;
use ibc_core::client::context::ClientExecutionContext;
use ibc_core::client::context::ClientValidationContext;
use ibc_core::client::types::error::ClientError;
use ibc_core::client::types::{Height, Status, UpdateKind};
use ibc_core::commitment_types::commitment::{
    CommitmentPrefix, CommitmentProofBytes, CommitmentRoot,
};
use ibc_core::commitment_types::error::CommitmentError;
use ibc_core::host::types::identifiers::{ClientId, ClientType};
use ibc_core::host::types::path::Path;
use ibc_core::host::types::path::{ClientConsensusStatePath, ClientStatePath};
use ibc_proto::google::protobuf::Any;
use ibc_proto::Protobuf;
use ics12_near_types::v1::error::Error;
use ics12_near_types::v1::near_types::hash::sha256;
use ics12_near_types::v1::near_types::hash::CryptoHash;
use ics12_near_types::v1::near_types::trie::verify_not_in_state;
use ics12_near_types::v1::near_types::trie::verify_state_proof;
use ics12_near_types::v1::near_types::trie::RawTrieNodeWithSize;
use ics12_near_types::v1::{
    client_state::ClientState as ClientStateType, client_type as near_client_type,
    consensus_state::ConsensusState as ConsensusStateType, header::Header as NearHeader,
    misbehaviour::Misbehaviour as NearMisbehaviour,
};
use ics12_proto::v1::ClientState as RawNearClientState;
use prost::DecodeError;

pub const NEAR_CLIENT_STATE_TYPE_URL: &str = "/ibc.lightclients.near.v1.ClientState";

/// ClientState defines a solo machine client that tracks the current consensus
/// state and if the client is frozen.
/// Newtype wrapper around the `ClientState` type imported from the
/// `ibc-client-tendermint-types` crate. This wrapper exists so that we can
/// bypass Rust's orphan rules and implement traits from
/// `ibc::core::client::context` on the `ClientState` type.
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[derive(Clone, Debug, PartialEq)]
pub struct ClientState(ClientStateType);

impl ClientState {
    pub fn inner(&self) -> &ClientStateType {
        &self.0
    }
}

impl From<ClientStateType> for ClientState {
    fn from(client_state: ClientStateType) -> Self {
        Self(client_state)
    }
}

impl Protobuf<RawNearClientState> for ClientState {}

impl TryFrom<RawNearClientState> for ClientState {
    type Error = Error;

    fn try_from(raw: RawNearClientState) -> Result<Self, Self::Error> {
        Ok(Self(ClientStateType::try_from(raw)?))
    }
}

impl From<ClientState> for RawNearClientState {
    fn from(client_state: ClientState) -> Self {
        client_state.0.into()
    }
}

impl Protobuf<Any> for ClientState {}

impl TryFrom<Any> for ClientState {
    type Error = ClientError;

    fn try_from(raw: Any) -> Result<Self, Self::Error> {
        Ok(Self(ClientStateType::try_from(raw)?))
    }
}

impl From<ClientState> for Any {
    fn from(client_state: ClientState) -> Self {
        client_state.0.into()
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
        near_client_type()
    }

    fn latest_height(&self) -> Height {
        self.0.latest_height
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

impl<V> ClientStateValidation<V> for ClientState
where
    V: NearValidationContext + ClientValidationContext,
    V::AnyConsensusState: TryInto<NearConsensusState>,
    ClientError: From<<V::AnyConsensusState as TryInto<NearConsensusState>>::Error>,
{
    fn verify_client_message(
        &self,
        ctx: &V,
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
        ctx: &V,
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

    fn status(&self, ctx: &V, client_id: &ClientId) -> Result<Status, ClientError> {
        if self.0.is_frozen() {
            return Ok(Status::Frozen);
        }

        let latest_consensus_state: NearConsensusState = {
            let any_latest_consensus_state =
                match ctx.consensus_state(&ClientConsensusStatePath::new(
                    client_id.clone(),
                    self.latest_height().revision_number(),
                    self.latest_height().revision_height(),
                )) {
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
            if elapsed_since_latest_consensus_state > self.0.trusting_period {
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
            ClientConsensusStatePath::new(
                client_id.clone(),
                self.latest_height().revision_number(),
                self.latest_height().revision_height(),
            ),
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
            let path_at_header_height = ClientConsensusStatePath::new(
                client_id.clone(),
                header_height.revision_number(),
                header_height.revision_height(),
            );

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
                    ConsensusStateType::new(
                        prev_cs.inner().get_block_producers_of(&header.epoch_id()),
                        header.clone(),
                    )
                    .into()
                }
                None => ConsensusStateType::new(None, header.clone()),
            };

            let new_client_state = self
                .clone()
                .0
                .with_header(&header)?
                .with_timestamp(new_consensus_state.header.timestamp().nanoseconds());

            ctx.store_update_time(
                client_id.clone(),
                new_client_state.latest_height,
                ctx.host_timestamp()?,
            )?;
            ctx.store_update_height(
                client_id.clone(),
                new_client_state.latest_height,
                ctx.host_height()?,
            )?;

            ctx.store_consensus_state(
                ClientConsensusStatePath::new(
                    client_id.clone(),
                    new_client_state.latest_height.revision_number(),
                    new_client_state.latest_height.revision_height(),
                ),
                NearConsensusState::from(new_consensus_state).into(),
            )?;

            ctx.store_client_state(
                ClientStatePath::new(client_id),
                ClientState::from(new_client_state).into(),
            )?;
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
        let frozen_client_state = self.clone().0.with_frozen_height(Height::min(0));

        let wrapped_frozen_client_state = ClientState::from(frozen_client_state);

        ctx.store_client_state(
            ClientStatePath::new(client_id),
            wrapped_frozen_client_state.into(),
        )?;
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
