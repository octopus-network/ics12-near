use crate::v1::client_state::ClientState;
use crate::v1::consensus_state::ConsensusState as NearConsensusState;
use crate::v1::context::ValidationContext as NearValidationContext;
use alloc::format;
use alloc::string::ToString;
use borsh::to_vec;
use ibc_core::client::types::error::ClientError;
use ibc_core::host::types::identifiers::ClientId;
use ibc_core::host::types::path::ClientConsensusStatePath;
use ics12_near_types::v1::header::Header as NearHeader;
use ics12_near_types::v1::near_types::{hash::sha256, merkle::merklize};

impl ClientState {
    pub fn verify_header<ClientValidationContext>(
        &self,
        ctx: &ClientValidationContext,
        client_id: &ClientId,
        header: &NearHeader,
    ) -> Result<(), ClientError>
    where
        ClientValidationContext: NearValidationContext,
    {
        let client_consensus_state_path = ClientConsensusStatePath::new(
            client_id.clone(),
            self.0.latest_height.revision_number(),
            self.0.latest_height.revision_height(),
        );

        let latest_consensus_state: NearConsensusState = ctx
            .consensus_state(&client_consensus_state_path)?
            .try_into()
            .map_err(|err| ClientError::Other {
                description: err.to_string(),
            })?;
        let latest_header = &latest_consensus_state.inner().header;

        let approval_message = header.light_client_block.approval_message();

        // Check the height of the block is higher than the height of the current head.
        if header.height() <= latest_header.height() {
            return Err(ClientError::Other {
                description: "Header is too old.".to_string(),
            });
        }

        // Check the epoch of the block is equal to the epoch_id or next_epoch_id
        // known for the current head.
        if header.epoch_id() != latest_header.epoch_id()
            && header.epoch_id() != latest_header.next_epoch_id()
        {
            return Err(ClientError::Other {
                description: "Invalid epoch id in header.".to_string(),
            });
        }

        // If the epoch of the block is equal to the next_epoch_id of the head,
        // then next_bps is not None.
        if header.epoch_id() == latest_header.next_epoch_id()
            && header.light_client_block.next_bps.is_none()
        {
            return Err(ClientError::Other {
                description: "Missing next block producers in header.".to_string(),
            });
        }

        // 1. The approvals_after_next contains valid signatures on approval_message
        // from the block producers of the corresponding epoch.
        // 2. The signatures present in approvals_after_next correspond to
        // more than 2/3 of the total stake.
        let mut total_stake = 0;
        let mut approved_stake = 0;

        let bps = latest_consensus_state
            .inner()
            .get_block_producers_of(&header.epoch_id());
        if bps.is_none() {
            return Err(ClientError::Other {
                description: format!(
                    "Latest consensus state is invalid: missing epoch block producers for epoch {}.",
                    header.epoch_id()
                )
            });
        }

        let epoch_block_producers = bps.expect("Should not fail based on previous checking.");
        for (maybe_signature, block_producer) in header
            .light_client_block
            .approvals_after_next
            .iter()
            .zip(epoch_block_producers.iter())
        {
            let bp_stake_view = block_producer.clone().into_validator_stake();
            let bp_stake = bp_stake_view.stake;
            total_stake += bp_stake;

            if maybe_signature.is_none() {
                continue;
            }

            approved_stake += bp_stake;

            let validator_public_key = bp_stake_view.public_key.clone();
            if !maybe_signature
                .as_ref()
                .expect("Should not fail based on previous checking.")
                .verify(&approval_message, &validator_public_key)
            {
                return Err(ClientError::Other {
                    description: format!(
                        "Invalid signature in header: {:?} for validator {:?}.",
                        maybe_signature, validator_public_key
                    ),
                });
            }
        }

        if approved_stake * 3 <= total_stake * 2 {
            return Err(ClientError::Other {
                description: "Insufficient approved stake in header.".to_string(),
            });
        }

        // If next_bps is not none, sha256(borsh(next_bps)) corresponds to
        // the next_bp_hash in inner_lite.
        if header.light_client_block.next_bps.is_some() {
            let block_view_next_bps_serialized = to_vec(
                &header
                    .light_client_block
                    .next_bps
                    .as_deref()
                    .expect("Should not fail based on previous checking."),
            )
            .expect("Should not fail based on previous checking.");
            if sha256(&block_view_next_bps_serialized).as_slice()
                != header.light_client_block.inner_lite.next_bp_hash.as_ref()
            {
                return Err(ClientError::Other {
                    description: "Invalid hash of next block producers.".to_string(),
                });
            }
        }

        // Check the `prev_state_root` is the merkle root of `prev_state_root_of_chunks`.
        if header.light_client_block.inner_lite.prev_state_root
            != merklize(&header.prev_state_root_of_chunks).0
        {
            return Err(ClientError::Other {
                description: "Invalid merkle root of previous state root of chunks.".to_string(),
            });
        }

        Ok(())
    }

    ///
    pub fn check_for_misbehaviour_update_client<ClientValidationContext>(
        &self,
        ctx: &ClientValidationContext,
        client_id: &ClientId,
        header: NearHeader,
    ) -> Result<bool, ClientError>
    where
        ClientValidationContext: NearValidationContext,
    {
        let maybe_existing_consensus_state = {
            let path_at_header_height = ClientConsensusStatePath::new(
                client_id.clone(),
                header.height().revision_number(),
                header.height().revision_height(),
            );

            ctx.consensus_state(&path_at_header_height).ok()
        };

        match maybe_existing_consensus_state {
            Some(existing_consensus_state) => {
                let existing_consensus_state: NearConsensusState = existing_consensus_state
                    .try_into()
                    .map_err(|err| ClientError::Other {
                        description: err.to_string(),
                    })?;

                // There is evidence of misbehaviour if the stored consensus state
                // is different from the new one we received.
                Ok(existing_consensus_state
                    .inner()
                    .header
                    .light_client_block
                    .current_block_hash()
                    != header.light_client_block.current_block_hash())
            }
            None => {
                // If no header was previously installed, we ensure the monotonicity of timestamps.

                // 1. for all headers, the new header needs to have a larger timestamp than
                //    the “previous header”
                {
                    let maybe_prev_cs = ctx.prev_consensus_state(client_id, &header.height())?;

                    if let Some(prev_cs) = maybe_prev_cs {
                        // New header timestamp cannot occur *before* the
                        // previous consensus state's height

                        let prev_cs: NearConsensusState =
                            prev_cs.try_into().map_err(|err| ClientError::Other {
                                description: err.to_string(),
                            })?;

                        if header.timestamp() <= prev_cs.inner().header.timestamp() {
                            return Ok(true);
                        }
                    }
                }

                // 2. if a header comes in and is not the “last” header, then we also ensure
                //    that its timestamp is less than the “next header”
                if header.height() < self.0.latest_height {
                    let maybe_next_cs = ctx.next_consensus_state(client_id, &header.height())?;

                    if let Some(next_cs) = maybe_next_cs {
                        // New (untrusted) header timestamp cannot occur *after* next
                        // consensus state's height

                        let next_cs: NearConsensusState =
                            next_cs.try_into().map_err(|err| ClientError::Other {
                                description: err.to_string(),
                            })?;

                        if header.timestamp() >= next_cs.inner().header.timestamp() {
                            return Ok(true);
                        }
                    }
                }

                Ok(false)
            }
        }
    }
}
