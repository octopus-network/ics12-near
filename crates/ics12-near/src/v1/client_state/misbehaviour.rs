use super::ClientState as NearClientState;
use crate::v1::context::ValidationContext as NearValidationContext;
use ibc_core::client::types::error::ClientError;
use ibc_core::host::types::identifiers::ClientId;
// use ics12_near_types::v1::consensus_state::ConsensusState as NearConsensusState;
use ics12_near_types::v1::misbehaviour::Misbehaviour as NearMisbehaviour;

impl NearClientState {
    // verify_misbehaviour determines whether or not two conflicting headers at
    // the same height would have convinced the light client.
    pub fn verify_misbehaviour<ClientValidationContext>(
        &self,
        ctx: &ClientValidationContext,
        client_id: &ClientId,
        misbehaviour: NearMisbehaviour,
    ) -> Result<(), ClientError>
    where
        ClientValidationContext: NearValidationContext,
    {
        self.verify_header(ctx, client_id, misbehaviour.header1())?;
        self.verify_header(ctx, client_id, misbehaviour.header2())
    }

    pub fn check_for_misbehaviour_misbehaviour(
        &self,
        misbehaviour: &NearMisbehaviour,
    ) -> Result<bool, ClientError> {
        let header_1 = misbehaviour.header1();
        let header_2 = misbehaviour.header2();

        if header_1.height() == header_2.height() {
            // when the height of the 2 headers are equal, we only have evidence
            // of misbehaviour in the case where the headers are different
            // (otherwise, the same header was added twice in the message,
            // and this is evidence of nothing)
            Ok(header_1.light_client_block.current_block_hash()
                != header_2.light_client_block.current_block_hash())
        } else {
            // header_1 is at greater height than header_2, therefore
            // header_1 time must be less than or equal to
            // header_2 time in order to be valid misbehaviour (violation of
            // monotonic time).
            Ok(header_1.timestamp() <= header_2.timestamp())
        }
    }
}
