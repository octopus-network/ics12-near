use super::{super::misbehaviour::Misbehaviour as NearMisbehaviour, ClientState};
use crate::prelude::*;
use ibc::core::{
    ics02_client::{error::ClientError, header::Header}, ics24_host::identifier::ClientId, ValidationContext,
};

impl ClientState {
    // verify_misbehaviour determines whether or not two conflicting headers at
    // the same height would have convinced the light client.
    pub fn verify_misbehaviour(
        &self,
        ctx: &dyn ValidationContext,
        client_id: &ClientId,
        misbehaviour: &NearMisbehaviour,
    ) -> Result<(), ClientError> {
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
