use alloc::vec::Vec;
use core::time::Duration;
use ibc::Height;

pub struct ClientState {
    pub trusting_period: Duration,
    /// Block height when the client was frozen due to a misbehaviour
    pub frozen_height: Height,
    /// Latest height the client was updated to
    pub latest_height: Height,
    /// Latest timestamp the client was updated to
    pub latest_timestamp: u64,
    ///
    pub upgrade_commitment_prefix: Vec<u8>,
    ///
    pub upgrade_key: Vec<u8>,
}
