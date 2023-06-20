//! ICS 012: NEAR Client implements a client verification algorithm for NEAR protocol.

use crate::prelude::*;
use ibc::core::ics02_client::client_type::ClientType;

pub mod client_state;
pub mod consensus_state;
pub mod error;
pub mod header;
pub mod near_types;

pub(crate) const NEAR_CLIENT_TYPE: &str = "12-near";

pub type Height = u64;

/// Returns the tendermint `ClientType`
pub fn client_type() -> ClientType {
    ClientType::from(NEAR_CLIENT_TYPE.to_string())
}
