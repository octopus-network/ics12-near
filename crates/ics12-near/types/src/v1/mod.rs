pub mod client_state;
pub mod consensus_state;
pub mod error;
pub mod header;
pub mod misbehaviour;
pub mod near_types;

use ibc_core::host::types::identifiers::ClientType;

pub const NEAR_CLIENT_TYPE: &str = "12-near";

/// Returns the near `ClientType`
pub fn client_type() -> ClientType {
    ClientType::new(NEAR_CLIENT_TYPE).expect("invalid client type")
}
