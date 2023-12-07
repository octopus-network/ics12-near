use super::{error::Error as Ics12Error, header::Header as NearHeader};
use alloc::string::ToString;
use alloc::vec;
use alloc::vec::Vec;
use core::{cmp::max, time::Duration};
use ibc_core::client::types::error::ClientError;
use ibc_core::client::types::Height;
use ibc_core::primitives::ZERO_DURATION;
use ibc_proto::{google::protobuf::Any, Protobuf};
use ics12_proto::v1::ClientState as RawClientState;
use prost::Message;
use serde::{Deserialize, Serialize};

pub const NEAR_CLIENT_STATE_TYPE_URL: &str = "/ibc.lightclients.near.v1.ClientState";

#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
pub struct ClientState {
    pub trusting_period: Duration,
    /// Block height when the client was frozen due to a misbehaviour
    pub frozen_height: Option<Height>,
    /// Latest height the client was updated to
    pub latest_height: Height,
    /// Latest timestamp the client was updated to
    pub latest_timestamp: u64,
    /// Prefix used to deterministically derive the next upgrade key
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

    pub fn is_frozen(&self) -> bool {
        self.frozen_height.is_some()
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
            value: Protobuf::<RawClientState>::encode_vec(client_state),
        }
    }
}
