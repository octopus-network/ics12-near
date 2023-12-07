use super::{error::Error, header::Header as NearHeader};
use alloc::string::ToString;
use bytes::Buf;
use ibc_core::client::types::error::ClientError;
use ibc_core::host::types::identifiers::ClientId;
use ibc_proto::{google::protobuf::Any, Protobuf};
use ics12_proto::v1::Misbehaviour as RawMisbehaviour;
use prost::Message;
use serde::{Deserialize, Serialize};

const NEAR_MISBEHAVIOUR_TYPE_URL: &str = "/ibc.lightclients.near.v1.Misbehaviour";

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq)]
pub struct Misbehaviour {
    client_id: ClientId,
    header1: NearHeader,
    header2: NearHeader,
}

impl Misbehaviour {
    pub fn new(client_id: ClientId, header1: NearHeader, header2: NearHeader) -> Self {
        Self {
            client_id,
            header1,
            header2,
        }
    }

    pub fn client_id(&self) -> &ClientId {
        &self.client_id
    }

    pub fn header1(&self) -> &NearHeader {
        &self.header1
    }

    pub fn header2(&self) -> &NearHeader {
        &self.header2
    }
}

impl Protobuf<RawMisbehaviour> for Misbehaviour {}

impl TryFrom<RawMisbehaviour> for Misbehaviour {
    type Error = Error;

    #[allow(deprecated)]
    fn try_from(raw: RawMisbehaviour) -> Result<Self, Self::Error> {
        let client_id = raw
            .client_id
            .parse()
            .map_err(|_| Error::InvalidRawClientId {
                client_id: raw.client_id.clone(),
            })?;
        let header1: NearHeader = raw
            .header_1
            .ok_or_else(|| Error::InvalidRawMisbehaviour {
                reason: "missing header1".into(),
            })?
            .try_into()?;
        let header2: NearHeader = raw
            .header_2
            .ok_or_else(|| Error::InvalidRawMisbehaviour {
                reason: "missing header2".into(),
            })?
            .try_into()?;

        Ok(Self::new(client_id, header1, header2))
    }
}

impl From<Misbehaviour> for RawMisbehaviour {
    fn from(value: Misbehaviour) -> Self {
        #[allow(deprecated)]
        RawMisbehaviour {
            client_id: value.client_id.to_string(),
            header_1: Some(value.header1.into()),
            header_2: Some(value.header2.into()),
        }
    }
}

impl Protobuf<Any> for Misbehaviour {}

impl TryFrom<Any> for Misbehaviour {
    type Error = ClientError;

    fn try_from(raw: Any) -> Result<Self, ClientError> {
        use core::ops::Deref;

        fn decode_misbehaviour<B: Buf>(buf: B) -> Result<Misbehaviour, Error> {
            RawMisbehaviour::decode(buf)
                .map_err(Error::Decode)?
                .try_into()
        }

        match raw.type_url.as_str() {
            NEAR_MISBEHAVIOUR_TYPE_URL => {
                decode_misbehaviour(raw.value.deref()).map_err(Into::into)
            }
            _ => Err(ClientError::UnknownMisbehaviourType {
                misbehaviour_type: raw.type_url,
            }),
        }
    }
}

impl From<Misbehaviour> for Any {
    fn from(misbehaviour: Misbehaviour) -> Self {
        Any {
            type_url: NEAR_MISBEHAVIOUR_TYPE_URL.to_string(),
            value: Protobuf::<RawMisbehaviour>::encode_vec(misbehaviour),
        }
    }
}

impl core::fmt::Display for Misbehaviour {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> Result<(), core::fmt::Error> {
        write!(
            f,
            "{} h1: {} h2: {}",
            self.client_id,
            self.header1.height(),
            self.header2.height(),
        )
    }
}
