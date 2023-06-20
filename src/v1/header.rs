use super::{
    error::Error,
    near_types::{hash::CryptoHash, LightClientBlock},
    Height,
};
use crate::prelude::*;
use borsh::{BorshDeserialize, BorshSerialize};
use bytes::Buf;
use ibc::core::{ics02_client::error::ClientError, timestamp::Timestamp};
use ibc_proto::{
    google::protobuf::Any,
    ibc::lightclients::near::v1::{CryptoHash as ProtoCryptoHash, Header as ProtoHeader},
    protobuf::Protobuf,
};
use prost::Message;
use serde::{Deserialize, Serialize};

pub const NEAR_HEADER_TYPE_URL: &str = "/ibc.lightclients.near.v1.Header";

/// The header data struct of NEAR light client.
#[derive(Clone, Debug, BorshDeserialize, BorshSerialize, Serialize, Deserialize, PartialEq)]
pub struct Header {
    pub light_client_block: LightClientBlock,
    pub prev_state_root_of_chunks: Vec<CryptoHash>,
}

impl Header {
    ///
    pub fn height(&self) -> Height {
        self.light_client_block.inner_lite.height
    }
    ///
    pub fn epoch_id(&self) -> CryptoHash {
        self.light_client_block.inner_lite.epoch_id.0
    }
    ///
    pub fn next_epoch_id(&self) -> CryptoHash {
        self.light_client_block.inner_lite.next_epoch_id.0
    }
}

impl ibc::core::ics02_client::header::Header for Header {
    fn height(&self) -> ibc::Height {
        ibc::Height::new(0, self.light_client_block.inner_lite.height)
            .expect("Invalid height in NEAR header")
    }

    fn timestamp(&self) -> Timestamp {
        Timestamp::from_nanoseconds(self.light_client_block.inner_lite.timestamp)
            .expect("Invalid timestamp in NEAR header")
    }
}

impl Protobuf<ProtoHeader> for Header {}

impl TryFrom<ProtoHeader> for Header {
    type Error = Error;

    fn try_from(value: ProtoHeader) -> Result<Self, Self::Error> {
        Ok(Self {
            light_client_block: LightClientBlock::try_from_slice(&value.light_client_block)
                .map_err(|e| Error::InvalidHeader {
                    reason: "Failed to decode `light_client_block`".to_string(),
                    error: format!("{:?}", e),
                })?,
            prev_state_root_of_chunks: value
                .prev_state_root_of_chunks
                .into_iter()
                .map(|ch| {
                    CryptoHash::try_from_slice(&ch.raw_data).map_err(|e| Error::InvalidHeader {
                        reason: "Failed to decode `prev_state_root_of_chunks`".to_string(),
                        error: format!("{:?}", e),
                    })
                })
                .collect::<Result<Vec<_>, _>>()?,
        })
    }
}

impl From<Header> for ProtoHeader {
    fn from(value: Header) -> Self {
        Self {
            light_client_block: value.light_client_block.try_to_vec().unwrap(),
            prev_state_root_of_chunks: value
                .prev_state_root_of_chunks
                .into_iter()
                .map(|ch| ProtoCryptoHash {
                    raw_data: ch.try_to_vec().unwrap(),
                })
                .collect(),
        }
    }
}

impl Protobuf<Any> for Header {}

impl TryFrom<Any> for Header {
    type Error = ClientError;

    fn try_from(raw: Any) -> Result<Self, Self::Error> {
        use core::ops::Deref;

        match raw.type_url.as_str() {
            NEAR_HEADER_TYPE_URL => decode_header(raw.value.deref()).map_err(Into::into),
            _ => Err(ClientError::UnknownHeaderType {
                header_type: raw.type_url,
            }),
        }
    }
}

impl From<Header> for Any {
    fn from(header: Header) -> Self {
        Any {
            type_url: NEAR_HEADER_TYPE_URL.to_string(),
            value: Protobuf::<ProtoHeader>::encode_vec(&header),
        }
    }
}

pub fn decode_header<B: Buf>(buf: B) -> Result<Header, Error> {
    ProtoHeader::decode(buf).map_err(Error::Decode)?.try_into()
}
