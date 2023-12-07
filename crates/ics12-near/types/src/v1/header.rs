use super::{
    error::Error,
    near_types::{hash::CryptoHash, LightClientBlock},
};
use alloc::format;
use alloc::string::ToString;
use alloc::vec::Vec;
use borsh::to_vec;
use borsh::{BorshDeserialize, BorshSerialize};
use bytes::Buf;
use ibc_core::client::types::error::ClientError;
use ibc_core::client::types::Height;
use ibc_core::primitives::Timestamp;
use ibc_proto::{google::protobuf::Any, Protobuf};
use ics12_proto::v1::{CryptoHash as RawCryptoHash, Header as RawHeader};
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
    pub fn epoch_id(&self) -> CryptoHash {
        self.light_client_block.inner_lite.epoch_id.0
    }
    ///
    pub fn next_epoch_id(&self) -> CryptoHash {
        self.light_client_block.inner_lite.next_epoch_id.0
    }
    ///
    pub fn raw_timestamp(&self) -> u64 {
        self.light_client_block.inner_lite.timestamp
    }
}

impl Header {
    ///
    pub fn height(&self) -> Height {
        Height::new(0, self.light_client_block.inner_lite.height)
            .expect("Invalid height in NEAR header")
    }

    ///
    pub fn timestamp(&self) -> Timestamp {
        Timestamp::from_nanoseconds(self.raw_timestamp()).expect("Invalid timestamp in NEAR header")
    }
}

impl Protobuf<RawHeader> for Header {}

impl TryFrom<RawHeader> for Header {
    type Error = Error;

    fn try_from(value: RawHeader) -> Result<Self, Self::Error> {
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

impl From<Header> for RawHeader {
    fn from(value: Header) -> Self {
        Self {
            light_client_block: to_vec(&value.light_client_block).unwrap(),
            prev_state_root_of_chunks: value
                .prev_state_root_of_chunks
                .into_iter()
                .map(|ch| RawCryptoHash {
                    raw_data: to_vec(&ch).unwrap(),
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
            value: Protobuf::<RawHeader>::encode_vec(header),
        }
    }
}

pub fn decode_header<B: Buf>(buf: B) -> Result<Header, Error> {
    RawHeader::decode(buf).map_err(Error::Decode)?.try_into()
}
