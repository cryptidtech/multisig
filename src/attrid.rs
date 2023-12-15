use crate::{error::AttributesError, Error};
use multitrait::{EncodeInto, TryDecodeFrom};
use std::fmt;

/// enum of attribute identifiers. this is here to avoid collisions between
/// different codecs and encryption schemes. these are the common set of
/// attribute identifiers use in Multikeys
#[repr(u8)]
#[derive(Clone, Copy, Hash, Ord, PartialOrd, PartialEq, Eq)]
pub enum AttrId {
    /// the signature data
    SigData,
    /// the payload encoding
    PayloadEncoding,
}

impl AttrId {
    /// Get the code for the attribute id
    pub fn code(&self) -> u8 {
        self.clone().into()
    }

    /// Convert the attribute id to &str
    pub fn as_str(&self) -> &str {
        match self {
            Self::SigData => "sig-data",
            Self::PayloadEncoding => "payload-encoding",
        }
    }
}

impl Into<u8> for AttrId {
    fn into(self) -> u8 {
        self as u8
    }
}

impl TryFrom<u8> for AttrId {
    type Error = Error;

    fn try_from(c: u8) -> Result<Self, Self::Error> {
        match c {
            0 => Ok(Self::SigData),
            1 => Ok(Self::PayloadEncoding),
            _ => Err(AttributesError::InvalidAttributeValue(c).into()),
        }
    }
}

impl Into<Vec<u8>> for AttrId {
    fn into(self) -> Vec<u8> {
        let v: u8 = self.into();
        v.encode_into()
    }
}

impl<'a> TryFrom<&'a [u8]> for AttrId {
    type Error = Error;

    fn try_from(bytes: &'a [u8]) -> Result<AttrId, Error> {
        let (id, _) = Self::try_decode_from(bytes)?;
        Ok(id)
    }
}

impl<'a> TryDecodeFrom<'a> for AttrId {
    type Error = Error;

    fn try_decode_from(bytes: &'a [u8]) -> Result<(Self, &'a [u8]), Self::Error> {
        let (code, ptr) = u8::try_decode_from(bytes)?;
        Ok((Self::try_from(code)?, ptr))
    }
}

impl TryFrom<&str> for AttrId {
    type Error = Error;

    fn try_from(s: &str) -> Result<Self, Self::Error> {
        match s {
            "sig-data" => Ok(Self::SigData),
            "payload-encoding" => Ok(Self::PayloadEncoding),
            _ => Err(AttributesError::InvalidAttributeName(s.to_string()).into()),
        }
    }
}

impl fmt::Display for AttrId {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.as_str())
    }
}
