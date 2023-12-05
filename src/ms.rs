use crate::Error;
use multibase::Base;
use multicodec::Codec;
use multitrait::TryDecodeFrom;
use multiutil::{BaseEncoded, CodecInfo, EncodingInfo, Varbytes, Varuint};
use ssh_key::{Algorithm, Signature};
use std::fmt;

/// the multisig sigil
pub const SIGIL: Codec = Codec::Multisig;

/// a base encoded varsig
pub type EncodedMultisig = BaseEncoded<Multisig>;

/// The multisig structure
#[derive(Clone, PartialEq)]
pub struct Multisig {
    /// signature codec
    pub(crate) codec: Codec,
    /// signature specific attributes
    pub attributes: Vec<u64>,
    /// the message part of a combined signature
    pub message: Vec<u8>,
    /// signature payloads
    pub payloads: Vec<Vec<u8>>,
}

impl CodecInfo for Multisig {
    /// Return that we are a Multisig object
    fn preferred_codec() -> Codec {
        SIGIL
    }

    /// Return the signing codec for the Multisig
    fn codec(&self) -> Codec {
        self.codec
    }
}

impl EncodingInfo for Multisig {
    fn preferred_encoding() -> Base {
        Base::Base16Lower
    }

    /// return the payload encoding
    fn encoding(&self) -> Base {
        Self::preferred_encoding()
    }
}

impl Into<Vec<u8>> for Multisig {
    fn into(self) -> Vec<u8> {
        let mut v = Vec::default();
        // add in the signature codec
        v.append(&mut self.codec().into());
        // add in the count of attributes
        v.append(&mut Varuint(self.attributes.len()).into());
        // add in the attributes
        self.attributes
            .iter()
            .for_each(|a| v.append(&mut Varuint(*a).into()));
        // add in the message
        v.append(&mut Varbytes(self.message).into());
        // add in the count of payloads
        v.append(&mut Varuint(self.payloads.len()).into());
        // add in the payloads
        self.payloads
            .iter()
            .for_each(|p| v.append(&mut Varbytes(p.clone()).into()));
        v
    }
}

impl<'a> TryFrom<&'a [u8]> for Multisig {
    type Error = Error;

    fn try_from(s: &'a [u8]) -> Result<Self, Self::Error> {
        let (ms, _) = Self::try_decode_from(s)?;
        Ok(ms)
    }
}

impl<'a> TryDecodeFrom<'a> for Multisig {
    type Error = Error;

    fn try_decode_from(bytes: &'a [u8]) -> Result<(Self, &'a [u8]), Self::Error> {
        // decode the signature codec
        let (codec, ptr) = Codec::try_decode_from(bytes)?;
        // decode the number of signature-specific attributes
        let (num_a, ptr) = Varuint::<usize>::try_decode_from(ptr)?;
        let num_a = num_a.to_inner();
        // decode the signature-specific attributes
        let (attributes, ptr) = match num_a {
            0 => (Vec::default(), ptr),
            _ => {
                let mut attributes = Vec::with_capacity(num_a);
                let mut p = ptr;
                for _ in 0..num_a {
                    let (a, ptr) = Varuint::<u64>::try_decode_from(p)?;
                    attributes.push(a.to_inner());
                    p = ptr;
                }
                (attributes, p)
            }
        };
        // decode the message
        let (message, ptr) = Varbytes::try_decode_from(ptr)?;
        let message = message.to_inner();
        // decode the number of payloads
        let (num_p, ptr) = Varuint::<usize>::try_decode_from(ptr)?;
        let num_p = num_p.to_inner();
        // decode the signature payloads
        let (payloads, ptr) = match num_p {
            0 => (Vec::default(), ptr),
            _ => {
                let mut payloads = Vec::with_capacity(num_p);
                let mut p = ptr;
                for _ in 0..num_p {
                    let (payload, ptr) = Varbytes::try_decode_from(p)?;
                    payloads.push(payload.to_inner());
                    p = ptr;
                }
                (payloads, p)
            }
        };
        Ok((
            Self {
                codec,
                attributes,
                message,
                payloads,
            },
            ptr,
        ))
    }
}

impl fmt::Debug for Multisig {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "{:?} - {:?} - {:?} - {}",
            SIGIL,
            self.codec(),
            self.encoding(),
            if self.message.len() > 0 {
                "combined"
            } else {
                "detached"
            },
        )
    }
}

/// Builder for Multisigs
#[derive(Clone, Debug, Default)]
pub struct Builder {
    codec: Codec,
    attributes: Vec<u64>,
    message: Vec<u8>,
    payloads: Vec<Vec<u8>>,
    base_encoding: Option<Base>,
}

impl Builder {
    /// create a new Multisig
    pub fn new(codec: Codec) -> Self {
        Self {
            codec,
            ..Default::default()
        }
    }

    /// create new v1 from ssh Signature
    pub fn new_from_ssh_signature(sig: &Signature) -> Result<Self, Error> {
        match sig.algorithm() {
            Algorithm::Ed25519 => Ok(Self {
                codec: Codec::Ed25519Pub,
                payloads: vec![sig.as_bytes().to_vec()],
                ..Default::default()
            }),
            _ => Err(Error::UnsupportedAlgorithm(sig.algorithm().to_string())),
        }
    }

    /// set the key codec
    pub fn with_codec(mut self, codec: Codec) -> Self {
        self.codec = codec;
        self
    }

    /// set the base encoding codec
    pub fn with_base_encoding(mut self, base: Base) -> Self {
        self.base_encoding = Some(base);
        self
    }

    /// add a signature payload
    pub fn with_signature_bytes(mut self, data: impl Into<Vec<u8>>) -> Self {
        self.payloads.push(data.into());
        self
    }

    /// add a message payload for a combined signature
    pub fn with_message_bytes(mut self, msg: impl Into<Vec<u8>>) -> Self {
        self.message = msg.into();
        self
    }

    /// set the signature-specific values for the header
    pub fn with_attributes(mut self, data: &Vec<u64>) -> Self {
        self.attributes = data.clone();
        self
    }

    /// build a base encoded varsig
    pub fn try_build_encoded(&self) -> Result<EncodedMultisig, Error> {
        Ok(BaseEncoded::new(
            self.base_encoding
                .unwrap_or_else(|| Multisig::preferred_encoding()),
            self.try_build()?,
        ))
    }

    /// try to build it
    pub fn try_build(&self) -> Result<Multisig, Error> {
        if self.payloads.is_empty() {
            return Err(Error::MissingSignature);
        }
        Ok(Multisig {
            codec: self.codec,
            attributes: self.attributes.clone(),
            message: self.message.clone(),
            payloads: self.payloads.clone(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encoded() {
        let ms = Builder::new(Codec::Ed25519Pub)
            .with_signature_bytes([0u8; 64].as_slice())
            .try_build_encoded()
            .unwrap();
        let s = ms.to_string();
        assert_eq!(ms, EncodedMultisig::try_from(s.as_str()).unwrap());
    }

    #[test]
    fn test_default() {
        let ms1 = Builder::new(Codec::default())
            .with_signature_bytes(Vec::default().as_slice())
            .try_build_encoded()
            .unwrap();
        let s = ms1.to_string();
        let ms2 = EncodedMultisig::try_from(s.as_str()).unwrap();
        assert_eq!(ms1, ms2);
    }

    #[test]
    fn test_eddsa() {
        let ms = Builder::new(Codec::Ed25519Pub)
            .with_signature_bytes([0u8; 64].as_slice())
            .try_build()
            .unwrap();
        let v: Vec<u8> = ms.clone().into();
        assert_eq!(ms, Multisig::try_from(v.as_slice()).unwrap());
    }

    #[test]
    fn test_eip191_unknown() {
        // this builds a Multisig::Unknown since we don't know about EIP-191
        // encoded data that is hashed with Keccak256 and signed with secp256k1
        let ms1 = Builder::new(Codec::Secp256K1Pub)
            .with_attributes(&[Codec::Eip191.code(), Codec::Keccak256.code()].to_vec())
            .with_signature_bytes([0u8; 64].as_slice())
            .try_build()
            .unwrap();
        let v: Vec<u8> = ms1.clone().into();
        let ms2 = Multisig::try_from(v.as_slice()).unwrap();
        assert_eq!(ms1, ms2);
    }
}
