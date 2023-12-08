use crate::{error::AttributesError, sig_views::ed25519, AttrId, Error, SigDataView, SigViews};
use multibase::Base;
use multicodec::Codec;
use multitrait::TryDecodeFrom;
use multiutil::{BaseEncoded, CodecInfo, EncodingInfo, Varbytes, Varuint};
use std::{cell::RefCell, collections::BTreeMap, fmt, rc::Rc};

/// the multisig sigil
pub const SIGIL: Codec = Codec::Multisig;

/// a base encoded varsig
pub type EncodedMultisig = BaseEncoded<Multisig>;

/// The multisig attributes type
pub type Attributes = BTreeMap<AttrId, Vec<u8>>;

/// The multisig structure
#[derive(Clone, PartialEq)]
pub struct Multisig {
    /// signature codec
    pub(crate) codec: Codec,
    /// the message part of a combined signature
    pub message: Vec<u8>,
    /// signature specific attributes
    pub attributes: Attributes,
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
        // add in the sigil
        v.append(&mut SIGIL.into());
        // add in the signature codec
        v.append(&mut self.codec.into());
        // add in the message
        v.append(&mut Varbytes(self.message.clone()).into());
        // add in the number of attributes
        v.append(&mut Varuint(self.attributes.len()).into());
        // add in the attributes
        self.attributes.iter().for_each(|(id, attr)| {
            v.append(&mut (*id).into());
            v.append(&mut Varbytes(attr.clone()).into());
        });
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
        // decode the sigil
        let (sigil, ptr) = Codec::try_decode_from(bytes)?;
        if sigil != SIGIL {
            return Err(Error::MissingSigil);
        }
        // decode the signature codec
        let (codec, ptr) = Codec::try_decode_from(ptr)?;
        // decode the message
        let (message, ptr) = Varbytes::try_decode_from(ptr)?;
        let message = message.to_inner();
        // decode the number of signature-specific attributes
        let (num_attr, ptr) = Varuint::<usize>::try_decode_from(ptr)?;
        // decode the signature-specific attributes
        let (attributes, ptr) = match *num_attr {
            0 => (Attributes::default(), ptr),
            _ => {
                let mut attributes = Attributes::new();
                let mut p = ptr;
                for _ in 0..*num_attr {
                    let (id, ptr) = AttrId::try_decode_from(p)?;
                    let (attr, ptr) = Varbytes::try_decode_from(ptr)?;
                    if attributes.insert(id, (*attr).clone()).is_some() {
                        return Err(Error::DuplicateAttribute(id.code()));
                    }
                    p = ptr;
                }
                (attributes, p)
            }
        };
        Ok((
            Self {
                codec,
                message,
                attributes,
            },
            ptr,
        ))
    }
}

impl fmt::Debug for Multisig {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "{:?} - {:?} - {}",
            SIGIL,
            self.codec(),
            if self.message.len() > 0 {
                "Combined"
            } else {
                "Detached"
            },
        )
    }
}

impl SigViews for Multisig {
    /// Provide a read-only view to access signature data
    fn sig_data_view<'a>(&'a self) -> Result<Rc<RefCell<dyn SigDataView + 'a>>, Error> {
        match self.codec {
            Codec::Ed25519Pub => Ok(Rc::new(RefCell::new(ed25519::View::try_from(self)?))),
            _ => Err(AttributesError::UnsupportedCodec(self.codec).into()),
        }
    }
}

/// Builder for Multisigs
#[derive(Clone, Debug, Default)]
pub struct Builder {
    codec: Codec,
    message: Option<Vec<u8>>,
    sig_bytes: Option<Vec<u8>>,
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
    pub fn new_from_ssh_signature(sig: &ssh_key::Signature) -> Result<Self, Error> {
        match sig.algorithm() {
            ssh_key::Algorithm::Ed25519 => Ok(Self {
                codec: Codec::Ed25519Pub,
                sig_bytes: Some(sig.as_bytes().to_vec()),
                ..Default::default()
            }),
            _ => Err(Error::UnsupportedAlgorithm(sig.algorithm().to_string())),
        }
    }

    /// set the base encoding codec
    pub fn with_base_encoding(mut self, base: Base) -> Self {
        self.base_encoding = Some(base);
        self
    }

    /// add a message payload for a combined signature
    pub fn with_message_bytes(mut self, msg: &impl AsRef<[u8]>) -> Self {
        let m: Vec<u8> = msg.as_ref().into();
        self.message = Some(m);
        self
    }

    /// add a signature payload
    pub fn with_signature_bytes(mut self, data: impl AsRef<[u8]>) -> Self {
        let s: Vec<u8> = data.as_ref().into();
        self.sig_bytes = Some(s);
        self
    }

    /// build a base encoded varsig
    pub fn try_build_encoded(self) -> Result<EncodedMultisig, Error> {
        Ok(BaseEncoded::new(
            self.base_encoding
                .unwrap_or_else(|| Multisig::preferred_encoding()),
            self.try_build()?,
        ))
    }

    /// try to build it
    pub fn try_build(self) -> Result<Multisig, Error> {
        let codec = self.codec;
        let message = self.message.unwrap_or_default();
        let mut attributes = Attributes::new();
        let sig_bytes = self
            .sig_bytes
            .clone()
            .ok_or_else(|| AttributesError::MissingSignature)?;
        attributes.insert(AttrId::SigData, sig_bytes);
        Ok(Multisig {
            codec,
            message,
            attributes,
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

    /*
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
    */
}
