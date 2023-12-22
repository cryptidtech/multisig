use crate::{
    error::{AttributesError, ConversionsError},
    AttrId, AttrView, Error, Multisig, SigConvView, SigDataView, SigViews,
};
use multicodec::Codec;

/// the name used to identify these signatures in non-Multikey formats
pub const ALGORITHM_NAME: &'static str = "secp256k1@multisig";

pub(crate) struct View<'a> {
    ms: &'a Multisig,
}

impl<'a> TryFrom<&'a Multisig> for View<'a> {
    type Error = Error;

    fn try_from(ms: &'a Multisig) -> Result<Self, Self::Error> {
        Ok(Self { ms })
    }
}

impl<'a> AttrView for View<'a> {
    /// for Secp256K1Pub Multisigs, the payload encoding is stored using the
    /// AttrId::PayloadEncoding attribute id.
    fn payload_encoding(&self) -> Result<Codec, Error> {
        let v = self
            .ms
            .attributes
            .get(&AttrId::PayloadEncoding)
            .ok_or(AttributesError::MissingPayloadEncoding)?;
        let encoding = Codec::try_from(v.as_slice())?;
        Ok(encoding)
    }
}

impl<'a> SigDataView for View<'a> {
    /// For Secp256K1Pub Multisig values, the sig data is stored using the
    /// AttrId::SigData attribute id.
    fn sig_bytes(&self) -> Result<Vec<u8>, Error> {
        let sig = self
            .ms
            .attributes
            .get(&AttrId::SigData)
            .ok_or(AttributesError::MissingSignature)?;
        Ok(sig.clone())
    }
}

impl<'a> SigConvView for View<'a> {
    /// convert to SSH signature format
    fn to_ssh_signature(&self) -> Result<ssh_key::Signature, Error> {
        // get the signature data
        let dv = self.ms.sig_data_view()?;
        let sig_bytes = dv.sig_bytes()?;
        Ok(ssh_key::Signature::new(
            ssh_key::Algorithm::Other(
                ssh_key::AlgorithmName::new(ALGORITHM_NAME)
                    .map_err(|e| ConversionsError::SshSigLabel(e))?,
            ),
            sig_bytes,
        )
        .map_err(|e| ConversionsError::SshSig(e))?)
    }
}
