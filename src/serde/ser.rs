use crate::{ms, AttrId, Multisig};
use multiutil::{EncodedVarbytes, EncodingInfo, Varbytes};
use serde::ser::{self, SerializeStruct};

/// Serialize instance of [`crate::AttrId`]
impl ser::Serialize for AttrId {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: ser::Serializer,
    {
        if serializer.is_human_readable() {
            serializer.serialize_str(self.as_str())
        } else {
            Varbytes(self.clone().into()).serialize(serializer)
        }
    }
}

/// Serialize instance of [`crate::Multisig`]
impl ser::Serialize for Multisig {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: ser::Serializer,
    {
        if serializer.is_human_readable() {
            let attributes: Vec<(String, EncodedVarbytes)> = self
                .attributes
                .iter()
                .map(|(id, attr)| {
                    (
                        id.to_string(),
                        Varbytes::encoded_new(self.encoding(), attr.clone()),
                    )
                })
                .collect();
            let message = Varbytes::encoded_new(self.encoding(), self.message.clone());

            let mut ss = serializer.serialize_struct(ms::SIGIL.as_str(), 3)?;
            ss.serialize_field("codec", &self.codec)?;
            ss.serialize_field("message", &message)?;
            ss.serialize_field("attributes", &attributes)?;
            ss.end()
        } else {
            let attributes: Vec<(AttrId, Varbytes)> = self
                .attributes
                .iter()
                .map(|(id, attr)| (*id, Varbytes(attr.clone())))
                .collect();
            let message = Varbytes(self.message.clone());

            (ms::SIGIL, self.codec, message, attributes).serialize(serializer)
        }
    }
}
