use crate::{ms::SIGIL, Multisig};
use multiutil::{
    BaseEncoded, CodecInfo, EncodedVarbytes, EncodedVaruint, EncodingInfo, Varbytes, Varuint,
};
use serde::ser::{self, SerializeStruct};

/// Serialize instance of [`crate::Multisig`]
impl ser::Serialize for Multisig {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: ser::Serializer,
    {
        if serializer.is_human_readable() {
            let attributes: Vec<EncodedVaruint<u64>> = self
                .attributes
                .iter()
                .map(|v| BaseEncoded::new(self.encoding(), Varuint(*v)))
                .collect();
            let message = BaseEncoded::new(self.encoding(), Varbytes(self.message.clone()));
            let payloads: Vec<EncodedVarbytes> = self
                .payloads
                .iter()
                .map(|p| BaseEncoded::new(self.encoding(), Varbytes(p.clone())))
                .collect();

            let mut ss = serializer.serialize_struct("Multisig", 5)?;
            ss.serialize_field("codec", &self.codec())?;
            ss.serialize_field("attributes", &attributes)?;
            ss.serialize_field("message", &message)?;
            ss.serialize_field("signature", &payloads)?;
            ss.end()
        } else {
            let attributes: Vec<Varuint<u64>> =
                self.attributes.iter().map(|v| Varuint(*v)).collect();
            let message = Varbytes(self.message.clone());
            let payloads: Vec<Varbytes> =
                self.payloads.iter().map(|p| Varbytes(p.clone())).collect();

            (SIGIL, self.codec(), attributes, message, payloads).serialize(serializer)
        }
    }
}
