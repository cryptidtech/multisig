use crate::{ms::SIGIL, Multisig};
use core::fmt;
use multicodec::Codec;
use multiutil::{EncodedVarbytes, EncodedVaruint, Varbytes, Varuint};
use serde::{
    de::{Error, MapAccess, Visitor},
    Deserialize, Deserializer,
};

/// Deserialize instance of [`crate::Multisig`]
impl<'de> Deserialize<'de> for Multisig {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        const FIELDS: &'static [&'static str] = &["codec", "attributes", "message", "signature"];

        #[derive(Deserialize)]
        #[serde(field_identifier, rename_all = "lowercase")]
        enum Field {
            Codec,
            Attributes,
            Message,
            Signature,
        }

        struct MultisigVisitor;

        impl<'de> Visitor<'de> for MultisigVisitor {
            type Value = Multisig;

            fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
                write!(f, "struct Multisig")
            }

            fn visit_map<V>(self, mut map: V) -> Result<Self::Value, V::Error>
            where
                V: MapAccess<'de>,
            {
                let mut codec = None;
                let mut attributes = None;
                let mut message = None;
                let mut payloads = None;
                while let Some(key) = map.next_key()? {
                    match key {
                        Field::Codec => {
                            if codec.is_some() {
                                return Err(Error::duplicate_field("codec"));
                            }
                            let s: &str = map.next_value()?;
                            codec = Some(
                                Codec::try_from(s)
                                    .map_err(|_| Error::custom("invalid Multisig codec"))?,
                            );
                        }
                        Field::Attributes => {
                            if attributes.is_some() {
                                return Err(Error::duplicate_field("attributes"));
                            }
                            let attr: Vec<EncodedVaruint<u64>> = map.next_value()?;
                            attributes = Some(
                                attr.iter()
                                    .map(|a| a.clone().to_inner().to_inner())
                                    .collect(),
                            );
                        }
                        Field::Message => {
                            if message.is_some() {
                                return Err(Error::duplicate_field("message"));
                            }
                            let msg: EncodedVarbytes = map.next_value()?;
                            message = Some(msg.to_inner().to_inner());
                        }
                        Field::Signature => {
                            if payloads.is_some() {
                                return Err(Error::duplicate_field("signature"));
                            }
                            let pls: Vec<EncodedVarbytes> = map.next_value()?;
                            payloads = Some(
                                pls.iter()
                                    .map(|p| p.clone().to_inner().to_inner())
                                    .collect(),
                            );
                        }
                    }
                }
                let codec = codec.ok_or_else(|| Error::missing_field("codec"))?;
                let attributes = attributes.ok_or_else(|| Error::missing_field("attributes"))?;
                let message = message.ok_or_else(|| Error::missing_field("message"))?;
                let payloads = payloads.ok_or_else(|| Error::missing_field("signature"))?;

                Ok(Self::Value {
                    codec,
                    attributes,
                    message,
                    payloads,
                })
            }
        }

        if deserializer.is_human_readable() {
            deserializer.deserialize_struct("Multisig", FIELDS, MultisigVisitor)
        } else {
            let (sigil, codec, attributes, message, payloads): (
                Codec,
                Codec,
                Vec<Varuint<u64>>,
                Varbytes,
                Vec<Varbytes>,
            ) = Deserialize::deserialize(deserializer)?;
            if sigil != SIGIL {
                return Err(Error::custom("deserialized sigil is not a Multisig sigil"));
            }
            let attributes = attributes.iter().map(|v| v.clone().to_inner()).collect();
            let message = message.to_inner();
            let payloads = payloads.iter().map(|p| p.clone().to_inner()).collect();

            Ok(Self {
                codec,
                attributes,
                message,
                payloads,
            })
        }
    }
}
