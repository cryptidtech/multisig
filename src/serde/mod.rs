//! Serde (de)serialization for [`crate::Varsig`].
mod de;
mod ser;

#[cfg(test)]
mod tests {
    use crate::{Builder, Multisig};
    use multibase::Base;
    use multicodec::Codec;
    use serde_test::{assert_tokens, Configure, Token};

    #[test]
    fn test_serde_compact() {
        let ms = Builder::new(Codec::Ed25519Pub)
            .with_signature_bytes([0u8; 64].as_slice())
            .try_build()
            .unwrap();

        assert_tokens(
            &ms.compact(),
            &[
                Token::Tuple { len: 4 },
                // sigil
                Token::BorrowedBytes(&[57]),
                // codec
                Token::BorrowedBytes(&[237, 1]),
                // message
                Token::BorrowedBytes(&[0]),
                // attributes
                Token::Seq { len: Some(1) },
                Token::Tuple { len: 2 },
                Token::BorrowedBytes(&[1, 0]),
                Token::BorrowedBytes(&[
                    64, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                ]),
                Token::TupleEnd,
                Token::SeqEnd,
                Token::TupleEnd,
            ],
        )
    }

    #[test]
    fn test_serde_encoded_string() {
        let ms = Builder::new(Codec::Ed25519Pub)
            .with_signature_bytes([0u8; 64].as_slice())
            .with_base_encoding(Base::Base58Btc)
            .try_build_encoded()
            .unwrap();

        assert_tokens(
            &ms.readable(),
            &[Token::BorrowedStr("zCEeLPdYRu4qr89wiYMvFG9ydgz7K5bUuCqDkTvbdXLJqF1TA8gLRqBgwxdj5gjdXkpp3Crwn8G86xaWKNQ8R9MNLb5qeJx91R")
            ],
        )
    }

    #[test]
    fn test_serde_readable() {
        let ms = Builder::new(Codec::Ed25519Pub)
            .with_signature_bytes([0u8; 64].as_slice())
            .try_build()
            .unwrap();

        assert_tokens(
            &ms.readable(),
            &[
                Token::Struct {
                    name: "multisig",
                    len: 3,
                },
                Token::BorrowedStr("codec"),
                Token::BorrowedStr("ed25519-pub"),
                Token::BorrowedStr("message"),
                Token::BorrowedStr("f00"),
                Token::BorrowedStr("attributes"),
                Token::Seq { len: Some(1) },
                Token::Tuple { len: 2 },
                Token::BorrowedStr("sig-data"),
                Token::BorrowedStr("f4000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"),
                Token::TupleEnd,
                Token::SeqEnd,
                Token::StructEnd,
            ],
        )
    }

    #[test]
    fn test_serde_json() {
        let ms1 = Builder::new(Codec::Ed25519Pub)
            .with_signature_bytes([0u8; 64].as_slice())
            .try_build()
            .unwrap();
        let s = serde_json::to_string(&ms1).unwrap();
        let ms2: Multisig = serde_json::from_str(&s).unwrap();
        assert_eq!(ms1, ms2);
    }

    #[test]
    fn test_serde_cbor() {
        let ms1 = Builder::new(Codec::Ed25519Pub)
            .with_signature_bytes([0u8; 64].as_slice())
            .try_build()
            .unwrap();
        let v = serde_cbor::to_vec(&ms1).unwrap();
        let ms2: Multisig = serde_cbor::from_slice(v.as_slice()).unwrap();
        assert_eq!(ms1, ms2);
    }

    /*
    #[test]
    fn test_eip191_unknown() {
        // this builds a Varsig::Unknown since we don't know about EIP-191
        // encoded data that is hashed with Keccak256 and signed with secp256k1
        let ms1 = Builder::new(Codec::Secp256K1Pub)
            .with_attributes(&[Codec::Eip191.code(), Codec::Keccak256.code()].to_vec())
            .with_signature_bytes([0u8; 64].as_slice())
            .try_build()
            .unwrap();
        let s = serde_json::to_string(&ms1).unwrap();
        let ms2: Multisig = serde_json::from_str(&s).unwrap();
        assert_eq!(ms1, ms2);
    }
    */
}
