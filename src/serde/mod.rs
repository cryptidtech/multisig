//! Serde (de)serialization for [`crate::Varsig`].
mod de;
mod ser;

#[cfg(test)]
mod tests {
    use crate::{Builder, EncodedMultisig, Multisig};
    use multibase::Base;
    use multicodec::Codec;
    use serde_test::{assert_tokens, Configure, Token};

    #[test]
    fn test_ed25519_serde_compact() {
        let ms = Builder::new(Codec::Eddsa)
            .with_signature_bytes(&[0u8; 64])
            .try_build()
            .unwrap();

        assert_tokens(
            &ms.compact(),
            &[
                Token::Tuple { len: 4 },
                // sigil
                Token::BorrowedBytes(&[57]),
                // codec
                Token::BorrowedBytes(&[237, 161, 3]),
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
    fn test_ed25519_serde_encoded_string() {
        let ms = Builder::new(Codec::Eddsa)
            .with_signature_bytes(&[0u8; 64])
            .with_base_encoding(Base::Base58Btc)
            .try_build_encoded()
            .unwrap();

        assert_tokens(
            &ms.readable(),
            &[Token::BorrowedStr("zrbLpQxbC4NFd4eLTzwpanG2E3Xgk6D1z6mv5tfW9hqZQ9Lx2WSJCkKdTVHsek5riPYZfZ1mNFztn4gyeUG9svAH9Yykx3fuUdD")
            ],
        )
    }

    #[test]
    fn test_ed25519_serde_readable() {
        let ms = Builder::new(Codec::Eddsa)
            .with_signature_bytes(&[0u8; 64])
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
                Token::BorrowedStr("eddsa"),
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
    fn test_ed25519_serde_json() {
        let ms1 = Builder::new(Codec::Eddsa)
            .with_signature_bytes(&[0u8; 64])
            .try_build()
            .unwrap();
        let s = serde_json::to_string(&ms1).unwrap();
        let ms2: Multisig = serde_json::from_str(&s).unwrap();
        assert_eq!(ms1, ms2);
    }

    #[test]
    fn test_ed25519_serde_cbor() {
        let ms1 = Builder::new(Codec::Eddsa)
            .with_signature_bytes(&[0u8; 64])
            .try_build()
            .unwrap();
        let v = serde_cbor::to_vec(&ms1).unwrap();
        let ms2: Multisig = serde_cbor::from_slice(v.as_slice()).unwrap();
        assert_eq!(ms1, ms2);
    }

    #[test]
    fn test_secp256k1_serde_compact() {
        let ms = Builder::new(Codec::Es256K)
            .with_signature_bytes(&[0u8; 64])
            .try_build()
            .unwrap();

        assert_tokens(
            &ms.compact(),
            &[
                Token::Tuple { len: 4 },
                // sigil
                Token::BorrowedBytes(&[57]),
                // codec
                Token::BorrowedBytes(&[231, 161, 3]),
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
    fn test_secp256k1_serde_encoded_string() {
        let ms = Builder::new(Codec::Es256K)
            .with_signature_bytes(&[0u8; 64])
            .with_base_encoding(Base::Base58Btc)
            .try_build_encoded()
            .unwrap();

        assert_tokens(
            &ms.readable(),
            &[Token::BorrowedStr("zraBKYTRFNqbSHenWPTkduwKtHG3ANrnuwtDk4yPop3Fw8QDybGFRmqCAJ92d3bfkZ9Ajme2ZLmXdt4FaBZWrYf9AajzTauFb67")
            ],
        )
    }

    #[test]
    fn test_secp256k1_serde_readable() {
        let ms = Builder::new(Codec::Es256K)
            .with_signature_bytes(&[0u8; 64])
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
                Token::BorrowedStr("es256k"),
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
    fn test_secp256k1_serde_json() {
        let ms1 = Builder::new(Codec::Es256K)
            .with_signature_bytes(&[0u8; 64])
            .try_build()
            .unwrap();
        let s = serde_json::to_string(&ms1).unwrap();
        let ms2: Multisig = serde_json::from_str(&s).unwrap();
        assert_eq!(ms1, ms2);
    }

    #[test]
    fn test_secp256k1_serde_cbor() {
        let ms1 = Builder::new(Codec::Es256K)
            .with_signature_bytes(&[0u8; 64])
            .try_build()
            .unwrap();
        let v = serde_cbor::to_vec(&ms1).unwrap();
        let ms2: Multisig = serde_cbor::from_slice(v.as_slice()).unwrap();
        assert_eq!(ms1, ms2);
    }

    #[test]
    fn test_bls12381g1_serde_compact() {
        let ms = EncodedMultisig::try_from(
            "z2ZyJ5U2f25c7GbkLwKGPWLWdkLpsiqVMwXzFSbCnUHGJS3manQMh1jerwMHTzYq3UPj9GEid5MDEx",
        )
        .unwrap()
        .to_inner();

        assert_tokens(
            &ms.compact(),
            &[
                Token::Tuple { len: 4 },
                // sigil
                Token::BorrowedBytes(&[57]),
                // codec
                Token::BorrowedBytes(&[234, 161, 3]),
                // message
                Token::BorrowedBytes(&[0]),
                // attributes
                Token::Seq { len: Some(1) },
                Token::Tuple { len: 2 },
                Token::BorrowedBytes(&[1, 0]),
                Token::BorrowedBytes(&[
                    48, 131, 80, 79, 128, 66, 53, 106, 134, 11, 109, 184, 199, 221, 203, 122, 204,
                    86, 59, 83, 198, 44, 228, 249, 121, 174, 119, 169, 182, 125, 114, 117, 204, 62,
                    1, 248, 219, 1, 213, 253, 187, 86, 61, 7, 176, 236, 45, 58, 121,
                ]),
                Token::TupleEnd,
                Token::SeqEnd,
                Token::TupleEnd,
            ],
        )
    }

    #[test]
    fn test_bls12381g1_serde_encoded_string() {
        let ms = EncodedMultisig::try_from(
            "z2ZyJ5U2f25c7GbkLwKGPWLWdkLpsiqVMwXzFSbCnUHGJS3manQMh1jerwMHTzYq3UPj9GEid5MDEx",
        )
        .unwrap();

        assert_tokens(
            &ms.readable(),
            &[Token::BorrowedStr(
                "z2ZyJ5U2f25c7GbkLwKGPWLWdkLpsiqVMwXzFSbCnUHGJS3manQMh1jerwMHTzYq3UPj9GEid5MDEx",
            )],
        )
    }

    #[test]
    fn test_bls12381g1_serde_readable() {
        let ms = EncodedMultisig::try_from(
            "z2ZyJ5U2f25c7GbkLwKGPWLWdkLpsiqVMwXzFSbCnUHGJS3manQMh1jerwMHTzYq3UPj9GEid5MDEx",
        )
        .unwrap()
        .to_inner();

        assert_tokens(
            &ms.readable(),
            &[
                Token::Struct {
                    name: "multisig",
                    len: 3,
                },
                Token::BorrowedStr("codec"),
                Token::BorrowedStr("bls-12381-g1-sig"),
                Token::BorrowedStr("message"),
                Token::BorrowedStr("f00"),
                Token::BorrowedStr("attributes"),
                Token::Seq { len: Some(1) },
                Token::Tuple { len: 2 },
                Token::BorrowedStr("sig-data"),
                Token::BorrowedStr("f3083504f8042356a860b6db8c7ddcb7acc563b53c62ce4f979ae77a9b67d7275cc3e01f8db01d5fdbb563d07b0ec2d3a79"),
                Token::TupleEnd,
                Token::SeqEnd,
                Token::StructEnd,
            ],
        )
    }

    #[test]
    fn test_bls12381g1_serde_json() {
        let ms1 = Builder::new(Codec::Bls12381G1Sig)
            .with_signature_bytes(&[0u8; 64])
            .try_build()
            .unwrap();
        let s = serde_json::to_string(&ms1).unwrap();
        let ms2: Multisig = serde_json::from_str(&s).unwrap();
        assert_eq!(ms1, ms2);
    }

    #[test]
    fn test_bls12381g1_serde_cbor() {
        let ms1 = Builder::new(Codec::Bls12381G1Sig)
            .with_signature_bytes(&[0u8; 64])
            .try_build()
            .unwrap();
        let v = serde_cbor::to_vec(&ms1).unwrap();
        let ms2: Multisig = serde_cbor::from_slice(v.as_slice()).unwrap();
        assert_eq!(ms1, ms2);
    }

    #[test]
    fn test_bls12381g1_share_serde_compact() {
        let ms = EncodedMultisig::try_from(
            "z8awyKZo9vU5uFqUTjLALGKyovR2Y2mhqMkLAaoDPwvJrrwKm8gifezRxASzu1SBEUCEZW3zixZykGevVSkQZSZrSwtrkh",
        )
        .unwrap()
        .to_inner();

        assert_eq!(Codec::Bls12381G1SigShare, ms.codec);

        assert_tokens(
            &ms.compact(),
            &[
                Token::Tuple { len: 4 },
                // sigil
                Token::BorrowedBytes(&[57]),
                // codec
                Token::BorrowedBytes(&[250, 161, 3]),
                // message
                Token::BorrowedBytes(&[0]),
                // attributes
                Token::Seq { len: Some(5) },
                // SigData
                Token::Tuple { len: 2 },
                Token::BorrowedBytes(&[1, 0]),
                Token::BorrowedBytes(&[
                    48, 132, 37, 89, 85, 174, 55, 19, 253, 195, 108, 166, 17, 225, 31, 189, 207,
                    240, 10, 195, 172, 73, 100, 164, 43, 130, 83, 32, 104, 100, 100, 8, 221, 183,
                    217, 213, 100, 101, 150, 75, 55, 222, 27, 251, 158, 10, 169, 216, 132,
                ]),
                Token::TupleEnd,
                // threshold
                Token::Tuple { len: 2 },
                Token::BorrowedBytes(&[1, 2]),
                Token::BorrowedBytes(&[1, 3]),
                Token::TupleEnd,
                // limit
                Token::Tuple { len: 2 },
                Token::BorrowedBytes(&[1, 3]),
                Token::BorrowedBytes(&[1, 4]),
                Token::TupleEnd,
                // share identifier
                Token::Tuple { len: 2 },
                Token::BorrowedBytes(&[1, 4]),
                Token::BorrowedBytes(&[1, 1]),
                Token::TupleEnd,
                // threshold data: share type id
                Token::Tuple { len: 2 },
                Token::BorrowedBytes(&[1, 5]),
                Token::BorrowedBytes(&[1, 2]),
                Token::TupleEnd,
                Token::SeqEnd,
                Token::TupleEnd,
            ],
        )
    }

    #[test]
    fn test_bls12381g1_share_serde_encoded_string() {
        let ms = EncodedMultisig::try_from(
            "z8awyKZo9vU5uFqUTjLALGKyovR2Y2mhqMkLAaoDPwvJrrwKm8gifezRxASzu1SBEUCEZW3zixZykGevVSkQZSZrSwtrkh",
        )
        .unwrap();

        assert_tokens(
            &ms.readable(),
            &[Token::BorrowedStr("z8awyKZo9vU5uFqUTjLALGKyovR2Y2mhqMkLAaoDPwvJrrwKm8gifezRxASzu1SBEUCEZW3zixZykGevVSkQZSZrSwtrkh")
            ],
        )
    }

    #[test]
    fn test_bls12381g1_share_serde_readable() {
        let ms = EncodedMultisig::try_from(
            "z8awyKZo9vU5uFqUTjLALGKyovR2Y2mhqMkLAaoDPwvJrrwKm8gifezRxASzu1SBEUCEZW3zixZykGevVSkQZSZrSwtrkh",
        )
        .unwrap()
        .to_inner();

        assert_tokens(
            &ms.readable(),
            &[
                Token::Struct {
                    name: "multisig",
                    len: 3,
                },
                Token::BorrowedStr("codec"),
                Token::BorrowedStr("bls-12381-g1-sig-share"),
                Token::BorrowedStr("message"),
                Token::BorrowedStr("f00"),
                Token::BorrowedStr("attributes"),
                Token::Seq { len: Some(5) },
                Token::Tuple { len: 2 },
                Token::BorrowedStr("sig-data"),
                Token::BorrowedStr("f3084255955ae3713fdc36ca611e11fbdcff00ac3ac4964a42b82532068646408ddb7d9d56465964b37de1bfb9e0aa9d884"),
                Token::TupleEnd,
                Token::Tuple { len: 2 },
                Token::BorrowedStr("threshold"),
                Token::BorrowedStr("f0103"),
                Token::TupleEnd,
                Token::Tuple { len: 2 },
                Token::BorrowedStr("limit"),
                Token::BorrowedStr("f0104"),
                Token::TupleEnd,
                Token::Tuple { len: 2 },
                Token::BorrowedStr("share-identifier"),
                Token::BorrowedStr("f0101"),
                Token::TupleEnd,
                Token::Tuple { len: 2 },
                Token::BorrowedStr("threshold-data"),
                Token::BorrowedStr("f0102"),
                Token::TupleEnd,
                Token::SeqEnd,
                Token::StructEnd,
            ],
        )
    }

    #[test]
    fn test_bls12381g1_share_serde_json() {
        let ms1 = EncodedMultisig::try_from(
            "z8awyKZo9vU5uFqUTjLALGKyovR2Y2mhqMkLAaoDPwvJrrwKm8gifezRxASzu1SBEUCEZW3zixZykGevVSkQZSZrSwtrkh",
        )
        .unwrap()
        .to_inner();

        let s = serde_json::to_string(&ms1).unwrap();
        let ms2: Multisig = serde_json::from_str(&s).unwrap();
        assert_eq!(ms1, ms2);
    }

    #[test]
    fn test_bls12381g1_share_serde_cbor() {
        let ms1 = EncodedMultisig::try_from(
            "z8awyKZo9vU5uFqUTjLALGKyovR2Y2mhqMkLAaoDPwvJrrwKm8gifezRxASzu1SBEUCEZW3zixZykGevVSkQZSZrSwtrkh",
        )
        .unwrap()
        .to_inner();

        let v = serde_cbor::to_vec(&ms1).unwrap();
        let ms2: Multisig = serde_cbor::from_slice(v.as_slice()).unwrap();
        assert_eq!(ms1, ms2);
    }
}
