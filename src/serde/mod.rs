// SPDX-License-Idnetifier: Apache-2.0
//! Serde (de)serialization for [`crate::Varsig`].
mod de;
mod ser;

#[cfg(test)]
mod tests {
    use crate::{Builder, EncodedMultisig, Multisig};
    use multibase::Base;
    use multicodec::Codec;
    use multitrait::Null;
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
                Token::BorrowedBytes(&[
                    0x39,
                    0xed, 0xa1, 0x03,
                    0x00,
                    0x01,
                    0x00, 0x40,
                    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
                    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00])
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
                Token::BorrowedBytes(&[
                    0x39,
                    0xe7, 0xa1, 0x03,
                    0x00,
                    0x01,
                    0x00, 0x40,
                    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
                ])
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
                Token::BorrowedBytes(&[
                    0x39,               // multisig sigil
                    0xea, 0xa1, 0x03,   // signature codec
                    0x00,               // message length
                    0x01,               // number of attributes
                    // SigData (48 in length)
                    0x00, 0x30,
                    0x83, 0x50, 0x4f, 0x80, 0x42, 0x35, 0x6a, 0x86,
                    0x0b, 0x6d, 0xb8, 0xc7, 0xdd, 0xcb, 0x7a, 0xcc,
                    0x56, 0x3b, 0x53, 0xc6, 0x2c, 0xe4, 0xf9, 0x79,
                    0xae, 0x77, 0xa9, 0xb6, 0x7d, 0x72, 0x75, 0xcc,
                    0x3e, 0x01, 0xf8, 0xdb, 0x01, 0xd5, 0xfd, 0xbb,
                    0x56, 0x3d, 0x07, 0xb0, 0xec, 0x2d, 0x3a, 0x79
                ])
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
                Token::BorrowedStr("bls12_381-g1-sig"),
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
        let ms1 = Builder::new(Codec::Bls12381G1Msig)
            .with_signature_bytes(&[0u8; 64])
            .try_build()
            .unwrap();
        let s = serde_json::to_string(&ms1).unwrap();
        let ms2: Multisig = serde_json::from_str(&s).unwrap();
        assert_eq!(ms1, ms2);
    }

    #[test]
    fn test_bls12381g1_serde_cbor() {
        let ms1 = Builder::new(Codec::Bls12381G1Msig)
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
            "h8gnkpoygyynoycfzos58ogws4pjh3a449i49jfhjcngftxqbgwh4yu8eakd66de6ykwtn7o7ptcojraoe7xgc5xub7iyryenycyogbybyononye",
        )
        .unwrap()
        .to_inner();

        assert_eq!(Codec::Bls12381G1ShareMsig, ms.codec);

        /*
        let v: Vec<u8> = ms.clone().into();
        print!("BLAH: ");
        for b in &v {
            print!("0x{:02x}, ", b);
        }
        println!("");
        */

        assert_tokens(
            &ms.compact(),
            &[
                Token::BorrowedBytes(&[
                    0x39, 0x84, 0xa6, 0xc0, 0x06, 0x00, 0x05, 0x00,
                    0x30, 0xb7, 0x85, 0xb6, 0x78, 0x1a, 0x96, 0xd3,
                    0x53, 0xcc, 0xe3, 0x5a, 0xfd, 0x75, 0xf4, 0x97,
                    0x89, 0x60, 0x8c, 0x58, 0xbd, 0xc1, 0x35, 0x39,
                    0xa0, 0x4c, 0xe8, 0xc2, 0x87, 0xef, 0x0d, 0x1e,
                    0x02, 0xa9, 0x11, 0x76, 0x1d, 0x6c, 0x59, 0x04,
                    0x93, 0x10, 0x47, 0x5e, 0x66, 0x6d, 0xf3, 0x0f,
                    0x6a, 0x02, 0x01, 0x02, 0x03, 0x01, 0x03, 0x04,
                    0x01, 0x04, 0x05, 0x01, 0x01,
                ])
            ],
        )
    }

    #[test]
    fn test_bls12381g1_share_serde_encoded_string() {
        let ms = EncodedMultisig::try_from(
            "h8gnkpoygyynoycfzos58ogws4pjh3a449i49jfhjcngftxqbgwh4yu8eakd66de6ykwtn7o7ptcojraoe7xgc5xub7iyryenycyogbybyononye",
        )
        .unwrap();

        assert_tokens(
            &ms.readable(),
            &[
                Token::BorrowedStr("h8gnkpoygyynoycfzos58ogws4pjh3a449i49jfhjcngftxqbgwh4yu8eakd66de6ykwtn7o7ptcojraoe7xgc5xub7iyryenycyogbybyononye")
            ],
        )
    }

    #[test]
    fn test_bls12381g1_share_serde_readable() {
        let ms = EncodedMultisig::try_from(
            "h8gnkpoygyynoycfzos58ogws4pjh3a449i49jfhjcngftxqbgwh4yu8eakd66de6ykwtn7o7ptcojraoe7xgc5xub7iyryenycyogbybyononye",
        )
        .unwrap()
        .to_inner();

        assert_tokens(
            &ms.readable(),
            &[
                Token::Struct { name: "multisig", len: 3, },
                Token::BorrowedStr("codec"),
                Token::BorrowedStr("bls12_381-g1-share-msig"),
                Token::BorrowedStr("message"),
                Token::BorrowedStr("f00"),
                Token::BorrowedStr("attributes"),
                Token::Seq { len: Some(5) },
                Token::Tuple { len: 2 },
                Token::BorrowedStr("sig-data"),
                Token::BorrowedStr("f30b785b6781a96d353cce35afd75f49789608c58bdc13539a04ce8c287ef0d1e02a911761d6c59049310475e666df30f6a"),
                Token::TupleEnd,
                Token::Tuple { len: 2 },
                Token::BorrowedStr("scheme"),
                Token::BorrowedStr("f0102"),
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
                Token::SeqEnd,
                Token::StructEnd,
            ],
        )
    }

    #[test]
    fn test_bls12381g1_share_serde_json() {
        let ms1 = EncodedMultisig::try_from(
            "h8gnkpoygyynoycfzos58ogws4pjh3a449i49jfhjcngftxqbgwh4yu8eakd66de6ykwtn7o7ptcojraoe7xgc5xub7iyryenycyogbybyononye",
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
            "h8gnkpoygyynoycfzos58ogws4pjh3a449i49jfhjcngftxqbgwh4yu8eakd66de6ykwtn7o7ptcojraoe7xgc5xub7iyryenycyogbybyononye",
        )
        .unwrap()
        .to_inner();

        let v = serde_cbor::to_vec(&ms1).unwrap();
        let ms2: Multisig = serde_cbor::from_slice(v.as_slice()).unwrap();
        assert_eq!(ms1, ms2);
    }

    #[test]
    fn test_null_multisig_serde_compact() {
        let ms = Multisig::null();
        assert_tokens(
            &ms.compact(),
            &[
                Token::BorrowedBytes(&[
                    0x39, // Multisig
                    0x00, // Codec::Identity
                    0x00, // message (0 length)
                    0x00  // number of attributes
                ])
            ],
        );
    }

    #[test]
    fn test_null_multisig_serde_readable() {
        let ms = Multisig::null();
        assert_tokens(
            &ms.readable(),
            &[
                Token::Struct { name: "multisig", len: 3, },
                Token::BorrowedStr("codec"),
                Token::BorrowedStr("identity"),
                Token::BorrowedStr("message"),
                Token::BorrowedStr("f00"),
                Token::BorrowedStr("attributes"),
                Token::Seq { len: Some(0) },
                Token::SeqEnd,
                Token::StructEnd,
            ],
        );
    }

    #[test]
    fn test_encoded_null_multisig_serde_readable() {
        let ms: EncodedMultisig = Multisig::null().into();
        assert_tokens(
            &ms.readable(),
            &[
                Token::BorrowedStr("f39000000"),
            ],
        );
    }
}
