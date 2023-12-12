/// Errors created by this library
#[derive(Clone, Debug, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    /// Attributes error
    #[error(transparent)]
    Attributes(#[from] AttributesError),

    /// A multibase conversion error
    #[error(transparent)]
    Multibase(#[from] multibase::Error),
    /// A multicodec decoding error
    #[error(transparent)]
    Multicodec(#[from] multicodec::Error),
    /// A multitrait error
    #[error(transparent)]
    Multitrait(#[from] multitrait::Error),
    /// A multiutil error
    #[error(transparent)]
    Multiutil(#[from] multiutil::Error),

    /// Formatting error
    #[error(transparent)]
    Fmt(#[from] std::fmt::Error),
    /// Utf8 error
    #[error(transparent)]
    Utf8(#[from] std::string::FromUtf8Error),
    /// Missing sigil 0x39
    #[error("Missing Multisig sigil")]
    MissingSigil,
    /// Duplicate attribute error
    #[error("Duplicate Multikey attribute: {0}")]
    DuplicateAttribute(u8),
    /// Failed Varsig conversion
    #[error("Failed Varsig conversion: {0}")]
    FailedConversion(String),
    /// Unsupported signature algorithm
    #[error("Unsupported signature codec: {0}")]
    UnsupportedAlgorithm(String),
}

/// Attributes errors created by this library
#[derive(Clone, Debug, thiserror::Error)]
#[non_exhaustive]
pub enum AttributesError {
    /// Unsupported signature algorithm
    #[error("Unsupported signature codec: {0}")]
    UnsupportedCodec(multicodec::Codec),
    /// No key data attribute
    #[error("Signature data missing")]
    MissingSignature,
    /// Invalid attribute name
    #[error("Invalid attribute name {0}")]
    InvalidAttributeName(String),
    /// Invalid attribute value
    #[error("Invalid attribute value {0}")]
    InvalidAttributeValue(u8),
}
