//!
#![warn(missing_docs)]
#![deny(
    trivial_casts,
    trivial_numeric_casts,
    unused_import_braces,
    unused_qualifications
)]

/// Errors produced by this library
pub mod error;
pub use error::Error;

/// Attribute Ids
pub mod attrid;
pub use attrid::AttrId;

/// Multisig implementation
pub mod ms;
pub use ms::{Builder, EncodedMultisig, Multisig};

/// Views on the multisig
pub mod sig_views;
pub use sig_views::{
    AttrView, SigConvView, SigDataView, SigViews, ThresholdAttrView, ThresholdView,
};

/// Serde serialization
#[cfg(feature = "serde")]
pub mod serde;

/// ...and in the darkness bind them
pub mod prelude {
    pub use super::*;
    /// re-exports
    pub use multibase::Base;
    pub use multicodec::Codec;
    pub use multiutil::BaseEncoded;
}
