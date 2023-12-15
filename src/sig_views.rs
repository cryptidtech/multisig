use crate::Error;
use multicodec::Codec;
use std::{cell::RefCell, rc::Rc};

// algorithms implement different sets of view
pub(crate) mod ed25519;
pub(crate) mod secp256k1;

///
/// Attributes views let you inquire about the Multisig and retrieve data
/// associated with the particular view.
///

/// trait for returning the attributes of the Multisig
pub trait AttrView {
    /// get the codec that the signed message was encoded with
    fn payload_encoding(&self) -> Result<Codec, Error>;
}

/// trait for returning the data from a Multisig
pub trait SigDataView {
    /// get the signature bytes from the Multisig
    fn sig_bytes(&self) -> Result<Vec<u8>, Error>;
}

/// trait for getting the other views
pub trait SigViews {
    /// Provide a read-only view to access the signature attributes
    fn attr_view<'a>(&'a self) -> Result<Rc<RefCell<dyn AttrView + 'a>>, Error>;
    /// Provide a read-only view to access signature data
    fn sig_data_view<'a>(&'a self) -> Result<Rc<RefCell<dyn SigDataView + 'a>>, Error>;
}
