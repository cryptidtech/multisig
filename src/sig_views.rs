use crate::Error;
use std::{cell::RefCell, rc::Rc};

// algorithms implement different sets of view
pub(crate) mod ed25519;
pub(crate) mod secp256k1;

///
/// Attributes views let you inquire about the Multisig and retrieve data
/// associated with the particular view.
///

/// trait for returning the sig data from a Multikey
pub trait SigDataView {
    /// get the signature bytes from the Multisig
    fn sig_bytes(&self) -> Result<Vec<u8>, Error>;
}

/// trait for getting the other views
pub trait SigViews {
    /// Provide a read-only view to access signature data
    fn sig_data_view<'a>(&'a self) -> Result<Rc<RefCell<dyn SigDataView + 'a>>, Error>;
}
