use crate::std::string::String;
use derive_more::{Display, From};
use std::convert::From;

/// Substrate Client error
#[derive(Debug, Display, From)]
pub enum JustificationError {
    /// Error decoding header justification.
    #[display(fmt = "error decoding justification for header")]
    JustificationDecode,
    /// Justification for header is correctly encoded, but invalid.
    #[display(fmt = "bad justification for header: {}", _0)]
    #[from(ignore)]
    BadJustification(String),
}

#[derive(Debug)]
pub enum Error {
    // InvalidStorageProof,
    StorageRootMismatch,
    StorageValueUnavailable,
    // InvalidValidatorSetProof,
    ValidatorSetMismatch,
    InvalidAncestryProof,
    NoSuchRelayExists,
    InvalidFinalityProof,
    // UnknownClientError,
    HeaderAncestryMismatch,
}

impl From<JustificationError> for Error {
    fn from(e: JustificationError) -> Self {
        match e {
            JustificationError::BadJustification(_) | JustificationError::JustificationDecode => {
                Error::InvalidFinalityProof
            }
        }
    }
}
