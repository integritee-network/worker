use crate::std::string::String;
use derive_more::{Display, From};

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
	/// Invalid authorities set received from the runtime.
	InvalidAuthoritiesSet,
}

#[derive(Debug, From)]
pub enum Error {
	// InvalidStorageProof,
	Storage(substratee_storage::Error),
	// InvalidValidatorSetProof,
	ValidatorSetMismatch,
	InvalidAncestryProof,
	NoSuchRelayExists,
	InvalidFinalityProof(JustificationError),
	// UnknownClientError,
	HeaderAncestryMismatch,
}
