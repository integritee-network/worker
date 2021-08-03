use derive_more::{Display, From};

#[derive(Debug, Display, PartialEq, Eq, From)]
pub enum Error {
	NoProofSupplied,
	/// Supplied storage value does not match the value from the proof
	WrongValue,
	/// InvalidStorageProof,
	StorageRootMismatch,
	StorageValueUnavailable,
	Codec(codec::Error),
}
