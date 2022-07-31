#[cfg(feature = "sgx")]
extern crate thiserror_sgx as thiserror;

#[derive(Debug, PartialEq, Eq, thiserror::Error)]
pub enum Error {
	/// Metadata has not been set
	#[error("Metadata has no been set")]
	MetadataNotSet,
	/// Node metadata error
	#[error("Metadata Error: {0:?}")]
	MetadataError(itp_node_api_metadata::error::Error),
}

pub type Result<T> = core::result::Result<T, Error>;

impl From<itp_node_api_metadata::error::Error> for Error {
	fn from(e: itp_node_api_metadata::error::Error) -> Self {
		Self::MetadataError(e)
	}
}
