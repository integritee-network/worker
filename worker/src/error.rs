use codec::{Error as CodecError};
use substrate_api_client::ApiClientError;


#[derive(Debug, thiserror::Error)]
pub enum Error {
	#[error("{0}")]
	Codec(#[from] CodecError),
	#[error("{0}")]
	ApiClientError(#[from] ApiClientError),
}