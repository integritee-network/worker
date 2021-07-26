use codec::Error as CodecError;
use substrate_api_client::ApiClientError;

#[derive(Debug, thiserror::Error)]
pub enum Error {
	#[error("{0}")]
	Codec(#[from] CodecError),
	#[error("{0}")]
	ApiClientError(#[from] ApiClientError),
	#[error("{0}")]
	JsonRpSeeClient(#[from] jsonrpsee::types::Error),
	#[error("{0}")]
	Serialization(#[from] serde_json::Error),
	#[error("{0}")]
	FromUtf8Error(#[from] std::string::FromUtf8Error),
	#[error("Application setup error!")]
	ApplicationSetupError,
	#[error("Custom Error: {0}")]
	Custom(Box<dyn std::error::Error>),
}
