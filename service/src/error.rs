use codec::Error as CodecError;
use substrate_api_client::ApiClientError;

pub type ServiceResult<T> = Result<T, Error>;

#[derive(Debug, thiserror::Error)]
pub enum Error {
	#[error("{0}")]
	Codec(#[from] CodecError),
	#[error("{0}")]
	ApiClient(#[from] ApiClientError),
	#[error("Node API terminated subscription unexpectedly: {0}")]
	ApiSubscriptionDisconnected(#[from] std::sync::mpsc::RecvError),
	#[error("Enclave API error: {0}")]
	EnclaveApi(#[from] itp_enclave_api::error::Error),
	#[error("Trusted Rpc Client error: {0}")]
	TrustedRpcClient(#[from] itc_rpc_client::error::Error),
	#[error("{0}")]
	JsonRpSeeClient(#[from] jsonrpsee::types::Error),
	#[error("{0}")]
	Serialization(#[from] serde_json::Error),
	#[error("{0}")]
	FromUtf8(#[from] std::string::FromUtf8Error),
	#[error("Application setup error!")]
	ApplicationSetup,
	#[error("Retrieved empty value")]
	EmptyValue,
	#[error("Insufficient buffer size. Actual: {0}, required: {1}")]
	InsufficientBufferSize(usize, usize),
	#[error("Custom Error: {0}")]
	Custom(Box<dyn std::error::Error + Sync + Send + 'static>),
}
