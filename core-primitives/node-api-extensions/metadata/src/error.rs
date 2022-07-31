#[derive(Debug, PartialEq, Eq)]
pub enum Error {
	/// Metadata has not been set
	MetadataNotSet,
	/// Api-client metadata error
	NodeMetadata(substrate_api_client::MetadataError),
}

pub type Result<T> = core::result::Result<T, Error>;
