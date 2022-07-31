#[derive(Debug, PartialEq, Eq)]
pub enum Error {
	/// Metadata has not been set
	MetadataNotSet,
}

pub type Result<T> = core::result::Result<T, Error>;
