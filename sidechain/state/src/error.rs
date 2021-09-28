#[cfg(all(not(feature = "std"), feature = "sgx"))]
use crate::sgx_reexports::*;

use std::string::String;

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum Error {
	#[error("Invalid apriori state hash supplied")]
	InvalidAprioriHash,
	#[error("Invalid storage diff")]
	InvalidStorageDiff,
	#[error("Codec error when accessing module: {1}, storage: {2}. Error: {0:?}")]
	DB(codec::Error, String, String),
}
