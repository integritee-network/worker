//! Metadata error that implements `thisError` to simplify other error implementations.

#![cfg_attr(not(feature = "std"), no_std)]

#[cfg(all(feature = "std", feature = "sgx"))]
compile_error!("feature \"std\" and feature \"sgx\" cannot be enabled at the same time");

#[cfg(all(not(feature = "std"), feature = "sgx"))]
extern crate sgx_tstd as std;

#[cfg(all(not(feature = "std"), feature = "sgx"))]
use thiserror_sgx as thiserror;

use itp_node_api_metadata::error::Error as MetadataError;
use itp_node_api_metadata_provider::error::Error as MetadataProviderError;
use std::boxed::Box;

#[derive(Debug, thiserror::Error)]
pub enum Error {
	#[error("NodeMetadata error: {0:?}")]
	NodeMetadataError(MetadataError),
	#[error("NodeMetadataProvider error: {0:?}")]
	NodeMetadataProviderError(MetadataProviderError),
	#[error(transparent)]
	Other(#[from] Box<dyn std::error::Error + Sync + Send + 'static>),
}

impl From<MetadataError> for Error {
	fn from(error: MetadataError) -> Self {
		Self::NodeMetadataError(error)
	}
}

impl From<MetadataProviderError> for Error {
	fn from(error: MetadataProviderError) -> Self {
		Self::NodeMetadataProviderError(error)
	}
}
