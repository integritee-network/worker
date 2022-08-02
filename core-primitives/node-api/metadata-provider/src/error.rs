/*
	Copyright 2021 Integritee AG and Supercomputing Systems AG

	Licensed under the Apache License, Version 2.0 (the "License");
	you may not use this file except in compliance with the License.
	You may obtain a copy of the License at

		http://www.apache.org/licenses/LICENSE-2.0

	Unless required by applicable law or agreed to in writing, software
	distributed under the License is distributed on an "AS IS" BASIS,
	WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
	See the License for the specific language governing permissions and
	limitations under the License.

*/

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
