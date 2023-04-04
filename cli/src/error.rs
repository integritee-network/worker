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

use itp_node_api::api_client::ApiClientError;
use itp_types::parentchain::{BlockHash, BlockNumber};
use std::result::Result as StdResult;

pub type Result<T> = StdResult<T, Error>;

#[derive(Debug, thiserror::Error)]
pub enum Error {
	#[error("{0:?}")]
	ApiClient(ApiClientError),
	#[error("Could not retrieve Header from node")]
	MissingBlock,
	#[error("Confirmed Block Number ({0:?}) exceeds expected one ({0:?})")]
	ConfirmedBlockNumberTooHigh(BlockNumber, BlockNumber),
	#[error("Confirmed Block Hash ({0:?}) does not match expected one ({0:?})")]
	ConfirmedBlockHashDoesNotMatchExpected(BlockHash, BlockHash),
}

impl From<ApiClientError> for Error {
	fn from(error: ApiClientError) -> Self {
		Error::ApiClient(error)
	}
}
