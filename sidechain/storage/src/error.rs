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

use thiserror::Error;

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Error, Debug)]
pub enum Error {
	#[error("Could not interact with file storage: {0:?}")]
	Operational(#[from] rocksdb::Error),
	#[error("Last Block of shard {0} not found")]
	LastBlockNotFound(String),
	#[error("Failed to find parent block")]
	FailedToFindParentBlock,
	#[error("Could not decode: {0:?}")]
	Decode(#[from] codec::Error),
	#[error("Given block is not a successor of the last known block")]
	HeaderAncestryMismatch,
}
