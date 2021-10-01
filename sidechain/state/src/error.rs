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
