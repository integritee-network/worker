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

use crate::TrustedOperation;
use codec::{Decode, Encode};
use std::vec::Vec;

/// Trusted operation Or hash
///
/// Allows to refer to trusted calls either by its raw representation or its hash.
#[derive(Clone, Debug, Encode, Decode)]
pub enum TrustedOperationOrHash<Hash> {
	/// The hash of the call.
	Hash(Hash),
	/// Raw extrinsic bytes.
	OperationEncoded(Vec<u8>),
	/// Raw extrinsic
	Operation(TrustedOperation),
}
