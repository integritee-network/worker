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

use crate::{error::Result, NodeMetadata};
/// Pallet' name:
const SIDECHAIN: &str = "Sidechain";

pub trait SidechainCallIndexes {
	fn confirm_proposed_sidechain_block_indexes(&self) -> Result<[u8; 2]>;
}

impl SidechainCallIndexes for NodeMetadata {
	fn confirm_proposed_sidechain_block_indexes(&self) -> Result<[u8; 2]> {
		self.call_indexes(SIDECHAIN, "confirm_proposed_sidechain_block")
	}
}
