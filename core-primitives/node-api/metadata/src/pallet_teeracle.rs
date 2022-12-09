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
const TEERACLE: &str = "Teeracle";

pub trait TeeracleCallIndexes {
	fn add_to_whitelist_call_indexes(&self) -> Result<[u8; 2]>;
	fn remove_from_whitelist_call_indexes(&self) -> Result<[u8; 2]>;
	fn update_exchange_rate_call_indexes(&self) -> Result<[u8; 2]>;
	fn update_oracle_call_indexes(&self) -> Result<[u8; 2]>;
}

impl TeeracleCallIndexes for NodeMetadata {
	fn add_to_whitelist_call_indexes(&self) -> Result<[u8; 2]> {
		self.call_indexes(TEERACLE, "add_to_whitelist")
	}

	fn remove_from_whitelist_call_indexes(&self) -> Result<[u8; 2]> {
		self.call_indexes(TEERACLE, "remove_from_whitelist")
	}

	fn update_exchange_rate_call_indexes(&self) -> Result<[u8; 2]> {
		self.call_indexes(TEERACLE, "update_exchange_rate")
	}

	fn update_oracle_call_indexes(&self) -> Result<[u8; 2]> {
		self.call_indexes(TEERACLE, "update_oracle")
	}
}
