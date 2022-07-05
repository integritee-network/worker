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

pub use sp_storage::StorageKey;

use crate::error::Result;
use codec::Encode;

pub trait StorageKeyProvider {
	fn storage_map_key<K: Encode>(
		&self,
		storage_prefix: &'static str,
		storage_key_name: &'static str,
		map_key: K,
	) -> Result<StorageKey>;

	fn storage_value_key(
		&self,
		storage_prefix: &'static str,
		storage_key_name: &'static str,
	) -> Result<StorageKey>;

	fn storage_double_map_key<K: Encode, Q: Encode>(
		&self,
		storage_prefix: &'static str,
		storage_key_name: &'static str,
		first: K,
		second: Q,
	) -> Result<StorageKey>;
}
