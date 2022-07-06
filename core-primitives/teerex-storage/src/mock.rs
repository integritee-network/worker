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

use crate::{TeeRexStorageAccess, TeeRexStorageKeys};
use itp_storage::error::Result;
use sp_std::{vec, vec::Vec};

#[derive(Default, Clone, Debug)]
pub struct TeeRexStorageKeysMock;

impl TeeRexStorageKeys for TeeRexStorageKeysMock {
	fn enclave_count(&self) -> Result<Vec<u8>> {
		Ok(vec![1, 2, 3])
	}

	fn enclave(&self, index: u64) -> Result<Vec<u8>> {
		let mut hash_key = vec![2, 4, 6];
		hash_key.append(&mut index.to_be_bytes().to_vec());
		Ok(hash_key)
	}
}

#[derive(Default, Clone, Debug)]
pub struct TeerexStorageAccessMock {
	storage_keys: TeeRexStorageKeysMock,
}

impl TeeRexStorageAccess for TeerexStorageAccessMock {
	type TeerexStorageType = TeeRexStorageKeysMock;

	fn teerex_storage(&self) -> &Self::TeerexStorageType {
		&self.storage_keys
	}
}
