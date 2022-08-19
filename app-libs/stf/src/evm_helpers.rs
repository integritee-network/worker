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
use crate::{
	helpers::{get_storage_double_map, get_storage_map},
	H256,
};
use itp_storage::StorageHasher;
use sp_core::H160;
use std::prelude::v1::*;

pub fn get_evm_account_codes(evm_account: &H160) -> Option<Vec<u8>> {
	get_storage_map("Evm", "AccountCodes", evm_account, &StorageHasher::Blake2_128Concat)
}

pub fn get_evm_account_storages(evm_account: &H160, index: &H256) -> Option<H256> {
	get_storage_double_map(
		"Evm",
		"AccountStorages",
		evm_account,
		&StorageHasher::Blake2_128Concat,
		index,
		&StorageHasher::Blake2_128Concat,
	)
}
