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
	AccountId, Index,
};
use itp_storage::StorageHasher;
use sha3::{Digest, Keccak256};
use sp_core::{H160, H256};
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

// FIXME: Once events are available, these addresses should be read from events.
pub fn evm_create_address(caller: H160, nonce: Index) -> H160 {
	let mut stream = rlp::RlpStream::new_list(2);
	stream.append(&caller);
	stream.append(&nonce);
	H256::from_slice(Keccak256::digest(&stream.out()).as_slice()).into()
}

// FIXME: Once events are available, these addresses should be read from events.
pub fn evm_create2_address(caller: H160, salt: H256, code_hash: H256) -> H160 {
	let mut hasher = Keccak256::new();
	hasher.update([0xff]);
	hasher.update(&caller[..]);
	hasher.update(&salt[..]);
	hasher.update(&code_hash[..]);
	H256::from_slice(hasher.finalize().as_slice()).into()
}

pub fn create_code_hash(code: &[u8]) -> H256 {
	H256::from_slice(Keccak256::digest(code).as_slice())
}

pub fn get_evm_account(account: &AccountId) -> H160 {
	let mut evm_acc_slice: [u8; 20] = [0; 20];
	evm_acc_slice.copy_from_slice((<[u8; 32]>::from(account.clone())).get(0..20).unwrap());
	evm_acc_slice.into()
}
