/*
	Copyright 2019 Supercomputing Systems AG

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

use codec::{Decode, Encode};
use derive_more::{Display, From};
use frame_support::ensure;
use sp_runtime::traits::Header as HeaderT;
use sp_std::prelude::Vec;
use std::collections::HashMap;
use substratee_storage::StorageProofChecker;
use substratee_worker_primitives::WorkerResponse;

#[derive(Debug, Display, PartialEq, Eq, From)]
pub enum Error {
	NoProofSupplied,
	/// Supplied storage value does not match the value from the proof
	WrongValue,
	Proof(substratee_storage::proof::Error),
	Codec(codec::Error),
}

#[derive(Default, Clone, Encode, Decode)]
pub struct StorageEntry<V: Decode> {
	pub key: Vec<u8>,
	pub value: Option<V>,
}

pub trait OnchainStorage {
	fn verify_proof<Header: HeaderT>(&self, header: &Header) -> Result<(), Error>;
	fn try_into_storage_entry<V: Decode>(self) -> Result<StorageEntry<V>, Error>;
	fn into_opaque_storage(self) -> StorageEntry<Vec<u8>>;
	fn key(&self) -> &[u8];
	fn value(&self) -> &Option<Vec<u8>>;
}

impl OnchainStorage for WorkerResponse<Vec<u8>> {
	/// returns key value pair of verified storage
	fn verify_proof<Header: HeaderT>(&self, header: &Header) -> Result<(), Error> {
		match self {
			WorkerResponse::ChainStorage(key, value, proof) => {
				let proof = proof.as_ref().ok_or(Error::NoProofSupplied)?;
				let actual = StorageProofChecker::<<Header as HeaderT>::Hashing>::check_proof(
					*header.state_root(),
					&key,
					proof.to_vec(),
				)?;

				// Todo: Why do they do it like that, we could supply the proof only and get the value from the proof directly??
				ensure!(&actual == value, Error::WrongValue);
				Ok(())
			},
		}
	}

	fn try_into_storage_entry<V: Decode>(self) -> Result<StorageEntry<V>, Error> {
		match self {
			WorkerResponse::ChainStorage(key, value, _proof) => {
				let v: Option<V> = match value {
					Some(v) => Decode::decode(&mut v.as_slice())?,
					None => None,
				};
				Ok(StorageEntry { key, value: v })
			},
		}
	}

	/// To get owned values of the `key` an `value` for further use without having to `clone`.
	fn into_opaque_storage(self) -> StorageEntry<Vec<u8>> {
		match self {
			WorkerResponse::ChainStorage(key, value, _) => StorageEntry { key, value },
		}
	}

	fn key(&self) -> &[u8] {
		match self {
			WorkerResponse::ChainStorage(key, _, _) => key,
		}
	}

	fn value(&self) -> &Option<Vec<u8>> {
		match self {
			WorkerResponse::ChainStorage(_, value, _) => value,
		}
	}
}

pub fn verify_worker_responses<Header: HeaderT>(
	responses: Vec<WorkerResponse<Vec<u8>>>,
	header: &Header,
) -> Result<HashMap<Vec<u8>, Option<Vec<u8>>>, Error> {
	let mut update_map = HashMap::new();
	for response in responses.into_iter() {
		response.verify_proof(header)?;
		let s = response.into_opaque_storage();
		update_map.insert(s.key, s.value);
	}
	Ok(update_map)
}
