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

use ita_stf::{ShardIdentifier, State as StfState};
use itp_stf_state_handler::{
	error::{Error, Result},
	handle_state::HandleState,
	query_shard_state::QueryShardState,
};
use itp_types::H256;
use sgx_externalities::SgxExternalitiesTrait;
use std::{
	collections::HashMap,
	format,
	sync::{SgxRwLock as RwLock, SgxRwLockWriteGuard as RwLockWriteGuard},
	vec::Vec,
};

/// Mock implementation for the `HandleState` trait
///
/// Uses an in-memory state, in a `HashMap`. To be used in unit tests.
pub struct HandleStateMock {
	state_map: RwLock<HashMap<ShardIdentifier, StfState>>,
}

impl Default for HandleStateMock {
	fn default() -> Self {
		HandleStateMock { state_map: Default::default() }
	}
}

impl HandleState for HandleStateMock {
	type WriteLockPayload = HashMap<ShardIdentifier, StfState>;
	type StateT = StfState;

	fn load_initialized(&self, shard: &ShardIdentifier) -> Result<StfState> {
		let maybe_state = self.state_map.read().unwrap().get(shard).map(|s| s.clone());

		return match maybe_state {
			// initialize with default state, if it doesn't exist yet
			None => {
				self.state_map.write().unwrap().insert(shard.clone(), StfState::default());

				self.state_map.read().unwrap().get(shard).map(|s| s.clone()).ok_or_else(|| {
					Error::Other(
						format!("state does not exist after inserting it, shard {:?}", shard)
							.into(),
					)
				})
			},
			Some(s) => Ok(s),
		}
	}

	fn load_for_mutation(
		&self,
		shard: &ShardIdentifier,
	) -> Result<(RwLockWriteGuard<'_, Self::WriteLockPayload>, StfState)> {
		let initialized_state = self.load_initialized(shard)?;
		let write_lock = self.state_map.write().unwrap();
		Ok((write_lock, initialized_state))
	}

	fn write(
		&self,
		state: StfState,
		mut state_lock: RwLockWriteGuard<'_, Self::WriteLockPayload>,
		shard: &ShardIdentifier,
	) -> Result<H256> {
		state_lock.insert(shard.clone(), state);
		Ok(H256::default())
	}
}

impl QueryShardState for HandleStateMock {
	fn exists(&self, shard: &ShardIdentifier) -> bool {
		self.state_map.read().unwrap().get(shard).is_some()
	}

	fn list_shards(&self) -> Result<Vec<ShardIdentifier>> {
		Ok(self.state_map.read().unwrap().iter().map(|(k, _)| k.clone()).collect())
	}
}

// Since the mock itself has quite a bit of complexity, we also have tests for the mock
pub mod tests {

	use super::*;
	use codec::{Decode, Encode};
	use ita_stf::Stf;
	use itp_sgx_crypto::{Aes, StateCrypto};
	use itp_types::ShardIdentifier;
	use sgx_externalities::SgxExternalitiesType;
	use sp_core::blake2_256;
	use std::collections::HashMap;

	pub fn initialized_shards_list_is_empty() {
		let state_handler = HandleStateMock::default();
		assert!(state_handler.list_shards().unwrap().is_empty());
	}

	pub fn shard_exists_after_inserting() {
		let state_handler = HandleStateMock::default();
		let shard = ShardIdentifier::default();
		let _loaded_state_result = state_handler.load_initialized(&shard);
		assert!(state_handler.exists(&shard));
	}

	pub fn load_initialized_inserts_default_state() {
		let state_handler = HandleStateMock::default();
		let shard = ShardIdentifier::default();

		let loaded_state_result = state_handler.load_initialized(&shard);

		assert!(loaded_state_result.is_ok());
	}

	pub fn load_mutate_and_write_works() {
		let state_handler = HandleStateMock::default();
		let shard = ShardIdentifier::default();

		let (lock, mut state) = state_handler.load_for_mutation(&shard).unwrap();

		let (key, value) = ("my_key", "my_value");
		state.insert(key.encode(), value.encode());

		state_handler.write(state, lock, &shard).unwrap();

		let updated_state = state_handler.load_initialized(&shard).unwrap();

		let inserted_value =
			updated_state.get(key.encode().as_slice()).expect("value for key should exist");
		assert_eq!(*inserted_value, value.encode());
	}

	// this is the same test as for the `GlobalFileStateHandler` to ensure we don't have any effects
	// from having the state in-memory (as here) vs. in file (`GlobalFileStateHandler`)
	pub fn ensure_subsequent_state_loads_have_same_hash() {
		let state_handler = HandleStateMock::default();
		let shard = ShardIdentifier::default();

		let (lock, _) = state_handler.load_for_mutation(&shard).unwrap();
		let initial_state = Stf::init_state();
		let initial_state_hash = hash_of(&initial_state.state);
		state_handler.write(initial_state, lock, &shard).unwrap();

		let state_loaded = state_handler.load_initialized(&shard).unwrap();
		let loaded_state_hash = hash_of(&state_loaded.state);

		assert_eq!(initial_state_hash, loaded_state_hash);
	}

	pub fn ensure_encode_and_encrypt_does_not_affect_state_hash() {
		let mut state = Stf::init_state();
		let initial_state_hash = hash_of(&state.state);

		let encrypted_state = encrypt(&state.state);
		let decrypted_state: SgxExternalitiesType = decrypt(encrypted_state);

		let decrypted_state_hash = hash_of(&decrypted_state);

		assert_eq!(initial_state_hash, decrypted_state_hash);
	}

	pub fn ensure_encoding_and_decoding_hash_map_results_in_same_hash() {
		use sgx_serialize::{DeSerializable, DeSerializeHelper, Serializable, SerializeHelper};

		let mut initial_hash_map = HashMap::<Vec<u8>, Vec<u8>>::new();
		initial_hash_map.insert(Encode::encode("penguin"), Encode::encode("south_pole"));
		initial_hash_map.insert(Encode::encode("zebra"), Encode::encode("savanna"));

		let hash_map_encoded = SerializeHelper::new().encode(initial_hash_map.clone()).unwrap();
		let decoded_hash_map =
			DeSerializeHelper::<HashMap<Vec<u8>, Vec<u8>>>::new(hash_map_encoded.clone())
				.decode()
				.unwrap();
		let second_time_encoded_hash_map =
			SerializeHelper::new().encode(decoded_hash_map.clone()).unwrap();

		assert_eq!(decoded_hash_map, initial_hash_map);

		assert_eq!(
			blake2_256(hash_map_encoded.as_slice()),
			blake2_256(second_time_encoded_hash_map.as_slice())
		);
	}

	fn hash_of<T: Encode>(encodable: &T) -> H256 {
		encodable.using_encoded(blake2_256).into()
	}

	fn encrypt<T: Encode>(payload: &T) -> Vec<u8> {
		let mut encoded_and_encrypted = payload.encode();
		//encryption_key().encrypt(&mut encoded_and_encrypted).unwrap();
		encoded_and_encrypted
	}

	fn decrypt<T: Decode>(mut cyphertext: Vec<u8>) -> T {
		//encryption_key().decrypt(&mut cyphertext).unwrap();
		T::decode(&mut cyphertext.as_slice()).unwrap()
	}

	fn encryption_key() -> Aes {
		Aes::default()
	}
}
