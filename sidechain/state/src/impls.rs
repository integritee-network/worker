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

//! Implement the sidechain state traits.

use crate::{Error, SidechainState, StateUpdate};
use codec::{Decode, Encode};
use frame_support::ensure;
use itp_sgx_externalities::{SgxExternalitiesTrait, StateHash};
use itp_storage::keys::storage_value_key;
use log::{error, info};
use sp_io::{storage, KillStorageResult};

impl<T: SgxExternalitiesTrait + Clone + StateHash> SidechainState for T
where
	<T as SgxExternalitiesTrait>::SgxExternalitiesType: Encode,
{
	type Externalities = Self;
	type StateUpdate = StateUpdate;

	fn apply_state_update(&mut self, state_payload: &Self::StateUpdate) -> Result<(), Error> {
		info!("Current state size: {}", self.state().encoded_size());
		ensure!(self.hash() == state_payload.state_hash_apriori(), Error::InvalidAprioriHash);

		self.execute_with(|| {
			state_payload.state_update.iter().for_each(|(k, v)| {
				match v {
					Some(value) => storage::set(k, value),
					None => storage::clear(k),
				};
			})
		});

		ensure!(self.hash() == state_payload.state_hash_aposteriori(), Error::InvalidStorageDiff);
		self.prune_state_diff();
		Ok(())
	}

	fn get_with_name<V: Decode>(&self, module_prefix: &str, storage_prefix: &str) -> Option<V> {
		let res = self
			.get(&storage_value_key(module_prefix, storage_prefix))
			.map(|v| Decode::decode(&mut v.as_slice()))
			.transpose();

		match res {
			Ok(res) => res,
			Err(e) => {
				error!(
					"Error decoding storage: {}, {}. Error: {:?}",
					module_prefix, storage_prefix, e
				);
				None
			},
		}
	}

	fn set_with_name<V: Encode>(&mut self, module_prefix: &str, storage_prefix: &str, value: V) {
		self.set(&storage_value_key(module_prefix, storage_prefix), &value.encode())
	}

	fn clear_with_name(&mut self, module_prefix: &str, storage_prefix: &str) {
		self.clear(&storage_value_key(module_prefix, storage_prefix))
	}

	fn clear_prefix_with_name(
		&mut self,
		module_prefix: &str,
		storage_prefix: &str,
	) -> KillStorageResult {
		self.clear_sidechain_prefix(&storage_value_key(module_prefix, storage_prefix))
	}

	fn set(&mut self, key: &[u8], value: &[u8]) {
		self.execute_with(|| sp_io::storage::set(key, value))
	}

	fn clear(&mut self, key: &[u8]) {
		self.execute_with(|| sp_io::storage::clear(key))
	}

	fn clear_sidechain_prefix(&mut self, prefix: &[u8]) -> KillStorageResult {
		self.execute_with(|| sp_io::storage::clear_prefix(prefix, None))
	}
}

#[cfg(test)]
pub mod tests {
	use super::*;
	use crate::StateUpdate;
	use frame_support::{assert_err, assert_ok};
	use itp_sgx_externalities::{SgxExternalities, SgxExternalitiesTrait};
	use sp_core::H256;

	pub fn default_db() -> SgxExternalities {
		SgxExternalities::default()
	}

	#[test]
	pub fn apply_state_update_works() {
		let mut state1 = default_db();
		let mut state2 = default_db();

		let apriori = state1.hash();
		state1.set(b"Hello", b"World");
		let aposteriori = state1.hash();

		let mut state_update = StateUpdate::new(apriori, aposteriori, state1.state_diff().clone());

		assert_ok!(state2.apply_state_update(&mut state_update));
		assert_eq!(state2.hash(), aposteriori);
		assert_eq!(state2.get(b"Hello").unwrap(), b"World");
		assert!(state2.state_diff().is_empty());
	}

	#[test]
	pub fn apply_state_update_returns_storage_hash_mismatch_err() {
		let mut state1 = default_db();
		let mut state2 = default_db();

		let apriori = H256::from([1; 32]);
		state1.set(b"Hello", b"World");
		let aposteriori = state1.hash();

		let mut state_update = StateUpdate::new(apriori, aposteriori, state1.state_diff().clone());

		assert_err!(state2.apply_state_update(&mut state_update), Error::InvalidAprioriHash);
		assert_eq!(state2, default_db());
	}

	#[test]
	pub fn apply_state_update_returns_invalid_storage_diff_err() {
		let mut state1 = default_db();
		let mut state2 = default_db();

		let apriori = state1.hash();
		state1.set(b"Hello", b"World");
		let aposteriori = H256::from([1; 32]);

		let mut state_update = StateUpdate::new(apriori, aposteriori, state1.state_diff().clone());

		assert_err!(state2.apply_state_update(&mut state_update), Error::InvalidStorageDiff);
		// After an error, the state is not guaranteed to be reverted and is potentially corrupted!
		assert_ne!(state2, default_db());
	}

	#[test]
	pub fn sp_io_storage_set_creates_storage_diff() {
		let mut state1 = default_db();

		state1.execute_with(|| {
			storage::set(b"hello", b"world");
		});

		assert_eq!(state1.state_diff().get(&b"hello"[..]).unwrap(), &Some(b"world".encode()));
	}

	#[test]
	pub fn create_state_diff_without_setting_externalities_works() {
		let mut state1 = default_db();

		state1.set(b"hello", b"world");

		assert_eq!(state1.state_diff().get(&b"hello"[..]).unwrap(), &Some(b"world".encode()));
	}
}
