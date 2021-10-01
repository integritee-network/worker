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

//! Implement the sidechain state traits. This is only sgx-compatible due to [`SgxExternalities`]
//! missing some features in `std`.

use crate::{sgx_reexports::*, Error, SidechainDB, SidechainState, StateHash, StateUpdate};
use codec::{Decode, Encode};
use itp_storage::keys::storage_value_key;
use log::error;
use sgx_externalities::SgxExternalitiesTrait;
use sp_core::{hashing::blake2_256, H256};
use sp_std::prelude::Vec;

impl<SB, T> SidechainState for SidechainDB<SB, T>
where
	T: SgxExternalitiesTrait + StateHash + Clone,
	SB: Clone,
{
	type Externalities = T;
	type StateUpdate = StateUpdate;
	type Hash = H256;

	fn state_hash(&self) -> Self::Hash {
		self.ext.hash()
	}

	fn apply_state_update(&mut self, state_payload: &Self::StateUpdate) -> Result<(), Error> {
		// Todo: how do we ensure that the apriori state hash matches: See #421
		// ensure!(self.state_hash() == state_payload.state_hash_apriori(), Error::InvalidAprioriHash);
		let mut state2 = self.ext.clone();

		state2.execute_with(|| {
			state_payload.state_update.iter().for_each(|(k, v)| {
				match v {
					Some(value) => sp_io::storage::set(k, value),
					None => sp_io::storage::clear(k),
				};
			})
		});

		// Todo: Consequence of #421
		// ensure!(state2.hash() == state_payload.state_hash_aposteriori(), Error::InvalidStorageDiff);
		self.ext = state2;
		self.ext.prune_state_diff();
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

	fn get(&self, key: &[u8]) -> Option<Vec<u8>> {
		self.ext.get(key).cloned()
	}

	fn set(&mut self, key: &[u8], value: &[u8]) {
		// self.ext.insert(key.to_vec(), value.to_vec());
		self.ext.execute_with(|| sp_io::storage::set(key, value))
	}
}

impl<E: SgxExternalitiesTrait + Encode> StateHash for E {
	fn hash(&self) -> H256 {
		self.state().using_encoded(blake2_256).into()
	}
}

// Most of the tests here can't be run in `std` just because `SgxExternalities` does not implement
// `Encode` in std. See: https://github.com/integritee-network/sgx-runtime/issues/26
#[cfg(feature = "test")]
pub mod tests {
	use super::*;
	use crate::{SidechainDB, StateUpdate};
	use frame_support::{assert_err, assert_ok};
	use sgx_externalities::{SgxExternalities, SgxExternalitiesTrait};
	use sp_core::H256;

	pub fn default_db() -> SidechainDB<(), SgxExternalities> {
		SidechainDB::<(), SgxExternalities>::default()
	}

	pub fn apply_state_update_works() {
		let mut state1 = default_db();
		let mut state2 = default_db();

		let apriori = state1.state_hash();
		state1.set(b"Hello", b"World");
		let aposteriori = state1.state_hash();

		let mut state_update =
			StateUpdate::new(apriori, aposteriori, state1.ext.state_diff.clone());

		assert_ok!(state2.apply_state_update(&mut state_update));
		assert_eq!(state2.state_hash(), aposteriori);
		assert_eq!(state2.get(b"Hello").unwrap(), b"World");
		assert!(state2.ext.state_diff.is_empty());
	}

	pub fn apply_state_update_returns_storage_hash_mismatch_err() {
		let mut state1 = default_db();
		let mut state2 = default_db();

		let apriori = H256::from([1; 32]);
		state1.set(b"Hello", b"World");
		let aposteriori = state1.state_hash();

		let mut state_update =
			StateUpdate::new(apriori, aposteriori, state1.ext.state_diff.clone());

		assert_err!(state2.apply_state_update(&mut state_update), Error::InvalidAprioriHash);
		assert_eq!(state2, default_db());
	}

	pub fn apply_state_update_returns_invalid_storage_diff_err() {
		let mut state1 = default_db();
		let mut state2 = default_db();

		let apriori = state1.state_hash();
		state1.set(b"Hello", b"World");
		let aposteriori = H256::from([1; 32]);

		let mut state_update =
			StateUpdate::new(apriori, aposteriori, state1.ext.state_diff.clone());

		assert_err!(state2.apply_state_update(&mut state_update), Error::InvalidStorageDiff);
		assert_eq!(state2, default_db());
	}

	pub fn sp_io_storage_set_creates_storage_diff() {
		let mut state1 = default_db();

		state1.ext.execute_with(|| {
			sp_io_sgx::storage::set(b"hello", b"world");
		});

		assert_eq!(state1.ext.state_diff.get(&b"hello"[..]).unwrap(), &Some(b"world".encode()));
	}

	pub fn create_state_diff_without_setting_externalities_works() {
		let mut state1 = default_db();

		state1.set(b"hello", b"world");

		assert_eq!(state1.ext.state_diff.get(&b"hello"[..]).unwrap(), &Some(b"world".encode()));
	}
}
