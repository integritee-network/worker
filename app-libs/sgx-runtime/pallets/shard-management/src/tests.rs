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
use crate::{mock::*, Error};
use enclave_bridge_primitives::{ShardConfig, UpgradableShardConfig};
use frame_support::{assert_err, assert_noop, assert_ok};
use frame_system::AccountInfo;
use pallet_balances::AccountData;
use sp_core::H256;
use sp_keyring::AccountKeyring;
use sp_runtime::{
	generic,
	traits::{BlakeTwo256, Header as HeaderT},
	DispatchError::BadOrigin,
};

pub type Header = generic::Header<BlockNumber, BlakeTwo256>;

#[test]
fn set_shard_config() {
	new_test_ext().execute_with(|| {
		let config = UpgradableShardConfig {
			active_config: ShardConfig {
				enclave_fingerprint: Default::default(),
				max_instances: None,
				authorities: None,
				maintenance_mode: false,
			},
			pending_upgrade: None,
			upgrade_at: None,
		};
		assert_ok!(ShardManagement::set_shard_config(RuntimeOrigin::root(), config.clone(), 42));
		assert_eq!(ShardManagement::upgradable_shard_config(), Some((config, 42)));
	})
}
