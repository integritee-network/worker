/*
	Copyright 2021 Integritee AG and Supercomputing Systems AG
	Copyright (C) 2017-2019 Baidu, Inc. All Rights Reserved.

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

use super::test_setup::TestStf;
use ita_stf::State;
use itp_sgx_externalities::{SgxExternalities, SgxExternalitiesTrait};
use itp_stf_interface::InitState;
use itp_stf_primitives::types::AccountId;
use itp_stf_state_handler::handle_state::HandleState;
use itp_types::ShardIdentifier;

/// Returns an empty `State` with the corresponding `ShardIdentifier`.
pub fn init_state<S: HandleState<StateT = SgxExternalities>>(
	state_handler: &S,
	enclave_account: AccountId,
) -> (State, ShardIdentifier) {
	let shard = ShardIdentifier::default();

	let _hash = state_handler.initialize_shard(shard).unwrap();
	let (lock, _) = state_handler.load_for_mutation(&shard).unwrap();
	let mut state = TestStf::init_state(enclave_account);
	state.prune_state_diff();

	state_handler.write_after_mutation(state.clone(), lock, &shard).unwrap();

	(state, shard)
}
