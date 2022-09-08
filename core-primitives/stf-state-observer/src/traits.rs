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

use crate::error::Result;
use itp_types::ShardIdentifier;

/// Observe state trait.
pub trait ObserveState {
	type StateType;

	/// Requires a &mut StateType because the externalities are always executed with a mutable reference.
	/// Underneath it all, the environmental!() macro only knows mutable access unfortunately.
	/// And since the sp-io interface is fixed and relies on the global instance created by environmental!(),
	/// it forces &mut access upon us here, even though read-only access would be enough.
	fn observe_state<F, R>(&self, shard: &ShardIdentifier, observation_func: F) -> Result<R>
	where
		F: FnOnce(&mut Self::StateType) -> R;
}

/// Trait to queue a state update for an observer.
pub trait UpdateState<StateType> {
	fn queue_state_update(&self, shard: ShardIdentifier, state: StateType) -> Result<()>;
}
