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

use crate::{error::Result, state_initializer::InitializeState};
use std::marker::PhantomData;

/// Initialize state mock.
pub struct InitializeStateMock<State> {
	init_state: State,
	_phantom: PhantomData<State>,
}

impl<State> InitializeStateMock<State> {
	pub fn new(init_state: State) -> Self {
		Self { init_state, _phantom: Default::default() }
	}
}

impl<State> InitializeState for InitializeStateMock<State>
where
	State: Clone,
{
	type StateType = State;

	fn initialize(&self) -> Result<Self::StateType> {
		Ok(self.init_state.clone())
	}
}
