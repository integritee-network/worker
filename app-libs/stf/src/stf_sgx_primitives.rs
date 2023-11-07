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

use std::marker::PhantomData;

pub mod types {
	pub use itp_types::{AccountData, AccountInfo, BlockNumber, Header as ParentchainHeader};

	pub type State = itp_sgx_externalities::SgxExternalities;
	pub type StateType = itp_sgx_externalities::SgxExternalitiesType;
	pub type StateDiffType = itp_sgx_externalities::SgxExternalitiesDiffType;
}

pub struct Stf<TCS, G, State, Runtime> {
	phantom_data: PhantomData<(TCS, G, State, Runtime)>,
}
