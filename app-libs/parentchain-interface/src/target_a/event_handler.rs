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

pub use ita_sgx_runtime::{Balance, Index};

use ita_stf::TrustedCallSigned;
use itc_parentchain_indirect_calls_executor::error::Error;
use itp_stf_primitives::traits::IndirectExecutor;
use itp_types::parentchain::{AccountId, FilterEvents, HandleParentchainEvents};
use log::*;

pub struct ParentchainEventHandler {}

impl<Executor> HandleParentchainEvents<Executor, TrustedCallSigned, Error>
	for ParentchainEventHandler
where
	Executor: IndirectExecutor<TrustedCallSigned, Error>,
{
	fn handle_events(
		_executor: &Executor,
		_events: impl FilterEvents,
		_vault_account: &AccountId,
	) -> Result<(), Error> {
		debug!("not handling any events for target A");
		Ok(())
	}
}
