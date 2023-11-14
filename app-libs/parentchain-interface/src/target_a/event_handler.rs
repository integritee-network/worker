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

use codec::{Decode, Encode};
use core::{fmt::Debug, marker::PhantomData};
use frame_support::traits::UnfilteredDispatchable;
pub use ita_sgx_runtime::{Balance, Index};
use ita_sgx_runtime::{Runtime, System};
use ita_stf::{Getter, TrustedCall, TrustedCallSigned};
use itc_parentchain_indirect_calls_executor::error::Error;
use itp_stf_primitives::{
	traits::{IndirectExecutor, TrustedCallVerification},
	types::TrustedOperation,
};
use itp_types::parentchain::{AccountId, FilterEvents, HandleParentchainEvents, ParentchainError};
use log::*;
use sp_runtime::MultiAddress;

pub struct ParentchainEventHandler {}

impl<Executor> HandleParentchainEvents<Executor, TrustedCallSigned, Error>
	for ParentchainEventHandler
where
	Executor: IndirectExecutor<TrustedCallSigned, Error>,
{
	fn handle_events(executor: &Executor, events: impl FilterEvents) -> Result<(), Error> {
		debug!("not handling any events for target A");
		Ok(())
	}
}
