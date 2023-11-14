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
//! Various way to filter Parentchain events

use crate::error::Error;
use core::marker::PhantomData;
use itp_api_client_types::Events;
use itp_sgx_runtime_primitives::types::{AccountId, Balance};
use itp_stf_primitives::{error::StfError, traits::IndirectExecutor};
use itp_test::mock::stf_mock::TrustedCallSignedMock;
use itp_types::{
	parentchain::{
		BalanceTransfer, ExtrinsicFailed, ExtrinsicStatus, ExtrinsicSuccess, FilterEvents,
		HandleParentchainEvents, ParentchainError,
	},
	H256,
};
use std::{format, vec::Vec};

impl From<StfError> for Error {
	fn from(a: StfError) -> Self {
		Error::Other(format!("Error when shielding for privacy sidechain {:?}", a).into())
	}
}

pub trait ToEvents<E> {
	fn to_events(&self) -> &E;
}

pub struct MockEvents;

impl FilterEvents for MockEvents {
	type Error = ();
	fn get_extrinsic_statuses(&self) -> core::result::Result<Vec<ExtrinsicStatus>, Self::Error> {
		Ok(Vec::from([ExtrinsicStatus::Success]))
	}

	fn get_transfer_events(&self) -> core::result::Result<Vec<BalanceTransfer>, Self::Error> {
		let transfer = BalanceTransfer {
			to: [0u8; 32].into(),
			from: [0u8; 32].into(),
			amount: Balance::default(),
		};
		Ok(Vec::from([transfer]))
	}
}

pub struct MockPrivacySidechain<Executor> {
	_phantom: PhantomData<Executor>,
}

impl<Executor> HandleParentchainEvents<Executor, TrustedCallSignedMock, Error>
	for MockPrivacySidechain<Executor>
where
	Executor: IndirectExecutor<TrustedCallSignedMock, Error>,
{
	fn handle_events(
		_: &Executor,
		_: impl itp_types::parentchain::FilterEvents,
	) -> core::result::Result<(), Error> {
		Ok(())
	}
}
