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
use crate::{error::Result, AdditionalParamsOf, CreateExtrinsics};
use core::marker::PhantomData;
use itp_types::{parentchain::GenericMortality, Balance, OpaqueCall, H256};
use sp_runtime::OpaqueExtrinsic;
use std::vec::Vec;

pub use itp_node_api::api_client::{
	Config, GenericExtrinsicParams, ParentchainRuntimeConfig, PlainTip,
};

/// Mock of an extrinsics factory. To be used in unit tests.
///
/// Returns an empty extrinsic.
#[derive(Clone)]
pub struct ExtrinsicsFactoryMock<C> {
	_phantom: PhantomData<C>,
}

impl<C> Default for ExtrinsicsFactoryMock<C> {
	fn default() -> Self {
		Self { _phantom: Default::default() }
	}
}

impl CreateExtrinsics for ExtrinsicsFactoryMock<ParentchainRuntimeConfig> {
	type Config = ParentchainRuntimeConfig;
	type ExtrinsicParams = GenericExtrinsicParams<ParentchainRuntimeConfig, PlainTip<Balance>>;

	fn create_extrinsics(
		&self,
		_calls: &[(OpaqueCall, GenericMortality)],
		_additional_params: Option<
			AdditionalParamsOf<ParentchainRuntimeConfig, Self::ExtrinsicParams>,
		>,
	) -> Result<Vec<OpaqueExtrinsic>> {
		// Intention was to map an OpaqueCall to some dummy OpaqueExtrinsic,
		// so the output vector has the same size as the input one (and thus can be tested from the outside).
		// However, it doesn't seem to be possible to construct an empty of dummy OpaqueExtrinsic,
		// `from_bytes` expects a valid encoded OpaqueExtrinsic.
		// Ok(calls
		// 	.iter()
		// 	.map(|_| OpaqueExtrinsic::from_bytes(Vec::new().as_slice()).unwrap())
		// 	.collect())
		Ok(Vec::new())
	}

	fn genesis_hash(&self) -> H256 {
		H256::default()
	}
}
