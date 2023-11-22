/*
	Copyright 2021 Integritee AG
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
use ita_parentchain_interface::{integritee, target_a, target_b};
use itc_parentchain::primitives::ParentchainId;
use itp_node_api::{
	api_client::{Api, ApiClientError, ApiResult, AssetRuntimeConfig, StorageKey},
	node_api_factory::{NodeApiFactory, NodeApiFactoryError, ParentchainApiWrapper},
};
use itp_types::parentchain::Hash;
use sp_core::sr25519;
use substrate_api_client::{
	ac_primitives::{Bytes, WithExtrinsicParams},
	rpc::{Request, TungsteniteRpcClient},
	ExtrinsicReport, GetStorage, ReadProof, SubmitAndWatch, SubmitExtrinsic, XtStatus,
};

/// Standard runtime config for Substrate and Polkadot nodes.
pub type IntegriteeRuntimeConfig =
	WithExtrinsicParams<AssetRuntimeConfig, integritee::ParentchainExtrinsicParams>;

/// runtime config for chains like Asset Hub or Encointer
pub type TargetARuntimeConfig =
	WithExtrinsicParams<AssetRuntimeConfig, target_a::ParentchainExtrinsicParams>;

/// Standard runtime config for Substrate and Polkadot nodes.
pub type TargetBRuntimeConfig =
	WithExtrinsicParams<AssetRuntimeConfig, target_b::ParentchainExtrinsicParams>;

pub enum ParentchainApiLocal {
	Integritee(IntegriteeParentchainApi),
	TargetA(TargetAParentchainApi),
	TargetB(TargetBParentchainApi),
}

impl ParentchainApiLocal {
	pub fn get_opaque_storage_by_key(
		&self,
		storage_key: StorageKey,
		at_block: Option<Hash>,
	) -> ApiResult<Option<Vec<u8>>> {
		match self {
			Self::Integritee(api) => api.get_opaque_storage_by_key(storage_key, at_block),
			Self::TargetA(api) => api.get_opaque_storage_by_key(storage_key, at_block),
			Self::TargetB(api) => api.get_opaque_storage_by_key(storage_key, at_block),
		}
	}
	pub fn get_storage_proof_by_keys(
		&self,
		storage_keys: Vec<StorageKey>,
		at_block: Option<Hash>,
	) -> ApiResult<Option<ReadProof<Hash>>> {
		match self {
			Self::Integritee(api) => api.get_storage_proof_by_keys(storage_keys, at_block),
			Self::TargetA(api) => api.get_storage_proof_by_keys(storage_keys, at_block),
			Self::TargetB(api) => api.get_storage_proof_by_keys(storage_keys, at_block),
		}
	}
	pub fn submit_and_watch_opaque_extrinsic_until(
		&self,
		encoded_extrinsic: &Bytes,
		watch_until: XtStatus,
	) -> ApiResult<ExtrinsicReport<Hash>> {
		match self {
			Self::Integritee(api) =>
				api.submit_and_watch_opaque_extrinsic_until(encoded_extrinsic, watch_until),
			Self::TargetA(api) =>
				api.submit_and_watch_opaque_extrinsic_until(encoded_extrinsic, watch_until),
			Self::TargetB(api) =>
				api.submit_and_watch_opaque_extrinsic_until(encoded_extrinsic, watch_until),
		}
	}
	pub fn submit_opaque_extrinsic(&self, encoded_extrinsic: &Bytes) -> ApiResult<Hash> {
		match self {
			Self::Integritee(api) => api.submit_opaque_extrinsic(encoded_extrinsic),
			Self::TargetA(api) => api.submit_opaque_extrinsic(encoded_extrinsic),
			Self::TargetB(api) => api.submit_opaque_extrinsic(encoded_extrinsic),
		}
	}
}

pub type IntegriteeParentchainApi = Api<IntegriteeRuntimeConfig, TungsteniteRpcClient>;
pub type TargetAParentchainApi = Api<TargetARuntimeConfig, TungsteniteRpcClient>;
pub type TargetBParentchainApi = Api<TargetBRuntimeConfig, TungsteniteRpcClient>;

pub struct IntegriteeParentchainApiWrapper(Api<IntegriteeRuntimeConfig, TungsteniteRpcClient>);

impl ParentchainApiWrapper for IntegriteeParentchainApiWrapper {
	type Api = IntegriteeParentchainApi;
	type Client = TungsteniteRpcClient;
	fn new_api(
		client: Self::Client,
		signer: sr25519::Pair,
	) -> Result<Self::Api, NodeApiFactoryError> {
		let mut api = Self::Api::new(client).map_err(NodeApiFactoryError::FailedToCreateNodeApi)?;
		api.set_signer(signer.into());
		Ok(api)
	}
}
pub struct TargetAParentchainApiWrapper(Api<TargetARuntimeConfig, TungsteniteRpcClient>);
impl ParentchainApiWrapper for TargetAParentchainApiWrapper {
	type Api = TargetAParentchainApi;
	type Client = TungsteniteRpcClient;
	fn new_api(
		client: Self::Client,
		signer: sr25519::Pair,
	) -> Result<Self::Api, NodeApiFactoryError> {
		let mut api = Self::Api::new(client).map_err(NodeApiFactoryError::FailedToCreateNodeApi)?;
		api.set_signer(signer.into());
		Ok(api)
	}
}
pub struct TargetBParentchainApiWrapper(Api<TargetBRuntimeConfig, TungsteniteRpcClient>);
impl ParentchainApiWrapper for TargetBParentchainApiWrapper {
	type Api = TargetBParentchainApi;
	type Client = TungsteniteRpcClient;
	fn new_api(
		client: Self::Client,
		signer: sr25519::Pair,
	) -> Result<Self::Api, NodeApiFactoryError> {
		let mut api = Self::Api::new(client).map_err(NodeApiFactoryError::FailedToCreateNodeApi)?;
		api.set_signer(signer.into());
		Ok(api)
	}
}
