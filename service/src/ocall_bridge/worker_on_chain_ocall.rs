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

use crate::ocall_bridge::bridge_api::{OCallBridgeError, OCallBridgeResult, WorkerOnChainBridge};
use chrono::Local;
use codec::{Decode, Encode};
use ita_parentchain_interface::{
	integritee::{api_client_types::IntegriteeApi, api_factory::IntegriteeNodeApiFactory},
	target_a::{api_client_types::TargetAApi, api_factory::TargetANodeApiFactory},
	target_b::{api_client_types::TargetBApi, api_factory::TargetBNodeApiFactory},
	ParentchainRuntimeConfig,
};
use itp_api_client_types::Request;
use itp_node_api::{
	api_client::{AccountApi, Config},
	node_api_factory::{CreateNodeApi, NodeApiFactory},
};
use itp_types::{
	parentchain::{AccountId, Header as ParentchainHeader, ParentchainId},
	BlockHash, DigestItem, Nonce, WorkerRequest, WorkerResponse,
};
use itp_utils::hex::hex_encode;
use log::*;
use sp_core::blake2_256;
use sp_runtime::{Digest, OpaqueExtrinsic};
use std::{
	fs::{create_dir_all, File},
	io::{self, Write},
	path::Path,
	sync::Arc,
	vec::Vec,
};
use substrate_api_client::{
	ac_primitives,
	ac_primitives::{serde_impls::StorageKey, Header, SubstrateHeader},
	rpc::TungsteniteRpcClient,
	Api, GetAccountInformation, GetChainInfo, GetStorage, SubmitAndWatch, SubmitExtrinsic,
	XtStatus,
};

pub struct WorkerOnChainOCall<
	IntegriteeConfig: Config,
	TargetAConfig: Config,
	TargetBConfig: Config,
	Client: Request,
> {
	integritee_api_factory: Arc<NodeApiFactory<IntegriteeConfig, Client>>,
	target_a_parentchain_api_factory: Option<Arc<NodeApiFactory<TargetAConfig, Client>>>,
	target_b_parentchain_api_factory: Option<Arc<NodeApiFactory<TargetBConfig, Client>>>,
	log_dir: Arc<Path>,
}

impl<IntegriteeConfig: Config, TargetAConfig: Config, TargetBConfig: Config>
	WorkerOnChainOCall<IntegriteeConfig, TargetAConfig, TargetBConfig, TungsteniteRpcClient>
where
	<IntegriteeConfig as Config>::ExtrinsicSigner: From<sp_core::sr25519::Pair>,
	<TargetAConfig as Config>::ExtrinsicSigner: From<sp_core::sr25519::Pair>,
	<TargetBConfig as Config>::ExtrinsicSigner: From<sp_core::sr25519::Pair>,
{
	pub fn new(
		integritee_api_factory: Arc<NodeApiFactory<IntegriteeConfig, TungsteniteRpcClient>>,
		target_a_parentchain_api_factory: Option<
			Arc<NodeApiFactory<TargetAConfig, TungsteniteRpcClient>>,
		>,
		target_b_parentchain_api_factory: Option<
			Arc<NodeApiFactory<TargetBConfig, TungsteniteRpcClient>>,
		>,
		log_dir: Arc<Path>,
	) -> Self {
		WorkerOnChainOCall {
			integritee_api_factory,
			target_a_parentchain_api_factory,
			target_b_parentchain_api_factory,
			log_dir,
		}
	}
}

impl<
		IntegriteeConfig: Config<Hash = BlockHash, Index = Nonce, AccountId = AccountId>,
		TargetAConfig: Config<Hash = BlockHash, Index = Nonce, AccountId = AccountId>,
		TargetBConfig: Config<Hash = BlockHash, Index = Nonce, AccountId = AccountId>,
	> WorkerOnChainOCall<IntegriteeConfig, TargetAConfig, TargetBConfig, TungsteniteRpcClient>
where
	<IntegriteeConfig as Config>::ExtrinsicSigner: From<sp_core::sr25519::Pair>,
	<TargetAConfig as Config>::ExtrinsicSigner: From<sp_core::sr25519::Pair>,
	<TargetBConfig as Config>::ExtrinsicSigner: From<sp_core::sr25519::Pair>,
{
	pub fn create_integritee_api(
		&self,
	) -> OCallBridgeResult<Api<IntegriteeConfig, TungsteniteRpcClient>> {
		Ok(self.integritee_api_factory.create_api()?)
	}

	pub fn create_target_a_api(
		&self,
	) -> OCallBridgeResult<Api<TargetAConfig, TungsteniteRpcClient>> {
		self.target_a_parentchain_api_factory
			.as_ref()
			.ok_or(OCallBridgeError::TargetAParentchainNotInitialized)
			.and_then(|f| f.create_api().map_err(Into::into))
	}

	pub fn create_target_b_api(
		&self,
	) -> OCallBridgeResult<Api<TargetBConfig, TungsteniteRpcClient>> {
		self.target_b_parentchain_api_factory
			.as_ref()
			.ok_or(OCallBridgeError::TargetBParentchainNotInitialized)
			.and_then(|f| f.create_api().map_err(Into::into))
	}

	fn handle_requests<
		Config: itp_api_client_types::Config<Hash = BlockHash, Index = Nonce, AccountId = AccountId>,
	>(
		&self,
		api: &Api<Config, TungsteniteRpcClient>,
		requests: Vec<WorkerRequest>,
		parentchain_id: ParentchainId,
	) -> OCallBridgeResult<Vec<WorkerResponse<ParentchainHeader, Vec<u8>>>> {
		let last_finalized =
			api.get_finalized_head().map_err(|_| OCallBridgeError::NodeApiError)?;
		let header = if let Some(header) =
			api.get_header(last_finalized).map_err(|_| OCallBridgeError::NodeApiError)?
		{
			header
		} else {
			warn!("failed to fetch parentchain header. can't answer WorkerRequest");
			return Ok(vec![])
		};
		let resp: Vec<WorkerResponse<ParentchainHeader, Vec<u8>>> = requests
			.into_iter()
			.map(|req| match req {
				WorkerRequest::ChainStorage(key, maybe_hash) => {
					let maybe_opaque_storage = api
						.get_opaque_storage_by_key(StorageKey(key.clone()), maybe_hash)
						.map_err(|e| {
							warn!(
								"failed to fetch storage for key: {:?}, error: {:?}",
								hex_encode(&key),
								e
							);
							e
						})
						.ok()
						.flatten();
					let maybe_proof = api
						.get_storage_proof_by_keys(vec![StorageKey(key.clone())], maybe_hash)
						.map_err(|e| {
							warn!(
								"failed to fetch storage proof for key: {:?}, error: {:?}",
								hex_encode(&key),
								e
							);
							e
						})
						.ok()
						.flatten()
						.map(|read_proof| {
							read_proof
								.proof
								.into_iter()
								.map(|bytes| bytes.0)
								.collect::<Vec<Vec<u8>>>()
						});
					trace!("(mirror) ocall fetched key: {}", hex_encode(&key));
					trace!(
						"(mirror) ocall fetched storage: {:?}",
						maybe_opaque_storage.clone().map(|v| hex_encode(&v))
					);
					trace!(
						"(mirror) ocall fetched proof: {:?}",
						maybe_proof.clone().map(|v| hex_encode(&v.encode()))
					);
					WorkerResponse::ChainStorage(key, maybe_opaque_storage, maybe_proof)
				},
				WorkerRequest::LatestParentchainHeaderUnverified => {
					WorkerResponse::LatestParentchainHeaderUnverified(
						// todo: fix this dirty type hack
						ParentchainHeader::decode(&mut header.encode().as_slice()).unwrap(),
					)
				},
				WorkerRequest::NextNonceFor(account) => {
					let nonce = api.get_system_account_next_index(account).ok();
					WorkerResponse::NextNonce(nonce)
				},
			})
			.collect();

		Ok(resp)
	}

	fn submit_extrinsics_to_parentchain<
		Config: itp_api_client_types::Config<Hash = BlockHash, Index = Nonce, AccountId = AccountId>,
	>(
		&self,
		api: &Api<Config, TungsteniteRpcClient>,
		extrinsics: Vec<OpaqueExtrinsic>,
		parentchain_id: ParentchainId,
		await_each_inclusion: bool,
	) -> OCallBridgeResult<()> {
		debug!(
			"Enclave wants to send {} extrinsics to parentchain: {:?}. await each inclusion: {:?}",
			extrinsics.len(),
			parentchain_id,
			await_each_inclusion
		);
		log_extrinsics_to_file(self.log_dir.clone(), parentchain_id, extrinsics.clone())
			.map_err(|e| {
				error!("Error logging extrinsic to disk: {}", e);
				e
			})
			.unwrap_or_default();

		for (index, call) in extrinsics.into_iter().enumerate() {
			if await_each_inclusion {
				if let Err(e) = api.submit_and_watch_opaque_extrinsic_until(
					&call.encode().into(),
					XtStatus::InBlock,
				) {
					error!(
						"Could not send extrinsic {} to {:?}: {:?}, error: {:?}",
						index,
						parentchain_id,
						serde_json::to_string(&call),
						e
					);
				}
			} else if let Err(e) = api.submit_opaque_extrinsic(&call.encode().into()) {
				error!(
					"Could not send extrinsic {} to {:?}: {:?}, error: {:?}",
					index,
					parentchain_id,
					serde_json::to_string(&call),
					e
				);
			}
		}

		Ok(())
	}
}

impl<
		IntegriteeConfig: Config<Hash = BlockHash, Index = Nonce, AccountId = AccountId>,
		TargetAConfig: Config<Hash = BlockHash, Index = Nonce, AccountId = AccountId>,
		TargetBConfig: Config<Hash = BlockHash, Index = Nonce, AccountId = AccountId>,
	> WorkerOnChainBridge
	for WorkerOnChainOCall<IntegriteeConfig, TargetAConfig, TargetBConfig, TungsteniteRpcClient>
where
	<IntegriteeConfig as Config>::ExtrinsicSigner: From<sp_core::sr25519::Pair>,
	<TargetAConfig as Config>::ExtrinsicSigner: From<sp_core::sr25519::Pair>,
	<TargetBConfig as Config>::ExtrinsicSigner: From<sp_core::sr25519::Pair>,
{
	fn worker_request(
		&self,
		request: Vec<u8>,
		parentchain_id: Vec<u8>,
	) -> OCallBridgeResult<Vec<u8>> {
		let parentchain_id = ParentchainId::decode(&mut parentchain_id.as_slice())?;
		debug!("[{:?}]    Entering ocall_worker_request", parentchain_id);

		let requests: Vec<WorkerRequest> = Decode::decode(&mut request.as_slice())?;
		if requests.is_empty() {
			debug!("requests is empty, returning empty vector");
			return Ok(Vec::<u8>::new().encode())
		}

		let resp = match parentchain_id {
			ParentchainId::Integritee => {
				let api = self.integritee_api_factory.create_api()?;
				self.handle_requests(&api, requests, parentchain_id)?
			},
			ParentchainId::TargetA => {
				let api = self
					.target_a_parentchain_api_factory
					.as_ref()
					.ok_or(OCallBridgeError::TargetAParentchainNotInitialized)?
					.create_api()?;
				self.handle_requests(&api, requests, parentchain_id)?
			},
			ParentchainId::TargetB => {
				let api = self
					.target_b_parentchain_api_factory
					.as_ref()
					.ok_or(OCallBridgeError::TargetBParentchainNotInitialized)?
					.create_api()?;
				self.handle_requests(&api, requests, parentchain_id)?
			},
		};

		let encoded_response: Vec<u8> = resp.encode();

		Ok(encoded_response)
	}

	fn send_to_parentchain(
		&self,
		extrinsics_encoded: Vec<u8>,
		parentchain_id: Vec<u8>,
		await_each_inclusion: bool,
	) -> OCallBridgeResult<()> {
		let extrinsics: Vec<OpaqueExtrinsic> =
			match Decode::decode(&mut extrinsics_encoded.as_slice()) {
				Ok(calls) => calls,
				Err(_) =>
					return Err(OCallBridgeError::SendExtrinsicsToParentchain(
						"Could not decode extrinsics".to_string(),
					)),
			};

		if extrinsics.is_empty() {
			return Ok(())
		}

		let parentchain_id = ParentchainId::decode(&mut parentchain_id.as_slice())?;

		match parentchain_id {
			ParentchainId::Integritee => {
				let api = self.integritee_api_factory.create_api()?;
				self.submit_extrinsics_to_parentchain(
					&api,
					extrinsics,
					parentchain_id,
					await_each_inclusion,
				)?
			},
			ParentchainId::TargetA => {
				let api = self
					.target_a_parentchain_api_factory
					.as_ref()
					.ok_or(OCallBridgeError::TargetAParentchainNotInitialized)?
					.create_api()?;
				self.submit_extrinsics_to_parentchain(
					&api,
					extrinsics,
					parentchain_id,
					await_each_inclusion,
				)?
			},
			ParentchainId::TargetB => {
				let api = self
					.target_b_parentchain_api_factory
					.as_ref()
					.ok_or(OCallBridgeError::TargetBParentchainNotInitialized)?
					.create_api()?;
				self.submit_extrinsics_to_parentchain(
					&api,
					extrinsics,
					parentchain_id,
					await_each_inclusion,
				)?
			},
		};

		Ok(())
	}
}

fn log_extrinsics_to_file(
	log_dir: Arc<Path>,
	parentchain_id: ParentchainId,
	extrinsics: Vec<OpaqueExtrinsic>,
) -> io::Result<()> {
	let log_dir = log_dir.join(format!("log-extrinsics-to-{}", parentchain_id));
	create_dir_all(&log_dir)?;
	let timestamp = Local::now().format("%Y%m%d-%H%M%S-%3f").to_string();
	let file_name = format!("extrinsics-{}.hex", timestamp);
	let file_path = log_dir.join(file_name);

	// Create the file in the specified directory
	let mut file = File::create(file_path)?;
	for xt in extrinsics {
		writeln!(file, "0x{}", hex::encode(xt.encode()))?;
	}
	Ok(())
}
