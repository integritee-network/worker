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

use crate::{
	account_funding::AccountAndRole,
	config::Config,
	error::{Error, ServiceResult},
	parentchain_handler::HandleParentchain,
};
use futures::executor::block_on;
use itp_api_client_types::ParentchainApi;
use itp_enclave_api::{enclave_base::EnclaveBase, sidechain::Sidechain};
use itp_node_api::api_client::{pallet_sidechain::PalletSidechainApi, PalletTeerexApi};
use itp_settings::{
	files::{SIDECHAIN_PURGE_INTERVAL, SIDECHAIN_PURGE_LIMIT},
	sidechain::SLOT_DURATION,
};
use itp_types::{
	parentchain::{AccountId, Balance, ParentchainId},
	Header, ShardIdentifier, SidechainBlockNumber,
};
use its_consensus_slots::start_slot_worker;
use its_primitives::types::block::SignedBlock as SignedSidechainBlock;
use its_storage::{interface::FetchBlocks, start_sidechain_pruning_loop, BlockPruner};
use log::*;
use sp_runtime::{traits::IdentifyAccount, MultiSigner};
use std::{
	sync::{atomic::AtomicBool, Arc},
	thread,
};
use teerex_primitives::AnySigner;
use tokio::runtime::Handle;

/// Information about an account on a specified parentchain.
pub trait ParentchainIntegriteeSidechainInfo {
	fn last_finalized_block_number(&self) -> ServiceResult<SidechainBlockNumber>;
	fn primary_worker_for_shard(&self) -> ServiceResult<AccountId>;
	fn shard(&self) -> ServiceResult<ShardIdentifier>;
}

pub struct ParentchainIntegriteeSidechainInfoProvider {
	node_api: ParentchainApi,
	shard: ShardIdentifier,
}

impl ParentchainIntegriteeSidechainInfo for ParentchainIntegriteeSidechainInfoProvider {
	fn last_finalized_block_number(&self) -> ServiceResult<SidechainBlockNumber> {
		self.node_api
			.latest_sidechain_block_confirmation(&self.shard, None)?
			.map(|confirmation| confirmation.block_number)
			.ok_or(Error::MissingLastFinalizedBlock)
	}

	fn primary_worker_for_shard(&self) -> ServiceResult<AccountId> {
		self.node_api
			.primary_worker_for_shard(&self.shard, None)
			.map_err(|e| e.into())
			.and_then(|maybe_enclave| {
				maybe_enclave
					.iter()
					.filter_map(|enclave| {
						if let AnySigner::Known(MultiSigner::Ed25519(signer)) =
							enclave.instance_signer()
						{
							Some(signer.into_account().into())
						} else {
							None
						}
					})
					.next()
					.ok_or_else(|| Error::NoWorkerForShardFound(self.shard))
			})
	}
	fn shard(&self) -> ServiceResult<ShardIdentifier> {
		Ok(self.shard)
	}
}

impl ParentchainIntegriteeSidechainInfoProvider {
	pub fn new(node_api: ParentchainApi, shard: ShardIdentifier) -> Self {
		ParentchainIntegriteeSidechainInfoProvider { node_api, shard }
	}
}

pub(crate) fn sidechain_start_untrusted_rpc_server<SidechainStorage>(
	config: &Config,
	sidechain_storage: Arc<SidechainStorage>,
	tokio_handle: &Handle,
) where
	SidechainStorage: BlockPruner + FetchBlocks<SignedSidechainBlock> + Sync + Send + 'static,
{
	let untrusted_url = config.untrusted_worker_url();
	debug!(
		"starting untrusted RPC server listening to sidechain blocks from peers on {}",
		&untrusted_url
	);
	let _untrusted_rpc_join_handle = tokio_handle.spawn(async move {
		itc_rpc_server::run_server(&untrusted_url, sidechain_storage).await.unwrap();
	});
}

pub(crate) fn sidechain_init_block_production<Enclave, SidechainStorage>(
	enclave: Arc<Enclave>,
	sidechain_storage: Arc<SidechainStorage>,
	shutdown_flag: Arc<AtomicBool>,
) -> ServiceResult<Vec<thread::JoinHandle<()>>>
where
	Enclave: EnclaveBase + Sidechain,
	SidechainStorage: BlockPruner + FetchBlocks<SignedSidechainBlock> + Sync + Send + 'static,
{
	// ------------------------------------------------------------------------
	// Initialize sidechain components (has to be AFTER init_parentchain_components()
	enclave.init_enclave_sidechain_components().unwrap();

	// ------------------------------------------------------------------------
	// Start interval sidechain block production (execution of trusted calls, sidechain block production).
	let sidechain_enclave_api = enclave;
	println!("[+] Spawning thread for sidechain block production");
	let local_shutdown_flag = shutdown_flag.clone();
	let block_production_handle = thread::Builder::new()
		.name("interval_block_production_timer".to_owned())
		.spawn(move || {
			let future = start_slot_worker(
				|| execute_trusted_calls(sidechain_enclave_api.as_ref()),
				SLOT_DURATION,
				local_shutdown_flag,
			);
			block_on(future);
			println!("[!] Sidechain block production loop has terminated");
		})
		.map_err(|e| Error::Custom(Box::new(e)))?;

	// ------------------------------------------------------------------------
	// start sidechain pruning loop
	let pruning_handle = thread::Builder::new()
		.name("sidechain_pruning_loop".to_owned())
		.spawn(move || {
			start_sidechain_pruning_loop(
				&sidechain_storage,
				SIDECHAIN_PURGE_INTERVAL,
				SIDECHAIN_PURGE_LIMIT,
				shutdown_flag,
			);
			println!("[!] Sidechain block pruning loop has terminated");
		})
		.map_err(|e| Error::Custom(Box::new(e)))?;

	Ok([block_production_handle, pruning_handle].into())
}

/// Execute trusted operations in the enclave.
fn execute_trusted_calls<E: Sidechain>(enclave_api: &E) {
	if let Err(e) = enclave_api.execute_trusted_calls() {
		error!("{:?}", e);
	};
}
