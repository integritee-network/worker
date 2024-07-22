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
	config::Config,
	error::{Error, ServiceResult},
	parentchain_handler::HandleParentchain,
};
use futures::executor::block_on;
use itp_enclave_api::{enclave_base::EnclaveBase, sidechain::Sidechain};
use itp_settings::{
	files::{SIDECHAIN_PURGE_INTERVAL, SIDECHAIN_PURGE_LIMIT},
	sidechain::SLOT_DURATION,
};
use itp_types::{Header, ShardIdentifier};
use its_consensus_slots::start_slot_worker;
use its_primitives::types::block::SignedBlock as SignedSidechainBlock;
use its_storage::{interface::FetchBlocks, start_sidechain_pruning_loop, BlockPruner};
use log::*;
use std::{sync::Arc, thread};
use tokio::runtime::Handle;

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
) -> ServiceResult<()>
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
	thread::Builder::new()
		.name("interval_block_production_timer".to_owned())
		.spawn(move || {
			let future = start_slot_worker(
				|| execute_trusted_calls(sidechain_enclave_api.as_ref()),
				SLOT_DURATION,
			);
			block_on(future);
			println!("[!] Sidechain block production loop has terminated");
		})
		.map_err(|e| Error::Custom(Box::new(e)))?;

	// ------------------------------------------------------------------------
	// start sidechain pruning loop
	thread::Builder::new()
		.name("sidechain_pruning_loop".to_owned())
		.spawn(move || {
			start_sidechain_pruning_loop(
				&sidechain_storage,
				SIDECHAIN_PURGE_INTERVAL,
				SIDECHAIN_PURGE_LIMIT,
			);
		})
		.map_err(|e| Error::Custom(Box::new(e)))?;

	Ok(())
}

/// Execute trusted operations in the enclave.
fn execute_trusted_calls<E: Sidechain>(enclave_api: &E) {
	if let Err(e) = enclave_api.execute_trusted_calls() {
		error!("{:?}", e);
	};
}
