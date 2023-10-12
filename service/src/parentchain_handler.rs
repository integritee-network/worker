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

use crate::error::{Error, ServiceResult};
use codec::{Decode, Encode};
use itc_parentchain::{
	light_client::light_client_init_params::{GrandpaParams, SimpleParams},
	primitives::{ParentchainId, ParentchainInitParams},
};
use itp_api_client_types::ParentchainApi;
use itp_enclave_api::{enclave_base::EnclaveBase, sidechain::Sidechain};
use itp_node_api::api_client::ChainApi;
use itp_storage::StorageProof;
use log::*;
use my_node_runtime::Header;
use sp_consensus_grandpa::VersionedAuthorityList;
use sp_runtime::traits::Header as HeaderTrait;
use std::{cmp::min, sync::Arc};
use substrate_api_client::ac_primitives::{Block, Header as HeaderT};

const BLOCK_SYNC_BATCH_SIZE: u32 = 1000;

pub trait HandleParentchain {
	/// Initializes all parentchain specific components on the enclave side.
	/// Returns the latest synced block header.
	fn init_parentchain_components(&self) -> ServiceResult<Header>;

	/// Fetches the parentchain blocks to sync from the parentchain and feeds them to the enclave.
	/// Returns the latest synced block header.
	fn sync_parentchain(&self, last_synced_header: Header) -> ServiceResult<Header>;

	/// Triggers the import of the synced parentchain blocks inside the enclave.
	fn trigger_parentchain_block_import(&self) -> ServiceResult<()>;

	/// Syncs and directly imports parentchain blocks from the latest synced header
	/// until the specified sync_target.
	fn sync_and_import_parentchain_until(
		&self,
		last_synced_header: &Header,
		sync_target: &Header,
	) -> ServiceResult<Header>;
}

/// Handles the interaction between parentchain and enclave.
pub(crate) struct ParentchainHandler<ParentchainApi, EnclaveApi> {
	parentchain_api: ParentchainApi,
	enclave_api: Arc<EnclaveApi>,
	parentchain_init_params: ParentchainInitParams,
}

// #TODO: #1451: Reintroduce `ParentchainApi: ChainApi` once there is no trait bound conflict
// any more with the api-clients own trait definitions.
impl<EnclaveApi> ParentchainHandler<ParentchainApi, EnclaveApi>
where
	EnclaveApi: EnclaveBase,
{
	pub fn new(
		parentchain_api: ParentchainApi,
		enclave_api: Arc<EnclaveApi>,
		parentchain_init_params: ParentchainInitParams,
	) -> Self {
		Self { parentchain_api, enclave_api, parentchain_init_params }
	}

	// FIXME: Necessary in the future? Fix with #1080
	pub fn new_with_automatic_light_client_allocation(
		parentchain_api: ParentchainApi,
		enclave_api: Arc<EnclaveApi>,
		id: ParentchainId,
	) -> ServiceResult<Self> {
		let genesis_hash = parentchain_api.get_genesis_hash()?;
		let genesis_header =
			parentchain_api.header(Some(genesis_hash))?.ok_or(Error::MissingGenesisHeader)?;

		let parentchain_init_params: ParentchainInitParams = if parentchain_api
			.is_grandpa_available()?
		{
			let grandpas = parentchain_api.grandpa_authorities(Some(genesis_hash))?;
			let grandpa_proof = parentchain_api.grandpa_authorities_proof(Some(genesis_hash))?;

			debug!("[{:?}] Grandpa Authority List: \n {:?} \n ", id, grandpas);

			let authority_list = VersionedAuthorityList::from(grandpas);

			(
				id,
				GrandpaParams::new(
					// #TODO: #1451: clean up type hacks
					Header::decode(&mut genesis_header.encode().as_slice())?,
					authority_list.into(),
					grandpa_proof,
				),
			)
				.into()
		} else {
			(
				id,
				SimpleParams::new(
					// #TODO: #1451: clean up type hacks
					Header::decode(&mut genesis_header.encode().as_slice())?,
				),
			)
				.into()
		};

		Ok(Self::new(parentchain_api, enclave_api, parentchain_init_params))
	}

	pub fn parentchain_api(&self) -> &ParentchainApi {
		&self.parentchain_api
	}

	pub fn parentchain_id(&self) -> &ParentchainId {
		self.parentchain_init_params.id()
	}
}

impl<EnclaveApi> HandleParentchain for ParentchainHandler<ParentchainApi, EnclaveApi>
where
	EnclaveApi: Sidechain + EnclaveBase,
{
	fn init_parentchain_components(&self) -> ServiceResult<Header> {
		Ok(self
			.enclave_api
			.init_parentchain_components(self.parentchain_init_params.clone())?)
	}

	fn sync_parentchain(&self, last_synced_header: Header) -> ServiceResult<Header> {
		let id = self.parentchain_id();
		trace!("[{:?}] Getting current head", id);
		let curr_block = self
			.parentchain_api
			.last_finalized_block()?
			.ok_or(Error::MissingLastFinalizedBlock)?;
		let curr_block_number = curr_block.block.header().number();

		if last_synced_header.number == curr_block_number {
			println!(
				"[{:?}] No sync necessary, we are already up to date with block {}",
				id, last_synced_header.number,
			);
			return Ok(last_synced_header)
		}

		println!(
			"[{:?}] Syncing blocks from {} to {}",
			id, last_synced_header.number, curr_block_number
		);

		let mut until_synced_header = last_synced_header;
		loop {
			until_synced_header = self.sync_blocks(
				until_synced_header.number + 1,
				min(until_synced_header.number + BLOCK_SYNC_BATCH_SIZE, curr_block_number),
			)?;

			println!(
				"[{:?}] Synced {} out of {} finalized parentchain blocks",
				id, until_synced_header.number, curr_block_number,
			);

			if &until_synced_header.number >= &curr_block_number {
				return Ok(until_synced_header)
			}
		}
	}

	fn trigger_parentchain_block_import(&self) -> ServiceResult<()> {
		trace!("[{:?}] trigger parentchain block import", self.parentchain_id());
		Ok(self.enclave_api.trigger_parentchain_block_import(self.parentchain_id())?)
	}

	fn sync_and_import_parentchain_until(
		&self,
		last_synced_header: &Header,
		sync_target: &Header,
	) -> ServiceResult<Header> {
		let id = self.parentchain_id();

		println!(
			"[{:?}] last synced block number: {}. syncing until {}",
			id, last_synced_header.number, sync_target.number
		);
		let mut last_synced_header = last_synced_header.clone();

		while last_synced_header.number() < sync_target.number() {
			let curr_block_number = self
				.parentchain_api
				.last_finalized_block()?
				.ok_or(Error::MissingLastFinalizedBlock)?
				.block
				.header()
				.number;

			if curr_block_number < sync_target.number
				&& curr_block_number < last_synced_header.number + 1
			{
				// Skip the rest of the loop and wait if we have synced as much
				// as possible, but haven't reached the sync target yet.
				println!(
					"[{:?}] sync target #{} is not finalized (#{}), wait a sec ...",
					id, sync_target.number, curr_block_number
				);
				std::thread::sleep(std::time::Duration::from_secs(1));
				continue
			}

			// min(sync_target, last_synced.number + chunk_size, current_parentchain_finalized_block)
			let chunk_target = min(
				min(last_synced_header.number + BLOCK_SYNC_BATCH_SIZE, curr_block_number),
				sync_target.number,
			);

			// Tested above that last_synced_header.number < current_block_number (i.e. chunk_target).
			last_synced_header = self.sync_blocks(last_synced_header.number + 1, chunk_target)?;
			trace!("[{:?}] synced block number: {}", id, last_synced_header.number);

			// Verify and import blocks into the light client. This can't be done after the loop
			// because the import is mandatory to remove them from RAM. When we register on
			// a production system that has already many blocks, this might lead to an OOM if we
			// import them all at once after the loop, see #1462.
			self.trigger_parentchain_block_import()?;
		}

		Ok(last_synced_header)
	}
}

impl<EnclaveApi> ParentchainHandler<ParentchainApi, EnclaveApi>
where
	EnclaveApi: Sidechain + EnclaveBase,
{
	fn sync_blocks(&self, from: u32, to: u32) -> ServiceResult<Header> {
		let id = self.parentchain_id();

		if from > to {
			return Err(Error::ApplicationSetup(format!(
				"[{:?}] from can't be bigger than to. {} > {}",
				id, from, to
			)))
		}

		let blocks = self.parentchain_api.get_blocks(from, to)?;
		println!("[+] [{:?}] Found {} block(s) to sync", id, blocks.len());

		let events: Vec<Vec<u8>> = blocks
			.iter()
			.map(|block| self.parentchain_api.get_events_for_block(Some(block.block.header.hash())))
			.collect::<Result<Vec<_>, _>>()?;

		println!("[+] [{:?}] Found {} event vector(s) to sync", id, events.len());

		let events_proofs: Vec<StorageProof> = blocks
			.iter()
			.map(|block| {
				self.parentchain_api.get_events_value_proof(Some(block.block.header.hash()))
			})
			.collect::<Result<Vec<_>, _>>()?;

		self.enclave_api.sync_parentchain(
			blocks.as_slice(),
			events.as_slice(),
			events_proofs.as_slice(),
			self.parentchain_id(),
		)?;

		let last_synced_header =
			blocks.last().map(|b| b.block.header.clone()).ok_or(Error::EmptyChunk)?;

		// #TODO: #1451: fix api/client types
		Ok(Header::decode(&mut last_synced_header.encode().as_slice())
			.expect("Can decode previously encoded header; qed"))
	}
}
