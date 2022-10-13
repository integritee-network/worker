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
use itc_parentchain_light_client::light_client_init_params::LightClientInitParams;
use itp_enclave_api::{enclave_base::EnclaveBase, sidechain::Sidechain};
use itp_node_api::api_client::ChainApi;
use itp_types::SignedBlock;
use log::*;
use my_node_runtime::Header;
use sp_finality_grandpa::VersionedAuthorityList;
use sp_runtime::traits::Header as HeaderTrait;
use std::{cmp::min, sync::Arc};

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

	/// Snycs and directly imports parentchain block until specified header.
	fn sync_and_import_parentchain_until(
		&self,
		last_synced_header: &Header,
		until_header: &Header,
	) -> ServiceResult<Header>;
}

/// Handles the interaction between parentchain and enclave.
pub(crate) struct ParentchainHandler<ParentchainApi: ChainApi, EnclaveApi: Sidechain> {
	parentchain_api: ParentchainApi,
	enclave_api: Arc<EnclaveApi>,
}

impl<ParentchainApi, EnclaveApi> ParentchainHandler<ParentchainApi, EnclaveApi>
where
	ParentchainApi: ChainApi,
	EnclaveApi: Sidechain + EnclaveBase,
{
	pub fn new(parentchain_api: ParentchainApi, enclave_api: Arc<EnclaveApi>) -> Self {
		Self { parentchain_api, enclave_api }
	}

	pub fn parentchain_api(&self) -> &ParentchainApi {
		&self.parentchain_api
	}
}

impl<ParentchainApi, EnclaveApi> HandleParentchain
	for ParentchainHandler<ParentchainApi, EnclaveApi>
where
	ParentchainApi: ChainApi,
	EnclaveApi: Sidechain + EnclaveBase,
{
	fn init_parentchain_components(&self) -> ServiceResult<Header> {
		let genesis_hash = self.parentchain_api.get_genesis_hash()?;
		let genesis_header: Header = self
			.parentchain_api
			.get_header(Some(genesis_hash))?
			.ok_or(Error::MissingGenesisHeader)?;
		info!("Got genesis Header: \n {:?} \n", genesis_header);
		if self.parentchain_api.is_grandpa_available()? {
			let grandpas = self.parentchain_api.grandpa_authorities(Some(genesis_hash))?;
			let grandpa_proof =
				self.parentchain_api.grandpa_authorities_proof(Some(genesis_hash))?;

			debug!("Grandpa Authority List: \n {:?} \n ", grandpas);

			let authority_list = VersionedAuthorityList::from(grandpas);

			let params = LightClientInitParams::Grandpa {
				genesis_header,
				authorities: authority_list.into(),
				authority_proof: grandpa_proof,
			};

			Ok(self.enclave_api.init_parentchain_components(params)?)
		} else {
			let params = LightClientInitParams::Parachain { genesis_header };

			Ok(self.enclave_api.init_parentchain_components(params)?)
		}
	}

	fn sync_parentchain(&self, last_synced_header: Header) -> ServiceResult<Header> {
		trace!("Getting current head");
		let curr_block: SignedBlock = self
			.parentchain_api
			.last_finalized_block()?
			.ok_or(Error::MissingLastFinalizedBlock)?;
		let curr_block_number = curr_block.block.header.number;

		let mut until_synced_header = last_synced_header;
		loop {
			let block_chunk_to_sync = self.parentchain_api.get_blocks(
				until_synced_header.number + 1,
				min(until_synced_header.number + BLOCK_SYNC_BATCH_SIZE, curr_block_number),
			)?;
			println!("[+] Found {} block(s) to sync", block_chunk_to_sync.len());
			if block_chunk_to_sync.is_empty() {
				return Ok(until_synced_header)
			}

			self.enclave_api.sync_parentchain(block_chunk_to_sync.as_slice(), 0)?;

			until_synced_header = block_chunk_to_sync
				.last()
				.map(|b| b.block.header.clone())
				.ok_or(Error::EmptyChunk)?;
			println!(
				"Synced {} out of {} finalized parentchain blocks",
				until_synced_header.number, curr_block_number,
			)
		}
	}

	fn trigger_parentchain_block_import(&self) -> ServiceResult<()> {
		Ok(self.enclave_api.trigger_parentchain_block_import()?)
	}

	fn sync_and_import_parentchain_until(
		&self,
		last_synced_header: &Header,
		until_header: &Header,
	) -> ServiceResult<Header> {
		let mut last_synced_header = last_synced_header.clone();

		while last_synced_header.number() < until_header.number() {
			last_synced_header = self.sync_parentchain(last_synced_header)?;
		}
		self.trigger_parentchain_block_import()?;

		Ok(last_synced_header)
	}
}
