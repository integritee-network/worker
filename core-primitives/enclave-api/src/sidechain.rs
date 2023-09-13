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

use crate::{error::Error, Enclave, EnclaveResult};
use codec::Encode;
use frame_support::ensure;
use itp_enclave_api_ffi as ffi;
use itp_storage::StorageProof;
use itp_types::parentchain::ParentchainId;
use sgx_types::sgx_status_t;
use sp_runtime::{generic::SignedBlock, traits::Block as ParentchainBlockTrait};

/// trait for handling blocks on the side chain
pub trait Sidechain: Send + Sync + 'static {
	/// Sync parentchain blocks and events. Execute pending tops
	/// and events proof in the enclave.
	fn sync_parentchain<ParentchainBlock: ParentchainBlockTrait>(
		&self,
		blocks: &[SignedBlock<ParentchainBlock>],
		events: &[Vec<u8>],
		events_proofs: &[StorageProof],
		parentchain_id: &ParentchainId,
	) -> EnclaveResult<()>;

	fn execute_trusted_calls(&self) -> EnclaveResult<()>;
}

impl Sidechain for Enclave {
	fn sync_parentchain<ParentchainBlock: ParentchainBlockTrait>(
		&self,
		blocks: &[SignedBlock<ParentchainBlock>],
		events: &[Vec<u8>],
		events_proofs: &[StorageProof],
		parentchain_id: &ParentchainId,
	) -> EnclaveResult<()> {
		let mut retval = sgx_status_t::SGX_SUCCESS;
		let blocks_enc = blocks.encode();
		let events_enc = events.encode();
		let events_proofs_enc = events_proofs.encode();
		let parentchain_id_enc = parentchain_id.encode();

		let result = unsafe {
			ffi::sync_parentchain(
				self.eid,
				&mut retval,
				blocks_enc.as_ptr(),
				blocks_enc.len(),
				events_enc.as_ptr(),
				events_enc.len(),
				events_proofs_enc.as_ptr(),
				events_proofs_enc.len(),
				parentchain_id_enc.as_ptr(),
				parentchain_id_enc.len() as u32,
			)
		};

		ensure!(result == sgx_status_t::SGX_SUCCESS, Error::Sgx(result));
		ensure!(retval == sgx_status_t::SGX_SUCCESS, Error::Sgx(retval));

		Ok(())
	}

	fn execute_trusted_calls(&self) -> EnclaveResult<()> {
		let mut retval = sgx_status_t::SGX_SUCCESS;

		let result = unsafe { ffi::execute_trusted_calls(self.eid, &mut retval) };

		ensure!(result == sgx_status_t::SGX_SUCCESS, Error::Sgx(result));
		ensure!(retval == sgx_status_t::SGX_SUCCESS, Error::Sgx(retval));

		Ok(())
	}
}
