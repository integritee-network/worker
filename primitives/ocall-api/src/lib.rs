/*
	Copyright 2019 Supercomputing Systems AG

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

#![cfg_attr(not(feature = "std"), no_std)]

use codec::{Decode, Encode};
use core::fmt::Debug;
use sgx_types::*;
use sp_std::prelude::Vec;
use substratee_worker_primitives::{
	block::SignedBlock as SignedSidechainBlock, TrustedOperationStatus, WorkerRequest,
	WorkerResponse,
};

/// Trait for the enclave to make o-calls related to remote attestation
pub trait EnclaveAttestationOCallApi: Clone + Debug + Send + Sync {
	fn sgx_init_quote(&self) -> SgxResult<(sgx_target_info_t, sgx_epid_group_id_t)>;

	fn get_ias_socket(&self) -> SgxResult<i32>;

	fn get_quote(
		&self,
		sig_rl: Vec<u8>,
		report: sgx_report_t,
		sign_type: sgx_quote_sign_type_t,
		spid: sgx_spid_t,
		quote_nonce: sgx_quote_nonce_t,
	) -> SgxResult<(sgx_report_t, Vec<u8>)>;

	fn get_update_info(
		&self,
		platform_info: sgx_platform_info_t,
		enclave_trusted: i32,
	) -> SgxResult<sgx_update_info_bit_t>;

	fn get_mrenclave_of_self(&self) -> SgxResult<sgx_measurement_t>;
}

/// trait for o-calls related to RPC
pub trait EnclaveRpcOCallApi: Clone + Debug + Send + Sync + Default {
	fn update_status_event<H: Encode>(
		&self,
		hash: H,
		status_update: TrustedOperationStatus,
	) -> SgxResult<()>;

	fn send_state<H: Encode>(&self, hash: H, value_opt: Option<Vec<u8>>) -> SgxResult<()>;
}

/// trait for o-calls related to on-chain interactions
pub trait EnclaveOnChainOCallApi: Clone + Debug + Send + Sync {
	fn send_block_and_confirmation(
		&self,
		confirmations: Vec<Vec<u8>>,
		signed_blocks: Vec<SignedSidechainBlock>,
	) -> SgxResult<()>;

	fn worker_request<V: Encode + Decode>(
		&self,
		req: Vec<WorkerRequest>,
	) -> SgxResult<Vec<WorkerResponse<V>>>;
}

/// Newtype for IPFS CID
pub struct IpfsCid(pub [u8; 46]);

/// trait for o-call related to IPFS
pub trait EnclaveIpfsOCallApi: Clone + Debug + Send + Sync {
	fn write_ipfs(&self, encoded_state: &[u8]) -> SgxResult<IpfsCid>;

	fn read_ipfs(&self, cid: &IpfsCid) -> SgxResult<()>;
}
