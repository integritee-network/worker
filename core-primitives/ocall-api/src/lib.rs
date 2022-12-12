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

#![cfg_attr(not(feature = "std"), no_std)]

pub extern crate alloc;

use alloc::vec::Vec;
use codec::{Decode, Encode};
use core::result::Result as StdResult;
use derive_more::{Display, From};
use itp_storage::Error as StorageError;
use itp_types::{
	storage::StorageEntryVerified, BlockHash, ShardIdentifier, TrustedOperationStatus,
	WorkerRequest, WorkerResponse,
};
use sgx_types::*;
use sp_core::H256;
use sp_runtime::{traits::Header, OpaqueExtrinsic};
use sp_std::prelude::*;

#[derive(Debug, Display, From)]
pub enum Error {
	Storage(StorageError),
	Codec(codec::Error),
	Sgx(sgx_types::sgx_status_t),
}

pub type Result<T> = StdResult<T, Error>;
/// Trait for the enclave to make o-calls related to remote attestation
pub trait EnclaveAttestationOCallApi: Clone + Send + Sync {
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

	fn get_dcap_quote(&self, report: sgx_report_t, quote_size: u32) -> SgxResult<Vec<u8>>;

	fn get_qve_report_on_quote(
		&self,
		quote: Vec<u8>,
		current_time: i64,
		quote_collateral: sgx_ql_qve_collateral_t,
		qve_report_info: sgx_ql_qe_report_info_t,
		supplemental_data_size: u32,
	) -> SgxResult<(u32, sgx_ql_qv_result_t, sgx_ql_qe_report_info_t, Vec<u8>)>;

	fn get_update_info(
		&self,
		platform_info: sgx_platform_info_t,
		enclave_trusted: i32,
	) -> SgxResult<sgx_update_info_bit_t>;

	fn get_mrenclave_of_self(&self) -> SgxResult<sgx_measurement_t>;
}

/// trait for o-calls related to RPC
pub trait EnclaveRpcOCallApi: Clone + Send + Sync + Default {
	fn update_status_event<H: Encode>(
		&self,
		hash: H,
		status_update: TrustedOperationStatus,
	) -> SgxResult<()>;

	fn send_state<H: Encode>(&self, hash: H, value_opt: Option<Vec<u8>>) -> SgxResult<()>;
}

/// trait for o-calls related to on-chain interactions
pub trait EnclaveOnChainOCallApi: Clone + Send + Sync {
	fn send_to_parentchain(&self, extrinsics: Vec<OpaqueExtrinsic>) -> SgxResult<()>;

	fn worker_request<V: Encode + Decode>(
		&self,
		req: Vec<WorkerRequest>,
	) -> SgxResult<Vec<WorkerResponse<V>>>;

	fn get_storage_verified<H: Header<Hash = H256>, V: Decode>(
		&self,
		storage_hash: Vec<u8>,
		header: &H,
	) -> Result<StorageEntryVerified<V>>;

	fn get_multiple_storages_verified<H: Header<Hash = H256>, V: Decode>(
		&self,
		storage_hashes: Vec<Vec<u8>>,
		header: &H,
	) -> Result<Vec<StorageEntryVerified<V>>>;
}

/// Trait for sending metric updates.
pub trait EnclaveMetricsOCallApi: Clone + Send + Sync {
	fn update_metric<Metric: Encode>(&self, metric: Metric) -> SgxResult<()>;
}

pub trait EnclaveSidechainOCallApi: Clone + Send + Sync {
	fn propose_sidechain_blocks<SignedSidechainBlock: Encode>(
		&self,
		signed_blocks: Vec<SignedSidechainBlock>,
	) -> SgxResult<()>;

	fn store_sidechain_blocks<SignedSidechainBlock: Encode>(
		&self,
		signed_blocks: Vec<SignedSidechainBlock>,
	) -> SgxResult<()>;

	fn fetch_sidechain_blocks_from_peer<SignedSidechainBlock: Decode>(
		&self,
		last_imported_block_hash: BlockHash,
		maybe_until_block_hash: Option<BlockHash>,
		shard_identifier: ShardIdentifier,
	) -> SgxResult<Vec<SignedSidechainBlock>>;
}

/// Newtype for IPFS CID
pub struct IpfsCid(pub [u8; 46]);

/// trait for o-call related to IPFS
pub trait EnclaveIpfsOCallApi: Clone + Send + Sync {
	fn write_ipfs(&self, encoded_state: &[u8]) -> SgxResult<IpfsCid>;

	fn read_ipfs(&self, cid: &IpfsCid) -> SgxResult<()>;
}
