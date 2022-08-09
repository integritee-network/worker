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

use sgx_types::*;

extern "C" {
	pub fn ocall_sgx_init_quote(
		ret_val: *mut sgx_status_t,
		ret_ti: *mut sgx_target_info_t,
		ret_gid: *mut sgx_epid_group_id_t,
	) -> sgx_status_t;

	pub fn ocall_get_ias_socket(ret_val: *mut sgx_status_t, ret_fd: *mut i32) -> sgx_status_t;

	pub fn ocall_get_quote(
		ret_val: *mut sgx_status_t,
		p_sigrl: *const u8,
		sigrl_len: u32,
		p_report: *const sgx_report_t,
		quote_type: sgx_quote_sign_type_t,
		p_spid: *const sgx_spid_t,
		p_nonce: *const sgx_quote_nonce_t,
		p_qe_report: *mut sgx_report_t,
		p_quote: *mut u8,
		maxlen: u32,
		p_quote_len: *mut u32,
	) -> sgx_status_t;

	pub fn ocall_get_dcap_quote(
		ret_val: *mut sgx_status_t,
		p_report: *const sgx_report_t,
		p_quote: *mut u8,
		quote_size: u32,
	) -> sgx_status_t;

	pub fn ocall_get_qve_report_on_quote(
		ret_val: *mut sgx_status_t,
		p_quote: *const u8,
		quote_len: u32,
		current_time: i64,
		p_quote_collateral: *const sgx_ql_qve_collateral_t,
		p_collateral_expiration_status: *mut u32,
		p_quote_verification_result: *mut sgx_ql_qv_result_t,
		p_qve_report_info: *mut sgx_ql_qe_report_info_t,
		p_supplemental_data: *mut u8,
		supplemental_data_size: u32,
	) -> sgx_status_t;

	pub fn ocall_get_update_info(
		ret_val: *mut sgx_status_t,
		platform_blob: *const sgx_platform_info_t,
		enclave_trusted: i32,
		update_info: *mut sgx_update_info_bit_t,
	) -> sgx_status_t;

	pub fn ocall_worker_request(
		ret_val: *mut sgx_status_t,
		request: *const u8,
		req_size: u32,
		response: *mut u8,
		resp_size: u32,
	) -> sgx_status_t;

	pub fn ocall_update_metric(
		ret_val: *mut sgx_status_t,
		metric_ptr: *const u8,
		metric_size: u32,
	) -> sgx_status_t;

	pub fn ocall_propose_sidechain_blocks(
		ret_val: *mut sgx_status_t,
		signed_blocks: *const u8,
		signed_blocks_size: u32,
	) -> sgx_status_t;

	pub fn ocall_store_sidechain_blocks(
		ret_val: *mut sgx_status_t,
		signed_blocks: *const u8,
		signed_blocks_size: u32,
	) -> sgx_status_t;

	pub fn ocall_fetch_sidechain_blocks_from_peer(
		ret_val: *mut sgx_status_t,
		last_imported_block_hash: *const u8,
		last_imported_block_hash_size: u32,
		maybe_until_block_hash: *const u8,
		maybe_until_block_hash_encoded_size: u32,
		shard_identifier: *const u8,
		shard_identifier_size: u32,
		sidechain_blocks: *mut u8,
		sidechain_blocks_size: u32,
	) -> sgx_status_t;

	pub fn ocall_send_to_parentchain(
		ret_val: *mut sgx_status_t,
		extrinsics: *const u8,
		extrinsics_size: u32,
	) -> sgx_status_t;

	pub fn ocall_read_ipfs(
		ret_val: *mut sgx_status_t,
		cid: *const u8,
		cid_size: u32,
	) -> sgx_status_t;

	pub fn ocall_write_ipfs(
		ret_val: *mut sgx_status_t,
		enc_state: *const u8,
		enc_state_size: u32,
		cid: *mut u8,
		cid_size: u32,
	) -> sgx_status_t;
}
