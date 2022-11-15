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

use crate::{error::Error, utils, Enclave, EnclaveResult};
use codec::Encode;
use frame_support::ensure;
use itp_enclave_api_ffi as ffi;
use itp_settings::worker::EXTRINSIC_MAX_SIZE;
use itp_types::ShardIdentifier;
use sgx_types::*;

/// general remote attestation methods
pub trait RemoteAttestation {
	fn perform_ra(&self, w_url: &str, skip_ra: bool) -> EnclaveResult<Vec<u8>>;

	fn dump_ra_to_disk(&self) -> EnclaveResult<()>;
}

/// call-backs that are made from inside the enclave (using o-call), to e-calls again inside the enclave
pub trait RemoteAttestationCallBacks {
	fn init_quote(&self) -> EnclaveResult<(sgx_target_info_t, sgx_epid_group_id_t)>;

	fn calc_quote_size(&self, revocation_list: Vec<u8>) -> EnclaveResult<u32>;

	fn get_quote(
		&self,
		revocation_list: Vec<u8>,
		report: sgx_report_t,
		quote_type: sgx_quote_sign_type_t,
		spid: sgx_spid_t,
		quote_nonce: sgx_quote_nonce_t,
		quote_length: u32,
	) -> EnclaveResult<(sgx_report_t, Vec<u8>)>;

	fn get_update_info(
		&self,
		platform_blob: sgx_platform_info_t,
		enclave_trusted: i32,
	) -> EnclaveResult<sgx_update_info_bit_t>;
}

/// TLS remote attestations methods
pub trait TlsRemoteAttestation {
	fn run_state_provisioning_server(
		&self,
		socket_fd: c_int,
		sign_type: sgx_quote_sign_type_t,
		skip_ra: bool,
	) -> EnclaveResult<()>;

	fn request_state_provisioning(
		&self,
		socket_fd: c_int,
		sign_type: sgx_quote_sign_type_t,
		shard: &ShardIdentifier,
		skip_ra: bool,
	) -> EnclaveResult<()>;
}

impl RemoteAttestation for Enclave {
	fn perform_ra(&self, w_url: &str, skip_ra: bool) -> EnclaveResult<Vec<u8>> {
		let mut retval = sgx_status_t::SGX_SUCCESS;

		let unchecked_extrinsic_size = EXTRINSIC_MAX_SIZE;
		let mut unchecked_extrinsic: Vec<u8> = vec![0u8; unchecked_extrinsic_size];

		let url = w_url.encode();

		let result = unsafe {
			ffi::perform_ra(
				self.eid,
				&mut retval,
				url.as_ptr(),
				url.len() as u32,
				unchecked_extrinsic.as_mut_ptr(),
				unchecked_extrinsic.len() as u32,
				skip_ra.into(),
			)
		};

		ensure!(result == sgx_status_t::SGX_SUCCESS, Error::Sgx(result));
		ensure!(retval == sgx_status_t::SGX_SUCCESS, Error::Sgx(retval));

		Ok(unchecked_extrinsic)
	}

	fn dump_ra_to_disk(&self) -> EnclaveResult<()> {
		let mut retval = sgx_status_t::SGX_SUCCESS;

		let result = unsafe { ffi::dump_ra_to_disk(self.eid, &mut retval) };

		ensure!(result == sgx_status_t::SGX_SUCCESS, Error::Sgx(result));
		ensure!(retval == sgx_status_t::SGX_SUCCESS, Error::Sgx(retval));

		Ok(())
	}
}

impl RemoteAttestationCallBacks for Enclave {
	fn init_quote(&self) -> EnclaveResult<(sgx_target_info_t, sgx_epid_group_id_t)> {
		let mut ti: sgx_target_info_t = sgx_target_info_t::default();
		let mut eg: sgx_epid_group_id_t = sgx_epid_group_id_t::default();

		let result = unsafe {
			sgx_init_quote(&mut ti as *mut sgx_target_info_t, &mut eg as *mut sgx_epid_group_id_t)
		};

		ensure!(result == sgx_status_t::SGX_SUCCESS, Error::Sgx(result));

		Ok((ti, eg))
	}

	fn calc_quote_size(&self, revocation_list: Vec<u8>) -> EnclaveResult<u32> {
		let mut real_quote_len: u32 = 0;

		let (p_sig_rl, sig_rl_size) = utils::vec_to_c_pointer_with_len(revocation_list);

		let result =
			unsafe { sgx_calc_quote_size(p_sig_rl, sig_rl_size, &mut real_quote_len as *mut u32) };

		ensure!(result == sgx_status_t::SGX_SUCCESS, Error::Sgx(result));

		Ok(real_quote_len)
	}

	fn get_quote(
		&self,
		revocation_list: Vec<u8>,
		report: sgx_report_t,
		quote_type: sgx_quote_sign_type_t,
		spid: sgx_spid_t,
		quote_nonce: sgx_quote_nonce_t,
		quote_length: u32,
	) -> EnclaveResult<(sgx_report_t, Vec<u8>)> {
		let (p_sig_rl, sig_rl_size) = utils::vec_to_c_pointer_with_len(revocation_list);
		let p_report = &report as *const sgx_report_t;
		let p_spid = &spid as *const sgx_spid_t;
		let p_nonce = &quote_nonce as *const sgx_quote_nonce_t;

		let mut qe_report = sgx_report_t::default();
		let p_qe_report = &mut qe_report as *mut sgx_report_t;

		let mut return_quote_buf = vec![0u8; quote_length as usize];
		let p_quote = return_quote_buf.as_mut_ptr();

		let ret = unsafe {
			sgx_get_quote(
				p_report,
				quote_type,
				p_spid,
				p_nonce,
				p_sig_rl,
				sig_rl_size,
				p_qe_report,
				p_quote as *mut sgx_quote_t,
				quote_length,
			)
		};

		ensure!(ret == sgx_status_t::SGX_SUCCESS, Error::Sgx(ret));

		Ok((qe_report, return_quote_buf))
	}

	fn get_update_info(
		&self,
		platform_blob: sgx_platform_info_t,
		enclave_trusted: i32,
	) -> EnclaveResult<sgx_update_info_bit_t> {
		let mut update_info: sgx_update_info_bit_t = sgx_update_info_bit_t::default();

		let result = unsafe {
			sgx_report_attestation_status(
				&platform_blob as *const sgx_platform_info_t,
				enclave_trusted,
				&mut update_info as *mut sgx_update_info_bit_t,
			)
		};

		ensure!(result == sgx_status_t::SGX_SUCCESS, Error::Sgx(result));

		Ok(update_info)
	}
}

impl TlsRemoteAttestation for Enclave {
	fn run_state_provisioning_server(
		&self,
		socket_fd: c_int,
		sign_type: sgx_quote_sign_type_t,
		skip_ra: bool,
	) -> EnclaveResult<()> {
		let mut retval = sgx_status_t::SGX_SUCCESS;

		let result = unsafe {
			ffi::run_state_provisioning_server(
				self.eid,
				&mut retval,
				socket_fd,
				sign_type,
				skip_ra.into(),
			)
		};

		ensure!(result == sgx_status_t::SGX_SUCCESS, Error::Sgx(result));
		ensure!(retval == sgx_status_t::SGX_SUCCESS, Error::Sgx(retval));

		Ok(())
	}

	fn request_state_provisioning(
		&self,
		socket_fd: c_int,
		sign_type: sgx_quote_sign_type_t,
		shard: &ShardIdentifier,
		skip_ra: bool,
	) -> EnclaveResult<()> {
		let mut retval = sgx_status_t::SGX_SUCCESS;

		let encoded_shard = shard.encode();

		let result = unsafe {
			ffi::request_state_provisioning(
				self.eid,
				&mut retval,
				socket_fd,
				sign_type,
				encoded_shard.as_ptr(),
				encoded_shard.len() as u32,
				skip_ra.into(),
			)
		};

		ensure!(result == sgx_status_t::SGX_SUCCESS, Error::Sgx(result));
		ensure!(retval == sgx_status_t::SGX_SUCCESS, Error::Sgx(retval));

		Ok(())
	}
}
