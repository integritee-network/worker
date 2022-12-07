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
use log::*;
use sgx_types::*;

const OS_SYSTEM_PATH: &str = "/usr/lib/x86_64-linux-gnu/";
const C_STRING_ENDING: &str = "\0";
const PCE_ENCLAVE: &str = "libsgx_pce.signed.so.1";
const QE3_ENCLAVE: &str = "libsgx_qe3.signed.so.1";
const ID_ENCLAVE: &str = "libsgx_id_enclave.signed.so.1";
const LIBDCAP_QUOTEPROV: &str = "libdcap_quoteprov.so.1";
const QVE_ENCLAVE: &str = "libsgx_qve.signed.so.1";

/// Struct that unites all relevant data reported by the QVE
pub struct QveReport {
	pub supplemental_data: Vec<u8>,
	pub qve_report_info_return_value: sgx_ql_qe_report_info_t,
	pub quote_verification_result: sgx_ql_qv_result_t,
	pub collateral_expiration_status: u32,
}

/// general remote attestation methods
pub trait RemoteAttestation {
	fn generate_ias_ra_extrinsic(&self, w_url: &str, skip_ra: bool) -> EnclaveResult<Vec<u8>>;

	fn generate_dcap_ra_extrinsic(&self, w_url: &str, skip_ra: bool) -> EnclaveResult<Vec<u8>>;

	fn dump_ias_ra_cert_to_disk(&self) -> EnclaveResult<()>;

	fn dump_dcap_ra_cert_to_disk(&self) -> EnclaveResult<()>;

	fn set_ql_qe_enclave_paths(&self) -> EnclaveResult<()>;

	fn qe_get_target_info(&self) -> EnclaveResult<sgx_target_info_t>;

	fn qe_get_quote_size(&self) -> EnclaveResult<u32>;
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

	fn get_dcap_quote(&self, report: sgx_report_t, quote_size: u32) -> EnclaveResult<Vec<u8>>;

	fn get_qve_report_on_quote(
		&self,
		quote: Vec<u8>,
		current_time: i64,
		quote_collateral: &sgx_ql_qve_collateral_t,
		qve_report_info: sgx_ql_qe_report_info_t,
		supplemental_data_size: u32,
	) -> EnclaveResult<QveReport>;

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
	fn generate_ias_ra_extrinsic(&self, w_url: &str, skip_ra: bool) -> EnclaveResult<Vec<u8>> {
		let mut retval = sgx_status_t::SGX_SUCCESS;

		let mut unchecked_extrinsic: Vec<u8> = vec![0u8; EXTRINSIC_MAX_SIZE];

		let url = w_url.encode();

		let result = unsafe {
			ffi::generate_ias_ra_extrinsic(
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

	fn generate_dcap_ra_extrinsic(&self, w_url: &str, skip_ra: bool) -> EnclaveResult<Vec<u8>> {
		let mut retval = sgx_status_t::SGX_SUCCESS;

		self.set_ql_qe_enclave_paths()?;
		let quoting_enclave_target_info = self.qe_get_target_info()?;
		let quote_size = self.qe_get_quote_size()?;
		info!("Retrieved quote size of {:?}", quote_size);

		let mut unchecked_extrinsic: Vec<u8> = vec![0u8; EXTRINSIC_MAX_SIZE];

		let url = w_url.encode();

		let result = unsafe {
			ffi::generate_dcap_ra_extrinsic(
				self.eid,
				&mut retval,
				url.as_ptr(),
				url.len() as u32,
				unchecked_extrinsic.as_mut_ptr(),
				unchecked_extrinsic.len() as u32,
				skip_ra.into(),
				&quoting_enclave_target_info,
				quote_size,
			)
		};

		ensure!(result == sgx_status_t::SGX_SUCCESS, Error::Sgx(result));
		ensure!(retval == sgx_status_t::SGX_SUCCESS, Error::Sgx(retval));

		Ok(unchecked_extrinsic)
	}

	fn dump_ias_ra_cert_to_disk(&self) -> EnclaveResult<()> {
		let mut retval = sgx_status_t::SGX_SUCCESS;

		let result = unsafe { ffi::dump_ias_ra_cert_to_disk(self.eid, &mut retval) };

		ensure!(result == sgx_status_t::SGX_SUCCESS, Error::Sgx(result));
		ensure!(retval == sgx_status_t::SGX_SUCCESS, Error::Sgx(retval));

		Ok(())
	}

	fn dump_dcap_ra_cert_to_disk(&self) -> EnclaveResult<()> {
		let mut retval = sgx_status_t::SGX_SUCCESS;

		self.set_ql_qe_enclave_paths()?;
		let quoting_enclave_target_info = self.qe_get_target_info()?;
		let quote_size = self.qe_get_quote_size()?;

		let result = unsafe {
			ffi::dump_dcap_ra_cert_to_disk(
				self.eid,
				&mut retval,
				&quoting_enclave_target_info,
				quote_size,
			)
		};

		ensure!(result == sgx_status_t::SGX_SUCCESS, Error::Sgx(result));
		ensure!(retval == sgx_status_t::SGX_SUCCESS, Error::Sgx(retval));

		Ok(())
	}

	fn set_ql_qe_enclave_paths(&self) -> EnclaveResult<()> {
		set_ql_path(sgx_ql_path_type_t::SGX_QL_PCE_PATH, PCE_ENCLAVE)?;
		set_ql_path(sgx_ql_path_type_t::SGX_QL_QE3_PATH, QE3_ENCLAVE)?;
		set_ql_path(sgx_ql_path_type_t::SGX_QL_IDE_PATH, ID_ENCLAVE)?;
		if set_ql_path(sgx_ql_path_type_t::SGX_QL_QPL_PATH, LIBDCAP_QUOTEPROV).is_err() {
			// Ignore the error, because user may want to get cert type=3 quote.
			warn!("Cannot set QPL directory, you may get ECDSA quote with `Encrypted PPID` cert type.\n");
		};
		set_qv_path(sgx_qv_path_type_t::SGX_QV_QVE_PATH, QVE_ENCLAVE)?;

		Ok(())
	}

	fn qe_get_target_info(&self) -> EnclaveResult<sgx_target_info_t> {
		let mut quoting_enclave_target_info: sgx_target_info_t = sgx_target_info_t::default();
		let qe3_ret = unsafe { sgx_qe_get_target_info(&mut quoting_enclave_target_info as *mut _) };
		ensure!(qe3_ret == sgx_quote3_error_t::SGX_QL_SUCCESS, Error::SgxQuote(qe3_ret));

		Ok(quoting_enclave_target_info)
	}

	fn qe_get_quote_size(&self) -> EnclaveResult<u32> {
		let mut quote_size: u32 = 0;
		let qe3_ret = unsafe { sgx_qe_get_quote_size(&mut quote_size as *mut _) };
		ensure!(qe3_ret == sgx_quote3_error_t::SGX_QL_SUCCESS, Error::SgxQuote(qe3_ret));

		Ok(quote_size)
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

	fn get_dcap_quote(&self, report: sgx_report_t, quote_size: u32) -> EnclaveResult<Vec<u8>> {
		let mut quote_vec: Vec<u8> = vec![0; quote_size as usize];

		let qe3_ret = unsafe { sgx_qe_get_quote(&report, quote_size, quote_vec.as_mut_ptr() as _) };

		ensure!(qe3_ret == sgx_quote3_error_t::SGX_QL_SUCCESS, Error::SgxQuote(qe3_ret));

		Ok(quote_vec)
	}

	fn get_qve_report_on_quote(
		&self,
		quote: Vec<u8>,
		current_time: i64,
		quote_collateral: &sgx_ql_qve_collateral_t,
		qve_report_info: sgx_ql_qe_report_info_t,
		supplemental_data_size: u32,
	) -> EnclaveResult<QveReport> {
		let mut collateral_expiration_status = 1u32;
		let mut quote_verification_result = sgx_ql_qv_result_t::SGX_QL_QV_RESULT_OK;
		let mut supplemental_data: Vec<u8> = vec![0; supplemental_data_size as usize];
		let mut qve_report_info_return_value: sgx_ql_qe_report_info_t = qve_report_info;

		// Set QvE (Quote verification Enclave) loading policy.
		let dcap_ret =
			unsafe { sgx_qv_set_enclave_load_policy(sgx_ql_request_policy_t::SGX_QL_EPHEMERAL) };

		if dcap_ret != sgx_quote3_error_t::SGX_QL_SUCCESS {
			error!("sgx_qv_set_enclave_load_policy failed: {:#04x}", dcap_ret as u32);
			return Err(Error::SgxQuote(dcap_ret))
		}

		// Retrieve supplemental data size from QvE.
		let mut qve_supplemental_data_size = 0u32;
		let dcap_ret =
			unsafe { sgx_qv_get_quote_supplemental_data_size(&mut qve_supplemental_data_size) };

		if dcap_ret != sgx_quote3_error_t::SGX_QL_SUCCESS {
			error!("sgx_qv_get_quote_supplemental_data_size failed: {:?}", dcap_ret);
			return Err(Error::SgxQuote(dcap_ret))
		}
		if qve_supplemental_data_size != supplemental_data_size {
			warn!("Quote supplemental data size is different between DCAP QVL and QvE, please make sure you installed DCAP QVL and QvE from same release.");
			return Err(Error::Sgx(sgx_status_t::SGX_ERROR_INVALID_PARAMETER))
		}

		// Check if a collateral has been given, or if it's a simple zero assignment.
		// If it's zero, let the pointer point to null. The collateral will then be retrieved
		// directly by the QvE in `sgx_qv_verify_quote`.
		let p_quote_collateral: *const sgx_ql_qve_collateral_t = if quote_collateral.version == 0 {
			std::ptr::null()
		} else {
			quote_collateral as *const sgx_ql_qve_collateral_t
		};

		// Call the QvE for quote verification
		// here you can choose 'trusted' or 'untrusted' quote verification by specifying parameter '&qve_report_info'
		// if '&qve_report_info' is NOT NULL, this API will call Intel QvE to verify quote
		// if '&qve_report_info' is NULL, this API will call 'untrusted quote verify lib' to verify quote,
		// this mode doesn't rely on SGX capable system, but the results can not be cryptographically authenticated
		let dcap_ret = unsafe {
			sgx_qv_verify_quote(
				quote.as_ptr(),
				quote.len() as u32,
				p_quote_collateral,
				current_time,
				&mut collateral_expiration_status as *mut u32,
				&mut quote_verification_result as *mut sgx_ql_qv_result_t,
				&mut qve_report_info_return_value as *mut sgx_ql_qe_report_info_t,
				supplemental_data_size,
				supplemental_data.as_mut_ptr(),
			)
		};

		if sgx_quote3_error_t::SGX_QL_SUCCESS != dcap_ret {
			error!("sgx_qv_verify_quote failed: {:?}", dcap_ret);
			error!("quote_verification_result: {:?}", quote_verification_result);
			return Err(Error::SgxQuote(dcap_ret))
		}

		// Check and print verification result.
		match quote_verification_result {
			sgx_ql_qv_result_t::SGX_QL_QV_RESULT_OK => {
				// Check verification collateral expiration status.
				// This value should be considered in your own attestation/verification policy.
				if 0u32 == collateral_expiration_status {
					info!("QvE verification completed successfully.");
				} else {
					warn!("QvE verification completed, but collateral is out of date based on 'expiration_check_date' you provided.");
				}
			},
			sgx_ql_qv_result_t::SGX_QL_QV_RESULT_CONFIG_NEEDED
			| sgx_ql_qv_result_t::SGX_QL_QV_RESULT_OUT_OF_DATE
			| sgx_ql_qv_result_t::SGX_QL_QV_RESULT_OUT_OF_DATE_CONFIG_NEEDED
			| sgx_ql_qv_result_t::SGX_QL_QV_RESULT_SW_HARDENING_NEEDED
			| sgx_ql_qv_result_t::SGX_QL_QV_RESULT_CONFIG_AND_SW_HARDENING_NEEDED => {
				warn!(
					"QvE verification completed with Non-terminal result: {:?}",
					quote_verification_result
				);
			},
			_ => {
				error!(
					"QvE verification completed with Terminal result: {:?}",
					quote_verification_result
				);
			},
		}

		// Check supplemental data.
		if supplemental_data_size > 0 {
			// For now we simply print it, no checks done.
			let p_supplemental_data: *const sgx_ql_qv_supplemental_t =
				supplemental_data.as_ptr() as *const sgx_ql_qv_supplemental_t;
			let qv_supplemental_data: sgx_ql_qv_supplemental_t = unsafe { *p_supplemental_data };
			info!("QvE verification: Supplemental data version: {}", qv_supplemental_data.version);
		}

		Ok(QveReport {
			collateral_expiration_status,
			quote_verification_result,
			qve_report_info_return_value,
			supplemental_data,
		})
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

fn create_system_path(file_name: &str) -> String {
	format!("{}{}{}", OS_SYSTEM_PATH, file_name, C_STRING_ENDING)
}

fn set_ql_path(path_type: sgx_ql_path_type_t, path: &str) -> EnclaveResult<()> {
	let ret_val = unsafe { sgx_ql_set_path(path_type, create_system_path(path).as_ptr() as _) };
	if ret_val != sgx_quote3_error_t::SGX_QL_SUCCESS {
		error!("Could not set {:?}", path_type);
		return Err(Error::SgxQuote(ret_val))
	}
	Ok(())
}

fn set_qv_path(path_type: sgx_qv_path_type_t, path: &str) -> EnclaveResult<()> {
	let ret_val = unsafe { sgx_qv_set_path(path_type, create_system_path(path).as_ptr() as _) };
	if ret_val != sgx_quote3_error_t::SGX_QL_SUCCESS {
		error!("Could not set {:?}", path_type);
		return Err(Error::SgxQuote(ret_val))
	}
	Ok(())
}
