/*
	Copyright 2022 Integritee AG and Supercomputing Systems AG
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

//! Perform DCAP remote attestation via PCCS server,
//! including the verification of the retrieved quote.

use crate::{cert, Result as EnclaveResult};
use core::{convert::TryInto, default::Default};
use itp_ocall_api::EnclaveAttestationOCallApi;
use itp_sgx_crypto::Ed25519Seal;
use itp_sgx_io::StaticSealedIO;
use itp_time_utils::now_as_secs;
use log::*;
use sgx_tcrypto::*;
use sgx_tse::rsgx_create_report;
use sgx_types::*;
use sp_core::Pair;
use std::{prelude::v1::*, vec::Vec};

pub fn ecdsa_quote_verification<A: EnclaveAttestationOCallApi>(
	quote: Vec<u8>,
	ocall_api: &A,
) -> SgxResult<Vec<u8>> {
	let mut app_enclave_target_info: sgx_target_info_t = unsafe { std::mem::zeroed() };
	let quote_collateral: sgx_ql_qve_collateral_t = unsafe { std::mem::zeroed() };
	let mut qve_report_info: sgx_ql_qe_report_info_t = unsafe { std::mem::zeroed() };
	let supplemental_data_size = std::mem::size_of::<sgx_ql_qv_supplemental_t>() as u32;

	// Get target info of SampleISVEnclave. QvE will target the generated report to this enclave.
	let ret_val =
		unsafe { sgx_self_target(&mut app_enclave_target_info as *mut sgx_target_info_t) };
	if ret_val != sgx_status_t::SGX_SUCCESS {
		error!("sgx_self_target returned: {:?}", ret_val);
		return Err(sgx_status_t::SGX_ERROR_UNEXPECTED)
	}

	// Set current time, which is needed to check against the expiration date of the certificate.
	let current_time: i64 = now_as_secs().try_into().unwrap_or_else(|e| {
		panic!("Could not convert SystemTime from u64 into i64: {:?}", e);
	});

	// Set random nonce.
	let mut rand_nonce = vec![0u8; 16];
	let ret_val = unsafe { sgx_read_rand(rand_nonce.as_mut_ptr(), rand_nonce.len()) };
	if ret_val != sgx_status_t::SGX_SUCCESS {
		error!("sgx_read_rand returned: {:?}", ret_val);
		return Err(sgx_status_t::SGX_ERROR_UNEXPECTED)
	}
	debug!("Retrieved random nonce {:?}", rand_nonce);
	qve_report_info.nonce.rand.copy_from_slice(rand_nonce.as_slice());
	qve_report_info.app_enclave_target_info = app_enclave_target_info;

	// Ocall to call Quote verification Enclave (QvE), which verifies the generated quote.
	let (
		collateral_expiration_status,
		quote_verification_result,
		qve_report_info_return_value,
		supplemental_data,
	) = ocall_api.get_qve_report_on_quote(
		quote.clone(),
		current_time,
		quote_collateral,
		qve_report_info,
		supplemental_data_size,
	)?;

	// Check nonce of qve report to protect against replay attacks, as the qve report
	// is coming from the untrusted side.
	if qve_report_info_return_value.nonce.rand != qve_report_info.nonce.rand {
		error!(
			"Nonce of input value and return value are not matching. Input: {:?}, Output: {:?}",
			qve_report_info.nonce.rand, qve_report_info_return_value.nonce.rand
		);
		return Err(sgx_status_t::SGX_ERROR_UNEXPECTED)
	}

	// Set the threshold of QvE ISV SVN. The ISV SVN of QvE used to verify quote must be greater or equal to this threshold
	// e.g. You can check latest QvE ISVSVN from QvE configuration file on Github
	// https://github.com/intel/SGXDataCenterAttestationPrimitives/blob/master/QuoteVerification/QvE/Enclave/linux/config.xml#L4
	// or you can get latest QvE ISVSVN in QvE Identity JSON file from
	// https://api.trustedservices.intel.com/sgx/certification/v3/qve/identity
	// Make sure you are using trusted & latest QvE ISV SVN as threshold
	// Warning: The function may return erroneous result if QvE ISV SVN has been modified maliciously.
	let qve_isvsvn_threshold: sgx_isv_svn_t = 6;

	// Verify the qve report to validate that it is coming from a legit quoting verification enclave
	// and has not been tampered with.
	let ret_val = unsafe {
		sgx_tvl_verify_qve_report_and_identity(
			quote.as_ptr(),
			quote.len() as u32,
			&qve_report_info_return_value as *const sgx_ql_qe_report_info_t,
			current_time,
			collateral_expiration_status,
			quote_verification_result,
			supplemental_data.as_ptr(),
			supplemental_data_size,
			qve_isvsvn_threshold,
		)
	};

	if ret_val != sgx_quote3_error_t::SGX_QL_SUCCESS {
		error!("sgx_tvl_verify_qve_report_and_identity returned: {:?}", ret_val);
		return Err(sgx_status_t::SGX_ERROR_UNEXPECTED)
	}

	// TODO. What to send to our teerex pallet?
	Ok(vec![])
}

pub fn retrieve_qe_dcap_quote<A: EnclaveAttestationOCallApi>(
	pub_k: &[u8; 32],
	ocall_api: &A,
	quoting_enclave_target_info: &sgx_target_info_t,
	quote_size: u32,
) -> SgxResult<Vec<u8>> {
	// Generate app enclave report and include the enclave public key.
	// The quote will be generated on top of this report and validate that the
	// report as well as the public key inside it are coming from a legit
	// intel sgx enclave.
	let mut report_data: sgx_report_data_t = sgx_report_data_t::default();
	report_data.d[..32].clone_from_slice(&pub_k[..]);

	let app_report = match rsgx_create_report(quoting_enclave_target_info, &report_data) {
		Ok(report) => {
			debug!(
				"rsgx_create_report creation successful. mr_signer: {:?}",
				report.body.mr_signer.m
			);
			report
		},
		Err(e) => {
			error!("rsgx_create_report creation failed. {:?}", e);
			return Err(e)
		},
	};

	// Retrieve quote from pccs for our app enclave.
	debug!("Entering ocall_api.get_dcap_quote with quote size: {:?} ", quote_size);
	let quote_vec = ocall_api.get_dcap_quote(app_report, quote_size)?;

	// Check mrenclave of quote, to ensure the quote has not been tampered with
	// while being on the untrusted side.
	// This step is probably obsolete, as the QvE will check the quote as well on behalf
	// of the target enclave.
	let p_quote3: *const sgx_quote3_t = quote_vec.as_ptr() as *const sgx_quote3_t;
	let quote3: sgx_quote3_t = unsafe { *p_quote3 };
	if quote3.report_body.mr_enclave.m != app_report.body.mr_enclave.m {
		error!("mr_enclave of quote and app_report are not matching");
		error!("mr_enclave of quote: {:?}", quote3.report_body.mr_enclave.m);
		error!("mr_enclave of quote: {:?}", app_report.body.mr_enclave.m);
		return Err(sgx_status_t::SGX_ERROR_UNEXPECTED)
	}

	Ok(quote_vec)
}

pub fn generate_dcap_ecc_cert<A: EnclaveAttestationOCallApi>(
	quoting_enclave_target_info: &sgx_target_info_t,
	quote_size: u32,
	ocall_api: &A,
	skip_ra: bool,
) -> EnclaveResult<(Vec<u8>, Vec<u8>)> {
	let chain_signer = Ed25519Seal::unseal_from_static_file()?;
	info!("[Enclave Attestation] Ed25519 signer pub key: {:?}", chain_signer.public().0);

	let ecc_handle = SgxEccHandle::new();
	let _result = ecc_handle.open();
	let (prv_k, pub_k) = ecc_handle.create_key_pair()?;
	info!("Enclave Attestation] Generated ephemeral ECDSA keypair:");

	let qe_quote = if !skip_ra {
		let qe_quote = match retrieve_qe_dcap_quote(
			&chain_signer.public().0,
			ocall_api,
			quoting_enclave_target_info,
			quote_size,
		) {
			Ok(quote) => quote,
			Err(e) => {
				error!("[Enclave] Error in create_dcap_attestation_report: {:?}", e);
				return Err(e.into())
			},
		};
		qe_quote
	} else {
		Default::default()
	};

	// Verify the quote via qve enclave
	let payload = ecdsa_quote_verification(qe_quote, ocall_api)?;

	// generate an ECC certificate
	debug!("[Enclave] Generate ECC Certificate");
	let (key_der, cert_der) = match cert::gen_ecc_cert(&payload, &prv_k, &pub_k, &ecc_handle) {
		Ok(r) => r,
		Err(e) => {
			error!("[Enclave] gen_ecc_cert failed: {:?}", e);
			return Err(e.into())
		},
	};

	let _ = ecc_handle.close();

	Ok((key_der, cert_der))
}
