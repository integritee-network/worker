// Copyright (C) 2017-2019 Baidu, Inc. All Rights Reserved.
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions
// are met:
//
//  * Redistributions of source code must retain the above copyright
//    notice, this list of conditions and the following disclaimer.
//  * Redistributions in binary form must reproduce the above copyright
//    notice, this list of conditions and the following disclaimer in
//    the documentation and/or other materials provided with the
//    distribution.
//  * Neither the name of Baidu, Inc., nor the names of its
//    contributors may be used to endorse or promote products derived
//    from this software without specific prior written permission.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
// "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
// LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
// A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
// OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
// SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
// LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
// DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
// THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
// (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
// OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

use crate::{
	cert, io, ocall::OcallApi, utils::hash_from_slice, Error as EnclaveError,
	ParentchainExtrinsicParams, ParentchainExtrinsicParamsBuilder, Result as EnclaveResult,
	GLOBAL_NODE_METADATA_REPOSITORY_COMPONENT,
};
use codec::Encode;
use core::{convert::TryInto, default::Default};
use itertools::Itertools;
use itp_component_container::ComponentGetter;
use itp_node_api::metadata::{pallet_teerex::TeerexCallIndexes, provider::AccessNodeMetadata};
use itp_ocall_api::EnclaveAttestationOCallApi;
use itp_settings::files::RA_DUMP_CERT_DER_FILE;
use itp_sgx_crypto::Ed25519Seal;
use itp_sgx_io::StaticSealedIO;
use itp_time_utils::now_as_secs;
use itp_utils::write_slice_and_whitespace_pad;
use log::*;
use sgx_tcrypto::*;
use sgx_tse::rsgx_create_report;
use sgx_types::*;
use sp_core::{blake2_256, Pair};
use std::{prelude::v1::*, slice, str, vec::Vec};
use substrate_api_client::{compose_extrinsic_offline, ExtrinsicParams};

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

	// Verify qve report.

	// Check nonce to protect agaisnt replay attacks
	if qve_report_info_return_value.nonce.rand != qve_report_info.nonce.rand {
		error!(
			"Nonce of input value and return value are not matching. Input: {:?}, Output: {:?}",
			qve_report_info.nonce.rand, qve_report_info_return_value.nonce.rand
		);
		return Err(sgx_status_t::SGX_ERROR_UNEXPECTED)
	}

	// Threshold of QvE ISV SVN. The ISV SVN of QvE used to verify quote must be greater or equal to this threshold
	// e.g. You can check latest QvE ISVSVN from QvE configuration file on Github
	// https://github.com/intel/SGXDataCenterAttestationPrimitives/blob/master/QuoteVerification/QvE/Enclave/linux/config.xml#L4
	// or you can get latest QvE ISVSVN in QvE Identity JSON file from
	// https://api.trustedservices.intel.com/sgx/certification/v3/qve/identity
	// Make sure you are using trusted & latest QvE ISV SVN as threshold
	// Warning: The function may return erroneous result if QvE ISV SVN has been modified maliciously.
	let qve_isvsvn_threshold: sgx_isv_svn_t = 6;

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

#[allow(const_err)]
pub fn retrieve_qe_dcap_quote<A: EnclaveAttestationOCallApi>(
	pub_k: &[u8; 32],
	ocall_api: &A,
	quoting_enclave_target_info: &sgx_target_info_t,
	quote_size: u32,
) -> SgxResult<Vec<u8>> {
	// Generate app enclave report and include the enclave public key.
	let mut report_data: sgx_report_data_t = sgx_report_data_t::default();
	report_data.d[..32].clone_from_slice(&pub_k[..]);

	let app_report = match rsgx_create_report(quoting_enclave_target_info, &report_data) {
		Ok(r) => {
			debug!(
				"    [Enclave] Report creation successful. mr_signer.m = {:x?}",
				r.body.mr_signer.m
			);
			r
		},
		Err(e) => {
			error!("    [Enclave] Report creation failed. {:?}", e);
			return Err(e)
		},
	};

	// Retrieve quote from pccs for our app enclave.
	debug!("Entering ocall_api.get_dcap_quote with quote size: {:?} ", quote_size);
	let quote_vec = ocall_api.get_dcap_quote(app_report, quote_size)?;

	// Check mrenclave of quote
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
	info!("[Enclave Attestation] Ed25519 pub raw : {:?}", chain_signer.public().0);

	info!("    [Enclave] Generate keypair");
	let ecc_handle = SgxEccHandle::new();
	let _result = ecc_handle.open();
	let (prv_k, pub_k) = ecc_handle.create_key_pair()?;
	info!("    [Enclave] Generate ephemeral ECDSA keypair successful");
	debug!("     pubkey X is {:02x}", pub_k.gx.iter().format(""));
	debug!("     pubkey Y is {:02x}", pub_k.gy.iter().format(""));

	let qe_quote = if !skip_ra {
		info!("    [Enclave] Create attestation report");
		let qe_quote = match retrieve_qe_dcap_quote(
			&chain_signer.public().0,
			ocall_api,
			quoting_enclave_target_info,
			quote_size,
		) {
			Ok(quote) => quote,
			Err(e) => {
				error!("    [Enclave] Error in create_dcap_attestation_report: {:?}", e);
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
	info!("    [Enclave] Generate ECC Certificate");
	let (key_der, cert_der) = match cert::gen_ecc_cert(&payload, &prv_k, &pub_k, &ecc_handle) {
		Ok(r) => r,
		Err(e) => {
			error!("    [Enclave] gen_ecc_cert failed: {:?}", e);
			return Err(e.into())
		},
	};

	let _ = ecc_handle.close();
	info!("    [Enclave] Generate ECC Certificate successful");
	Ok((key_der, cert_der))
}

#[no_mangle]
pub unsafe extern "C" fn perform_dcap_ra(
	genesis_hash: *const u8,
	genesis_hash_size: u32,
	nonce: *const u32,
	w_url: *const u8,
	w_url_size: u32,
	unchecked_extrinsic: *mut u8,
	unchecked_extrinsic_size: u32,
	quoting_enclave_target_info: &sgx_target_info_t,
	quote_size: *const u32,
) -> sgx_status_t {
	let (_key_der, cert_der) =
		match generate_dcap_ecc_cert(quoting_enclave_target_info, *quote_size, &OcallApi, false) {
			Ok(r) => r,
			Err(e) => return e.into(),
		};

	if let Err(err) = io::write(&cert_der, RA_DUMP_CERT_DER_FILE) {
		error!(
			"    [Enclave] failed to write RA file ({}), status: {:?}",
			RA_DUMP_CERT_DER_FILE, err
		);
		return sgx_status_t::SGX_ERROR_UNEXPECTED
	}
	info!("    [Enclave] dumped ra cert to {}", RA_DUMP_CERT_DER_FILE);

	info!("    [Enclave] Compose extrinsic");
	let genesis_hash_slice = slice::from_raw_parts(genesis_hash, genesis_hash_size as usize);
	//let mut nonce_slice     = slice::from_raw_parts(nonce, nonce_size as usize);
	let url_slice = slice::from_raw_parts(w_url, w_url_size as usize);
	let extrinsic_slice =
		slice::from_raw_parts_mut(unchecked_extrinsic, unchecked_extrinsic_size as usize);
	let signer = match Ed25519Seal::unseal_from_static_file() {
		Ok(pair) => pair,
		Err(e) => return e.into(),
	};
	info!("[Enclave] Restored ECC pubkey: {:?}", signer.public());

	debug!("decoded nonce: {}", *nonce);
	let genesis_hash = hash_from_slice(genesis_hash_slice);
	debug!("decoded genesis_hash: {:?}", genesis_hash_slice);
	debug!("worker url: {}", str::from_utf8(url_slice).unwrap());
	let node_metadata_repository = match GLOBAL_NODE_METADATA_REPOSITORY_COMPONENT.get() {
		Ok(r) => r,
		Err(e) => {
			error!("Component get failure: {:?}", e);
			return sgx_status_t::SGX_ERROR_UNEXPECTED
		},
	};

	let (register_enclave_call, runtime_spec_version, runtime_transaction_version) =
		match node_metadata_repository.get_from_metadata(|m| {
			(
				m.register_enclave_call_indexes(),
				m.get_runtime_version(),
				m.get_runtime_transaction_version(),
			)
		}) {
			Ok(r) => r,
			Err(e) => {
				error!("Failed to get node metadata: {:?}", e);
				return sgx_status_t::SGX_ERROR_UNEXPECTED
			},
		};

	let call =
		match register_enclave_call {
			Ok(c) => c,
			Err(e) => {
				error!("Failed to get the indexes for the register_enclave call from the metadata: {:?}", e);
				return sgx_status_t::SGX_ERROR_UNEXPECTED
			},
		};

	let extrinsic_params = ParentchainExtrinsicParams::new(
		runtime_spec_version,
		runtime_transaction_version,
		*nonce,
		genesis_hash,
		ParentchainExtrinsicParamsBuilder::default(),
	);

	let xt = compose_extrinsic_offline!(
		signer,
		(call, cert_der.to_vec(), url_slice.to_vec()),
		extrinsic_params
	);

	let xt_encoded = xt.encode();
	let xt_hash = blake2_256(&xt_encoded);
	debug!("    [Enclave] Encoded extrinsic ( len = {} B), hash {:?}", xt_encoded.len(), xt_hash);

	if let Err(e) = write_slice_and_whitespace_pad(extrinsic_slice, xt_encoded) {
		return EnclaveError::Other(Box::new(e)).into()
	};

	sgx_status_t::SGX_SUCCESS
}

#[no_mangle]
pub unsafe extern "C" fn dump_dcap_ra_to_disk(
	quoting_enclave_target_info: &sgx_target_info_t,
	quote_size: u32,
) -> sgx_status_t {
	let (_key_der, cert_der) =
		match generate_dcap_ecc_cert(quoting_enclave_target_info, quote_size, &OcallApi, false) {
			Ok(r) => r,
			Err(e) => return e.into(),
		};

	if let Err(err) = io::write(&cert_der, RA_DUMP_CERT_DER_FILE) {
		error!(
			"    [Enclave] failed to write RA file ({}), status: {:?}",
			RA_DUMP_CERT_DER_FILE, err
		);
		return sgx_status_t::SGX_ERROR_UNEXPECTED
	}
	info!("    [Enclave] dumped ra cert to {}", RA_DUMP_CERT_DER_FILE);

	sgx_status_t::SGX_SUCCESS
}
