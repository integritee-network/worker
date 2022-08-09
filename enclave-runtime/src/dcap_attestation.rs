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
use itp_utils::write_slice_and_whitespace_pad;
use log::*;
use sgx_tcrypto::*;
use sgx_tse::rsgx_create_report;
use sgx_types::*;
use sp_core::{blake2_256, Pair};
use std::{
	io::{Read, Write},
	prelude::v1::*,
	slice, str,
	time::SystemTime,
	vec::Vec,
};
use substrate_api_client::{compose_extrinsic_offline, ExtrinsicParams};

pub fn ecdsa_quote_verification<A: EnclaveAttestationOCallApi>(
	quote: Vec<u8>,
	ocall_api: &A,
) -> SgxResult<Vec<u8>> {
	let mut app_enclave_target_info: sgx_target_info_t = unsafe { std::mem::zeroed() };
	let quote_collateral: sgx_ql_qve_collateral_t = unsafe { std::mem::zeroed() };
	let mut qve_report_info: sgx_ql_qe_report_info_t = unsafe { std::mem::zeroed() };
	let quote_verification_result = sgx_ql_qv_result_t::SGX_QL_QV_RESULT_UNSPECIFIED;
	let supplemental_data_size = std::mem::size_of::<sgx_ql_qv_supplemental_t>() as u32;

	// get target info of SampleISVEnclave. QvE will target the generated report to this enclave.
	unsafe { sgx_self_target(&mut app_enclave_target_info as *mut sgx_target_info_t) };

	// set current time. This is only for sample purposes, in production mode a trusted time should be used.
	//
	let current_time: i64 = SystemTime::now()
		.duration_since(SystemTime::UNIX_EPOCH)
		.unwrap()
		.as_secs()
		.try_into()
		.unwrap();

	// FIXME: make nonce truly random
	let rand_nonce = "59jslk201fgjmm;\0";
	// set nonce
	qve_report_info.nonce.rand.copy_from_slice(rand_nonce.as_bytes());
	qve_report_info.app_enclave_target_info = app_enclave_target_info;

	// Ocall call Quote verification Enclave (QvE) report
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
	error!("Final check: {:?}", ret_val);
	// 	let mut sha_handle: sgx_sha_state_handle_t = unsafe { std::mem::zeroed() };
	// 	let mut report_data: sgx_report_data_t = 0;
	//
	// 	// Sanity checks.
	// 	if std::mem::size_of(qve_report_info_return_value) == 0
	// 		|| std::mem::size_of(qve_report_info_return_value)
	// 			!= std::mem::size_of(sgx_ql_qe_report_info_t)
	// 		|| !sgx_is_within_enclave(quote.as_ptr(), quote.len())
	// 		|| !sgx_is_within_enclave(
	// 			qve_report_info_return_value,
	// 			std::mem::size_of(sgx_ql_qe_report_info_t),
	// 		) || (supplemental_data.len() == 0 && supplemental_data_size != 0)
	// 		|| (supplemental_data.len() != 0 && supplemental_data_size == 0)
	// 	{
	// 		error!("    [Enclave] Invalid quote verification return values.");
	// 		return Err(sgx_status_t::SGX_INVALID_PARAMETER)
	// 	}
	//
	// 	if (supplemental_data.len() && supplemental_data_size > 0) {
	// 		if (!sgx_is_within_enclave(supplemental_data.as_ptr(), supplemental_data_size)) {
	// 			error!("    [Enclave] Invalid quote verification return values.");
	// 			return Err(sgx_status_t::SGX_INVALID_PARAMETER)
	// 		}
	// 	}
	// 	let qve_report = qve_report_info_return_value.qe_report;
	//
	// 	// Verify QvE report.
	// 	sgx_ret = sgx_verify_report(p_qve_report as *const sgx_report_t);
	// 	if (sgx_ret != SGX_SUCCESS) {
	// 		error!("    [Enclave] QvE report verification failed. {:?}", sgx_ret);
	// 		return Err(sgx_status_t::SGX_ERROR_UNEXPECTED)
	// 	}
	//
	// 	//Verify QvE report data
	// 	//report_data = SHA256([nonce || quote || expiration_check_date || expiration_status || verification_result || supplemental_data]) || 32 - 0x00
	// 	sgx_ret = sgx_sha256_init(&sha_handle as *mut sgx_sha_state_handle_t);
	// 	if (sgx_ret != SGX_SUCCESS) {
	// 		error!("    [Enclave] Sha handle initiation failed. {:?}", sgx_ret);
	// 		return Err(sgx_status_t::SGX_ERROR_UNEXPECTED)
	// 	}
	// 	//nonce
	// 	let qve_nonce = qve_report_info_return_value.nonce;
	// 	sgx_ret = sgx_sha256_update(qve_nonce as const* u8, std::mem::size_of(qve_nonce), sha_handle);
	// 	if (sgx_ret != SGX_SUCCESS) {
	// 		error!("    [Enclave] Sha handle initiation failed. {:?}", sgx_ret);
	// 		return Err(sgx_status_t::SGX_ERROR_UNEXPECTED)
	// 	}
	// 	//quote
	// 	sgx_ret = sgx_sha256_update(quote.as_ptr(), quote_size, sha_handle);
	// 	if (sgx_ret != SGX_SUCCESS) {
	// 		error!("    [Enclave] Sha handle initiation failed. {:?}", sgx_ret);
	// 		return Err(sgx_status_t::SGX_ERROR_UNEXPECTED)
	// 	}
	// 	//expiration_check_date
	// 	sgx_ret = sgx_sha256_update(&expiration_check_date, std::mem::size_of(expiration_check_date), sha_handle);
	// 	if (sgx_ret != SGX_SUCCESS) {
	// 		error!("    [Enclave] Sha handle initiation failed. {:?}", sgx_ret);
	// 		return Err(sgx_status_t::SGX_ERROR_UNEXPECTED)
	// 	}
	// 	sgx_ret = sgx_sha256_update(collateral_expiration_status, std::mem::size_of(collateral_expiration_status), sha_handle);
	// 	if (sgx_ret != SGX_SUCCESS) {
	// 		error!("    [Enclave] Sha handle initiation failed. {:?}", sgx_ret);
	// 		return Err(sgx_status_t::SGX_ERROR_UNEXPECTED)
	// 	}
	// 	sgx_ret = sgx_sha256_update(quote_verification_result, std::mem::size_of(quote_verification_result), sha_handle);
	// 	if (sgx_ret != SGX_SUCCESS) {
	// 		error!("    [Enclave] Sha handle initiation failed. {:?}", sgx_ret);
	// 		return Err(sgx_status_t::SGX_ERROR_UNEXPECTED)
	// 	}
	// 	if supplemental_data.len() != 0 {
	// 		sgx_ret = sgx_sha256_update(supplemental_data.as_ptr(), supplemental_data_size, sha_handle);
	// 		if (sgx_ret != SGX_SUCCESS) {
	// 			error!("    [Enclave] Sha handle initiation failed. {:?}", sgx_ret);
	// 			return Err(sgx_status_t::SGX_ERROR_UNEXPECTED)
	// 		}
	// 	}
	//
	// 	//get the hashed report_data
	// 	sgx_ret = sgx_sha256_get_hash(sha_handle, mut report_data);
	//
	// 	if memcmp(qve_report.body.report_data, &report_data, std::mem::size_of(report_data)) != 0 {
	// 		if (sgx_ret != SGX_SUCCESS) {
	// 			error!("    [Enclave] Sha handle initiation failed. {:?}", sgx_ret);
	// 			return Err(sgx_status_t::SGX_ERROR_UNEXPECTED)
	// 		}
	// 	}
	//
	// 	//Hardcode Intel signed QvE Identity below
	// 	//You can get such info from QvE Identity JSON file
	// 	//e.g. Get the QvE Identity JSON file from
	// 	//https://api.trustedservices.intel.com/sgx/certification/v3/qve/identity
	// 	const QVE_MISC_SELECT: &str = "00000000";
	// 	const QVE_MISC_SELECT_MASK: &str = "FFFFFFFF";
	//
	// 	const QVE_ATTRIBUTE: &str = "01000000000000000000000000000000";
	// 	const QVE_ATTRIBUTE_MASK: &str = "FBFFFFFFFFFFFFFF0000000000000000";
	//
	// 	//MRSIGNER of Intel signed QvE
	// 	const std::string QVE_MRSIGNER = "8C4F5775D796503E96137F77C68A829A0056AC8DED70140B081B094490C57BFF";
	//
	// 	const sgx_prod_id_t QVE_PRODID = 2;
	//
	// 	//Defense in depth, QvE ISV SVN in report must be greater or equal to hardcode QvE ISV SVN
	// 	const sgx_isv_svn_t LEAST_QVE_ISVSVN = 6;

	Ok(vec![])
}

#[allow(const_err)]
pub fn create_qe_dcap_quote<A: EnclaveAttestationOCallApi>(
	pub_k: &[u8; 32],
	ocall_api: &A,
	quoting_enclave_target_info: &sgx_target_info_t,
	quote_size: u32,
) -> SgxResult<Vec<u8>> {
	// Generate app enclave report
	let mut report_data: sgx_report_data_t = sgx_report_data_t::default();
	report_data.d[..32].clone_from_slice(&pub_k[..]);

	let app_report = match rsgx_create_report(&quoting_enclave_target_info, &report_data) {
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

	// This quote has type `sgx_quote3_t` and is structured as:
	// sgx_quote3_t {
	//     header: sgx_quote_header_t,
	//     report_body: sgx_report_body_t,
	//     signature_data_len: uint32_t,  // 1116
	//     signature_data {               // 1116 bytes payload
	//         sig_data: sgx_ql_ecdsa_sig_data_t { // 576 = 64x3 +384 header
	//             sig: [uint8_t; 64],
	//             attest_pub_key: [uint8_t; 64],
	//             qe3_report: sgx_report_body_t, //  384
	//             qe3_report_sig: [uint8_t; 64],
	//             auth_certification_data { // 2 + 32 = 34
	//                 sgx_ql_auth_data_t: u16 // observed 32, size of following auth_data
	//                 auth_data: [u8; sgx_ql_auth_data_t]
	//             }
	//             sgx_ql_certification_data_t {/ 2 + 4 + 500
	//                 cert_key_type: uint16_t,
	//                 size: uint32_t, // observed 500, size of following certificateion_data
	//                 certification_data { // 500 bytes
	//                 }
	//             }
	//         }
	//     }
	//  }
	debug!("Entering ocall_api.get_dcap_quote with quote size: {:?} ", quote_size);
	let quote_vec = ocall_api.get_dcap_quote(app_report, quote_size)?;
	if quote_vec.len() == 0 {
		error!("    [Enclave] DCAP quote size is zero, can not continue");
		return Err(sgx_status_t::SGX_ERROR_UNEXPECTED)
	}
	let p_quote3: *const sgx_quote3_t = quote_vec.as_ptr() as *const sgx_quote3_t;
	let quote3: sgx_quote3_t = unsafe { *p_quote3 };

	// TODO: Before signing the report, we should check the report ourselves
	// Because blockchain verification does not go the trusted way. We can do this here.
	// Perform a check on qe_report to verify if the qe_report is valid
	// match rsgx_verify_report(&quote3) {
	// 	Ok(()) => debug!("    [Enclave] rsgx_verify_report success!"),
	// 	Err(x) => {
	// 		error!("    [Enclave] rsgx_verify_report failed. {:?}", x);
	// 		return Err(x)
	// 	},
	// }
	//TODO!
	// Check if the qe_report is produced on the same platform
	// 	if quoting_enclave_target_info.mr_enclave.m != quote3.report_body.mr_enclave.m
	// 		|| quoting_enclave_target_info.attributes.flags != quote3.report_body.attributes.flags
	// 		|| quoting_enclave_target_info.attributes.xfrm != quote3.report_body.attributes.xfrm
	// 	{
	// 		error!("    [Enclave] qe_quote does not match current quoting_enclave_target_info!");
	// 		error!(
	// 			"{:?} vs {:?}",
	// 			quoting_enclave_target_info.mr_enclave.m, quote3.report_body.mr_enclave.m
	// 		);
	// 		error!(
	// 			"{:?} vs {:?}",
	// 			quoting_enclave_target_info.attributes.flags, quote3.report_body.attributes.flags
	// 		);
	// 		error!(
	// 			"{:?} vs {:?}",
	// 			quoting_enclave_target_info.attributes.xfrm, quote3.report_body.attributes.xfrm
	// 		);
	// 		return Err(sgx_status_t::SGX_ERROR_UNEXPECTED)
	// 	}
	//
	// 	debug!("    [Enclave] qe_quote check success");

	// TODO: Need to defend against replay attacks?

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
		let qe_quote = match create_qe_dcap_quote(
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
