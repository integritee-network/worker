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
use core::default::Default;
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
	vec::Vec,
};
use substrate_api_client::{compose_extrinsic_offline, ExtrinsicParams};

pub fn ecdsa_quote_verification<A: EnclaveAttestationOCallApi>(
	quote: &[u8],
	ocall_api: &A,
) -> SgxResult<Vec<u8>> {
	let mut supplemental_data_size = 0u32; // mem::zeroed() is safe as long as the struct doesn't have zero-invalid types, like pointers
	let mut supplemental_data: qvl::sgx_ql_qv_supplemental_t = unsafe { std::mem::zeroed() };
	let mut quote_verification_result = qvl::sgx_ql_qv_result_t::SGX_QL_QV_RESULT_UNSPECIFIED;
	let mut qve_report_info: qvl::sgx_ql_qe_report_info_t = unsafe { std::mem::zeroed() };
	let rand_nonce = "59jslk201fgjmm;\0";
	let mut collateral_expiration_status = 1u32;

	// get target info of SampleISVEnclave. QvE will target the generated report to this enclave.
	sgx_self_target(
		&mut qve_report_info.app_enclave_target_info as *mut qvl_sys::sgx_target_info_t,
	);

	// set current time. This is only for sample purposes, in production mode a trusted time should be used.
	//
	let current_time: i64 = SystemTime::now()
		.duration_since(SystemTime::UNIX_EPOCH)
		.unwrap()
		.as_secs()
		.try_into()
		.unwrap();

	let p_supplemental_data = match supplemental_data_size {
		0 => None,
		_ => Some(&mut supplemental_data),
	};

	// Ocall call Quote verification Enclave (QvE) report
	let dcap_ret = qvl::sgx_qv_verify_quote(
		quote,
		None,
		current_time,
		&mut collateral_expiration_status,
		&mut quote_verification_result,
		Some(&mut qve_report_info),
		supplemental_data_size,
		p_supplemental_data,
	);
}

#[allow(const_err)]
pub fn create_qe_dcap_quote<A: EnclaveAttestationOCallApi>(
	pub_k: &[u8; 32],
	ocall_api: &A,
	quoting_enclave_target_info: &sgx_target_info_t,
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
	let quote_vec = ocall_api.get_dcap_quote(app_report)?;
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
) -> sgx_status_t {
	let (_key_der, cert_der) =
		match generate_dcap_ecc_cert(quoting_enclave_target_info, &OcallApi, false) {
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
) -> sgx_status_t {
	let (_key_der, cert_der) =
		match generate_dcap_ecc_cert(quoting_enclave_target_info, &OcallApi, false) {
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
