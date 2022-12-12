// Copyright 2022 Integritee AG and Supercomputing Systems AG
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
	initialization::global_components::GLOBAL_ATTESTATION_HANDLER_COMPONENT,
	utils::{
		get_extrinsic_factory_from_solo_or_parachain,
		get_node_metadata_repository_from_solo_or_parachain,
	},
	Error as EnclaveError, Result as EnclaveResult,
};
use codec::{Decode, Encode};
use itp_attestation_handler::AttestationHandler;
use itp_component_container::ComponentGetter;
use itp_extrinsics_factory::CreateExtrinsics;
use itp_node_api::metadata::{
	pallet_teerex::TeerexCallIndexes,
	provider::{AccessNodeMetadata, Error as MetadataProviderError},
};
use itp_settings::worker::MR_ENCLAVE_SIZE;
use itp_types::OpaqueCall;
use itp_utils::write_slice_and_whitespace_pad;
use log::*;
use sgx_types::*;
use sp_runtime::OpaqueExtrinsic;
use std::{prelude::v1::*, slice, vec::Vec};

#[no_mangle]
pub unsafe extern "C" fn get_mrenclave(mrenclave: *mut u8, mrenclave_size: usize) -> sgx_status_t {
	if mrenclave.is_null() || mrenclave_size < MR_ENCLAVE_SIZE {
		return sgx_status_t::SGX_ERROR_INVALID_PARAMETER
	}
	let attestation_handler = match GLOBAL_ATTESTATION_HANDLER_COMPONENT.get() {
		Ok(r) => r,
		Err(e) => {
			error!("Component get failure: {:?}", e);
			return sgx_status_t::SGX_ERROR_UNEXPECTED
		},
	};
	match attestation_handler.get_mrenclave() {
		Ok(mrenclave_value) => {
			let mrenclave_slice = slice::from_raw_parts_mut(mrenclave, mrenclave_size);
			if let Err(e) =
				write_slice_and_whitespace_pad(mrenclave_slice, mrenclave_value.to_vec())
			{
				error!("Failed to transfer mrenclave to o-call buffer: {:?}", e);
				return sgx_status_t::SGX_ERROR_UNEXPECTED
			}
			sgx_status_t::SGX_SUCCESS
		},
		Err(e) => e.into(),
	}
}

pub fn create_ra_report_and_signature(
	sign_type: sgx_quote_sign_type_t,
	skip_ra: bool,
) -> EnclaveResult<(Vec<u8>, Vec<u8>)> {
	let attestation_handler = match GLOBAL_ATTESTATION_HANDLER_COMPONENT.get() {
		Ok(r) => r,
		Err(e) => {
			error!("Component get failure: {:?}", e);
			return Err(e.into())
		},
	};

	match attestation_handler.create_ra_report_and_signature(sign_type, skip_ra) {
		Ok(r) => Ok(r),
		Err(e) => {
			error!("create_ra_report_and_signature failure: {:?}", e);
			Err(e.into())
		},
	}
}

#[no_mangle]
pub unsafe extern "C" fn generate_ias_ra_extrinsic(
	w_url: *const u8,
	w_url_size: u32,
	unchecked_extrinsic: *mut u8,
	unchecked_extrinsic_size: u32,
	skip_ra: c_int,
) -> sgx_status_t {
	if w_url.is_null() || unchecked_extrinsic.is_null() {
		return sgx_status_t::SGX_ERROR_INVALID_PARAMETER
	}
	let mut url_slice = slice::from_raw_parts(w_url, w_url_size as usize);
	let url = String::decode(&mut url_slice).expect("Could not decode url slice to a valid String");
	let extrinsic_slice =
		slice::from_raw_parts_mut(unchecked_extrinsic, unchecked_extrinsic_size as usize);

	let extrinsic = match generate_ias_ra_extrinsic_internal(url, skip_ra == 1) {
		Ok(xt) => xt,
		Err(e) => return e.into(),
	};

	if let Err(e) = write_slice_and_whitespace_pad(extrinsic_slice, extrinsic.encode()) {
		return EnclaveError::Other(Box::new(e)).into()
	};

	sgx_status_t::SGX_SUCCESS
}

#[no_mangle]
pub unsafe extern "C" fn generate_dcap_ra_extrinsic(
	_w_url: *const u8,
	_w_url_size: u32,
	_unchecked_extrinsic: *mut u8,
	_unchecked_extrinsic_size: u32,
	_skip_ra: c_int,
	quoting_enclave_target_info: &sgx_target_info_t,
	quote_size: u32,
) -> sgx_status_t {
	let attestation_handler = match GLOBAL_ATTESTATION_HANDLER_COMPONENT.get() {
		Ok(r) => r,
		Err(e) => {
			error!("Component get failure: {:?}", e);
			return sgx_status_t::SGX_ERROR_UNEXPECTED
		},
	};

	let (_key_der, _cert_der) = match attestation_handler.generate_dcap_ra_cert(
		quoting_enclave_target_info,
		quote_size,
		false,
	) {
		Ok(r) => r,
		Err(e) => return e.into(),
	};
	// TODO Need to send this to the teerex pallet (something similar to perform_ra_internal)
	sgx_status_t::SGX_SUCCESS
}

fn generate_ias_ra_extrinsic_internal(
	url: String,
	skip_ra: bool,
) -> EnclaveResult<OpaqueExtrinsic> {
	let attestation_handler = GLOBAL_ATTESTATION_HANDLER_COMPONENT.get()?;
	let extrinsics_factory = get_extrinsic_factory_from_solo_or_parachain()?;
	let node_metadata_repo = get_node_metadata_repository_from_solo_or_parachain()?;

	let cert_der = attestation_handler.generate_ias_ra_cert(skip_ra)?;

	info!("    [Enclave] Compose register enclave call");
	let call_ids = node_metadata_repo
		.get_from_metadata(|m| m.register_enclave_call_indexes())?
		.map_err(MetadataProviderError::MetadataError)?;

	let call = OpaqueCall::from_tuple(&(call_ids, cert_der, url));

	let extrinsics = extrinsics_factory.create_extrinsics(&[call], None)?;

	Ok(extrinsics[0].clone())
}

#[no_mangle]
pub extern "C" fn dump_ias_ra_cert_to_disk() -> sgx_status_t {
	let attestation_handler = match GLOBAL_ATTESTATION_HANDLER_COMPONENT.get() {
		Ok(r) => r,
		Err(e) => {
			error!("Component get failure: {:?}", e);
			return sgx_status_t::SGX_ERROR_UNEXPECTED
		},
	};
	match attestation_handler.dump_ias_ra_cert_to_disk() {
		Ok(_) => sgx_status_t::SGX_SUCCESS,
		Err(e) => e.into(),
	}
}

#[no_mangle]
pub unsafe extern "C" fn dump_dcap_ra_cert_to_disk(
	quoting_enclave_target_info: &sgx_target_info_t,
	quote_size: u32,
) -> sgx_status_t {
	let attestation_handler = match GLOBAL_ATTESTATION_HANDLER_COMPONENT.get() {
		Ok(r) => r,
		Err(e) => {
			error!("Component get failure: {:?}", e);
			return sgx_status_t::SGX_ERROR_UNEXPECTED
		},
	};
	match attestation_handler.dump_dcap_ra_cert_to_disk(quoting_enclave_target_info, quote_size) {
		Ok(_) => sgx_status_t::SGX_SUCCESS,
		Err(e) => e.into(),
	}
}
