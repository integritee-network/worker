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

use crate::{global_components::GLOBAL_ATTESTATION_HANDLER_COMPONENT, Result as EnclaveResult};
use itp_attestation_handler::AttestationHandler;
use itp_component_container::ComponentGetter;
use itp_settings::worker::MR_ENCLAVE_SIZE;
use itp_utils::write_slice_and_whitespace_pad;
use log::*;
use sgx_types::*;
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
pub unsafe extern "C" fn perform_ra(
	w_url: *const u8,
	w_url_size: u32,
	unchecked_extrinsic: *mut u8,
	unchecked_extrinsic_size: u32,
) -> sgx_status_t {
	if genesis_hash.is_null() || w_url.is_null() || unchecked_extrinsic.is_null() || nonce.is_null()
	{
		return sgx_status_t::SGX_ERROR_INVALID_PARAMETER
	}
	let attestation_handler = match GLOBAL_ATTESTATION_HANDLER_COMPONENT.get() {
		Ok(r) => r,
		Err(e) => {
			error!("Component get failure: {:?}", e);
			return sgx_status_t::SGX_ERROR_UNEXPECTED
		},
	};
	let genesis_slice = slice::from_raw_parts(genesis_hash, genesis_hash_size as usize);
	let w_url_slice = slice::from_raw_parts(w_url, w_url_size as usize);
	let extrinsics_slice =
		slice::from_raw_parts_mut(unchecked_extrinsic, unchecked_extrinsic_size as usize);
	match attestation_handler.perform_ra(genesis_slice, *nonce, w_url_slice) {
		Ok(extrinsic) => {
			if let Err(e) = write_slice_and_whitespace_pad(extrinsics_slice, extrinsic) {
				error!("Failed to transfer extrinsic to o-call buffer: {:?}", e);
				return sgx_status_t::SGX_ERROR_UNEXPECTED
			}
			sgx_status_t::SGX_SUCCESS
		},
		Err(e) => e.into(),
	}
	// our certificate is unlinkable
	let sign_type = sgx_quote_sign_type_t::SGX_UNLINKABLE_SIGNATURE;

	let (_key_der, cert_der) = match create_ra_report_and_signature(sign_type, &OcallApi, false) {
		Ok(r) => r,
		Err(e) => return e.into(),
	};

	info!("    [Enclave] Compose extrinsic");
	let mut url_slice = slice::from_raw_parts(w_url, w_url_size as usize);
	let url = String::decode(&mut url_slice).unwrap();
	let extrinsic_slice =
		slice::from_raw_parts_mut(unchecked_extrinsic, unchecked_extrinsic_size as usize);

	let xt = match create_attestation_extrinsic(url, cert_der) {
		Ok(xt) => xt,
		Err(e) => return e.into(),
	};

	if let Err(e) = write_slice_and_whitespace_pad(extrinsic_slice, xt.encode()) {
		return EnclaveError::Other(Box::new(e)).into()
	};

	sgx_status_t::SGX_SUCCESS
}

#[no_mangle]
pub unsafe extern "C" fn mock_register_enclave_xt(
	w_url: *const u8,
	w_url_size: u32,
	unchecked_extrinsic: *mut u8,
	unchecked_extrinsic_size: u32,
) -> sgx_status_t {
	let mut url_slice = slice::from_raw_parts(w_url, w_url_size as usize);
	let url: String = Decode::decode(&mut url_slice).unwrap();
	let extrinsic_slice =
		slice::from_raw_parts_mut(unchecked_extrinsic, unchecked_extrinsic_size as usize);

	let mre = OcallApi
		.get_mrenclave_of_self()
		.map_or_else(|_| Vec::<u8>::new(), |m| m.m.encode());

	let xt = match create_attestation_extrinsic(url, mre) {
		Ok(xt) => xt,
		Err(e) => return e.into(),
	};

	if let Err(e) = write_slice_and_whitespace_pad(extrinsic_slice, xt.encode()) {
		return EnclaveError::Other(Box::new(e)).into()
	};
	sgx_status_t::SGX_SUCCESS
}

fn create_attestation_extrinsic(url: String, cert_der: Vec<u8>) -> EnclaveResult<OpaqueExtrinsic> {
	let node_metadata_repository = GLOBAL_NODE_METADATA_REPOSITORY_COMPONENT.get()?;
	let extrinsics_factory = GLOBAL_EXTRINSICS_FACTORY_COMPONENT.get()?;

	let call_ids =
		node_metadata_repository.get_from_metadata(|m| m.register_enclave_call_indexes())??;

	let call = OpaqueCall::from_tuple(&(call_ids, cert_der, url));

	let extrinsics = extrinsics_factory.create_extrinsics(&[call], None)?;

	Ok(extrinsics[0].clone())
}

#[no_mangle]
pub extern "C" fn dump_ra_to_disk() -> sgx_status_t {
	let attestation_handler = match GLOBAL_ATTESTATION_HANDLER_COMPONENT.get() {
		Ok(r) => r,
		Err(e) => {
			error!("Component get failure: {:?}", e);
			return sgx_status_t::SGX_ERROR_UNEXPECTED
		},
	};
	match attestation_handler.dump_ra_to_disk() {
		Ok(_) => sgx_status_t::SGX_SUCCESS,
		Err(e) => e.into(),
	}
}
