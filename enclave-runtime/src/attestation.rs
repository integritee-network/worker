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
use hex_literal::hex;
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

pub fn get_quoting_enclave_data() -> (Vec<u8>, Vec<u8>, Vec<u8>) {
	let data = br#"{"id":"QE","version":2,"issueDate":"2022-11-17T14:34:49Z","nextUpdate":"2023-04-16T14:34:49Z","tcbEvaluationDataNumber":12,"miscselect":"00000000","miscselectMask":"FFFFFFFF","attributes":"11000000000000000000000000000000","attributesMask":"FBFFFFFFFFFFFFFF0000000000000000","mrsigner":"8C4F5775D796503E96137F77C68A829A0056AC8DED70140B081B094490C57BFF","isvprodid":1,"tcbLevels":[{"tcb":{"isvsvn":6},"tcbDate":"2021-11-10T00:00:00Z","tcbStatus":"UpToDate"},{"tcb":{"isvsvn":5},"tcbDate":"2020-11-11T00:00:00Z","tcbStatus":"OutOfDate","advisoryIDs":["INTEL-SA-00477"]},{"tcb":{"isvsvn":4},"tcbDate":"2019-11-13T00:00:00Z","tcbStatus":"OutOfDate","advisoryIDs":["INTEL-SA-00334","INTEL-SA-00477"]},{"tcb":{"isvsvn":2},"tcbDate":"2019-05-15T00:00:00Z","tcbStatus":"OutOfDate","advisoryIDs":["INTEL-SA-00219","INTEL-SA-00293","INTEL-SA-00334","INTEL-SA-00477"]},{"tcb":{"isvsvn":1},"tcbDate":"2018-08-15T00:00:00Z","tcbStatus":"OutOfDate","advisoryIDs":["INTEL-SA-00202","INTEL-SA-00219","INTEL-SA-00293","INTEL-SA-00334","INTEL-SA-00477"]}]}"#;
	let signature = hex!("a9456c69e5878ee2f689b3d449bc961add61a6b80d30804a5510dbd2813d6c748ee8562a02de8d02b1528e83d9740e34736495512eff4a45db11c42002a4c8cf");
	let certs = br#"-----BEGIN CERTIFICATE-----
MIICizCCAjKgAwIBAgIUfjiC1ftVKUpASY5FhAPpFJG99FUwCgYIKoZIzj0EAwIw
aDEaMBgGA1UEAwwRSW50ZWwgU0dYIFJvb3QgQ0ExGjAYBgNVBAoMEUludGVsIENv
cnBvcmF0aW9uMRQwEgYDVQQHDAtTYW50YSBDbGFyYTELMAkGA1UECAwCQ0ExCzAJ
BgNVBAYTAlVTMB4XDTE4MDUyMTEwNTAxMFoXDTI1MDUyMTEwNTAxMFowbDEeMBwG
A1UEAwwVSW50ZWwgU0dYIFRDQiBTaWduaW5nMRowGAYDVQQKDBFJbnRlbCBDb3Jw
b3JhdGlvbjEUMBIGA1UEBwwLU2FudGEgQ2xhcmExCzAJBgNVBAgMAkNBMQswCQYD
VQQGEwJVUzBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABENFG8xzydWRfK92bmGv
P+mAh91PEyV7Jh6FGJd5ndE9aBH7R3E4A7ubrlh/zN3C4xvpoouGlirMba+W2lju
ypajgbUwgbIwHwYDVR0jBBgwFoAUImUM1lqdNInzg7SVUr9QGzknBqwwUgYDVR0f
BEswSTBHoEWgQ4ZBaHR0cHM6Ly9jZXJ0aWZpY2F0ZXMudHJ1c3RlZHNlcnZpY2Vz
LmludGVsLmNvbS9JbnRlbFNHWFJvb3RDQS5kZXIwHQYDVR0OBBYEFH44gtX7VSlK
QEmORYQD6RSRvfRVMA4GA1UdDwEB/wQEAwIGwDAMBgNVHRMBAf8EAjAAMAoGCCqG
SM49BAMCA0cAMEQCIB9C8wOAN/ImxDtGACV246KcqjagZOR0kyctyBrsGGJVAiAj
ftbrNGsGU8YH211dRiYNoPPu19Zp/ze8JmhujB0oBw==
-----END CERTIFICATE-----
-----BEGIN CERTIFICATE-----
MIICjzCCAjSgAwIBAgIUImUM1lqdNInzg7SVUr9QGzknBqwwCgYIKoZIzj0EAwIw
aDEaMBgGA1UEAwwRSW50ZWwgU0dYIFJvb3QgQ0ExGjAYBgNVBAoMEUludGVsIENv
cnBvcmF0aW9uMRQwEgYDVQQHDAtTYW50YSBDbGFyYTELMAkGA1UECAwCQ0ExCzAJ
BgNVBAYTAlVTMB4XDTE4MDUyMTEwNDUxMFoXDTQ5MTIzMTIzNTk1OVowaDEaMBgG
A1UEAwwRSW50ZWwgU0dYIFJvb3QgQ0ExGjAYBgNVBAoMEUludGVsIENvcnBvcmF0
aW9uMRQwEgYDVQQHDAtTYW50YSBDbGFyYTELMAkGA1UECAwCQ0ExCzAJBgNVBAYT
AlVTMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEC6nEwMDIYZOj/iPWsCzaEKi7
1OiOSLRFhWGjbnBVJfVnkY4u3IjkDYYL0MxO4mqsyYjlBalTVYxFP2sJBK5zlKOB
uzCBuDAfBgNVHSMEGDAWgBQiZQzWWp00ifODtJVSv1AbOScGrDBSBgNVHR8ESzBJ
MEegRaBDhkFodHRwczovL2NlcnRpZmljYXRlcy50cnVzdGVkc2VydmljZXMuaW50
ZWwuY29tL0ludGVsU0dYUm9vdENBLmRlcjAdBgNVHQ4EFgQUImUM1lqdNInzg7SV
Ur9QGzknBqwwDgYDVR0PAQH/BAQDAgEGMBIGA1UdEwEB/wQIMAYBAf8CAQEwCgYI
KoZIzj0EAwIDSQAwRgIhAOW/5QkR+S9CiSDcNoowLuPRLsWGf/Yi7GSX94BgwTwg
AiEA4J0lrHoMs+Xo5o/sX6O9QWxHRAvZUGOdRQ7cvqRXaqI=
-----END CERTIFICATE-----"#;
	(data.to_vec(), signature.to_vec(), certs.to_vec())
}

#[no_mangle]
pub unsafe extern "C" fn generate_dcap_ra_extrinsic(
	w_url: *const u8,
	w_url_size: u32,
	unchecked_extrinsic: *mut u8,
	unchecked_extrinsic_size: u32,
	skip_ra: c_int,
	quoting_enclave_target_info: &sgx_target_info_t,
	quote_size: u32,
) -> sgx_status_t {
	if w_url.is_null() || unchecked_extrinsic.is_null() {
		return sgx_status_t::SGX_ERROR_INVALID_PARAMETER
	}
	let mut url_slice = slice::from_raw_parts(w_url, w_url_size as usize);
	let url = String::decode(&mut url_slice).expect("Could not decode url slice to a valid String");
	let extrinsic_slice =
		slice::from_raw_parts_mut(unchecked_extrinsic, unchecked_extrinsic_size as usize);
	let attestation_handler = match GLOBAL_ATTESTATION_HANDLER_COMPONENT.get() {
		Ok(r) => r,
		Err(e) => {
			error!("Component get failure: {:?}", e);
			return sgx_status_t::SGX_ERROR_UNEXPECTED
		},
	};

	let (_key_der, cert_der) = match attestation_handler.generate_dcap_ra_cert(
		quoting_enclave_target_info,
		quote_size,
		skip_ra == 1,
	) {
		Ok(r) => r,
		Err(e) => return e.into(),
	};
	// TODO Need to send this to the teerex pallet (something similar to perform_ra_internal)
	let extrinsics_factory = get_extrinsic_factory_from_solo_or_parachain().unwrap();
	let node_metadata_repo = get_node_metadata_repository_from_solo_or_parachain().unwrap();

	let call_ids = node_metadata_repo
		.get_from_metadata(|m| m.register_dcap_enclave_call_indexes())
		.unwrap()
		.map_err(MetadataProviderError::MetadataError)
		.unwrap();
	info!("    [Enclave] Compose register enclave call DCAP IDS: {:?}", call_ids);
	let call = OpaqueCall::from_tuple(&(call_ids, cert_der, url));

	let extrinsic = extrinsics_factory.create_extrinsics(&[call], None).unwrap()[0].clone();
	if let Err(e) = write_slice_and_whitespace_pad(extrinsic_slice, extrinsic.encode()) {
		return EnclaveError::Other(Box::new(e)).into()
	};
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
pub unsafe extern "C" fn generate_qe_extrinsic(
	unchecked_extrinsic: *mut u8,
	unchecked_extrinsic_size: u32,
) -> sgx_status_t {
	if unchecked_extrinsic.is_null() {
		return sgx_status_t::SGX_ERROR_INVALID_PARAMETER
	}
	let extrinsic_slice =
		slice::from_raw_parts_mut(unchecked_extrinsic, unchecked_extrinsic_size as usize);
	let attestation_handler = match GLOBAL_ATTESTATION_HANDLER_COMPONENT.get() {
		Ok(r) => r,
		Err(e) => {
			error!("Component get failure: {:?}", e);
			return sgx_status_t::SGX_ERROR_UNEXPECTED
		},
	};
	let (data, signature, certs) = get_quoting_enclave_data();

	let extrinsics_factory = get_extrinsic_factory_from_solo_or_parachain().unwrap();
	let node_metadata_repo = get_node_metadata_repository_from_solo_or_parachain().unwrap();

	let call_ids = node_metadata_repo
		.get_from_metadata(|m| m.register_quoting_enclave_call_indexes())
		.unwrap()
		.map_err(MetadataProviderError::MetadataError)
		.unwrap();
	info!("    [Enclave] Compose register quoting enclave call: {:?}", call_ids);
	let call = OpaqueCall::from_tuple(&(call_ids, data, signature, certs));

	let extrinsic = extrinsics_factory.create_extrinsics(&[call], None).unwrap()[0].clone();
	if let Err(e) = write_slice_and_whitespace_pad(extrinsic_slice, extrinsic.encode()) {
		return EnclaveError::Other(Box::new(e)).into()
	};
	sgx_status_t::SGX_SUCCESS
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
