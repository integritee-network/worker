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

use crate::ocall_bridge::bridge_api::{
	OCallBridgeError, OCallBridgeResult, RemoteAttestationBridge,
};
use itp_enclave_api::remote_attestation::{QveReport, RemoteAttestationCallBacks};
use sgx_types::*;
use std::{
	net::{SocketAddr, TcpStream},
	os::unix::io::IntoRawFd,
	sync::Arc,
};

pub struct RemoteAttestationOCall<E> {
	enclave_api: Arc<E>,
}

impl<E> RemoteAttestationOCall<E> {
	pub fn new(enclave_api: Arc<E>) -> Self {
		RemoteAttestationOCall { enclave_api }
	}
}

impl<E> RemoteAttestationBridge for RemoteAttestationOCall<E>
where
	E: RemoteAttestationCallBacks,
{
	fn init_quote(&self) -> OCallBridgeResult<(sgx_target_info_t, sgx_epid_group_id_t)> {
		self.enclave_api.init_quote().map_err(|e| match e {
			itp_enclave_api::error::Error::Sgx(s) => OCallBridgeError::InitQuote(s),
			_ => OCallBridgeError::InitQuote(sgx_status_t::SGX_ERROR_UNEXPECTED),
		})
	}

	fn get_ias_socket(&self) -> OCallBridgeResult<i32> {
		let port = 443;
		let hostname = "api.trustedservices.intel.com";

		let addr = lookup_ipv4(hostname, port).map_err(OCallBridgeError::GetIasSocket)?;

		let stream = TcpStream::connect(addr).map_err(|_| {
			OCallBridgeError::GetIasSocket("[-] Connect tls server failed!".to_string())
		})?;

		Ok(stream.into_raw_fd())
	}

	fn get_quote(
		&self,
		revocation_list: Vec<u8>,
		report: sgx_report_t,
		quote_type: sgx_quote_sign_type_t,
		spid: sgx_spid_t,
		quote_nonce: sgx_quote_nonce_t,
	) -> OCallBridgeResult<(sgx_report_t, Vec<u8>)> {
		let real_quote_len =
			self.enclave_api.calc_quote_size(revocation_list.clone()).map_err(|e| match e {
				itp_enclave_api::error::Error::Sgx(s) => OCallBridgeError::GetQuote(s),
				_ => OCallBridgeError::GetQuote(sgx_status_t::SGX_ERROR_UNEXPECTED),
			})?;

		self.enclave_api
			.get_quote(revocation_list, report, quote_type, spid, quote_nonce, real_quote_len)
			.map_err(|e| match e {
				itp_enclave_api::error::Error::Sgx(s) => OCallBridgeError::GetQuote(s),
				_ => OCallBridgeError::GetQuote(sgx_status_t::SGX_ERROR_UNEXPECTED),
			})
	}

	fn get_dcap_quote(&self, report: sgx_report_t, quote_size: u32) -> OCallBridgeResult<Vec<u8>> {
		self.enclave_api.get_dcap_quote(report, quote_size).map_err(|e| match e {
			itp_enclave_api::error::Error::Sgx(s) => OCallBridgeError::GetQuote(s),
			_ => OCallBridgeError::GetQuote(sgx_status_t::SGX_ERROR_UNEXPECTED),
		})
	}

	fn get_qve_report_on_quote(
		&self,
		quote: Vec<u8>,
		current_time: i64,
		quote_collateral: &sgx_ql_qve_collateral_t,
		qve_report_info: sgx_ql_qe_report_info_t,
		supplemental_data_size: u32,
	) -> OCallBridgeResult<QveReport> {
		self.enclave_api
			.get_qve_report_on_quote(
				quote,
				current_time,
				quote_collateral,
				qve_report_info,
				supplemental_data_size,
			)
			.map_err(|e| match e {
				itp_enclave_api::error::Error::Sgx(s) => OCallBridgeError::GetQuote(s),
				_ => OCallBridgeError::GetQuote(sgx_status_t::SGX_ERROR_UNEXPECTED),
			})
	}

	fn get_update_info(
		&self,
		platform_blob: sgx_platform_info_t,
		enclave_trusted: i32,
	) -> OCallBridgeResult<sgx_update_info_bit_t> {
		self.enclave_api
			.get_update_info(platform_blob, enclave_trusted)
			.map_err(|e| match e {
				itp_enclave_api::error::Error::Sgx(s) => OCallBridgeError::GetUpdateInfo(s),
				_ => OCallBridgeError::GetUpdateInfo(sgx_status_t::SGX_ERROR_UNEXPECTED),
			})
	}
}

fn lookup_ipv4(host: &str, port: u16) -> Result<SocketAddr, String> {
	use std::net::ToSocketAddrs;

	let addrs = (host, port).to_socket_addrs().map_err(|e| format!("{:?}", e))?;
	for addr in addrs {
		if let SocketAddr::V4(_) = addr {
			return Ok(addr)
		}
	}

	Err("Cannot lookup address".to_string())
}
