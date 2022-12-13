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
use sgx_types::sgx_ql_qve_collateral_t;
use std::{
	io::Write,
	string::{String, ToString},
	vec::Vec,
};

// This is a rust-ified version of the type sgx_ql_qve_collateral_t
pub struct SgxQlQveCollateral {
	pub version: u32, // version = 1.  PCK Cert chain is in the Quote.
	/* intel DCAP 1.13 */
	pub tee_type: u32, // 0x00000000: SGX or 0x00000081: TDX
	pub pck_crl_issuer_chain: Vec<u8>,
	pub root_ca_crl: Vec<u8>,
	pub pck_crl: Vec<u8>,
	pub tcb_info_issuer_chain: Vec<u8>,
	pub tcb_info: Vec<u8>,
	pub qe_identity_issuer_chain: Vec<u8>,
	pub qe_identity: Vec<u8>,
}

impl SgxQlQveCollateral {
	/// # Safety
	///
	/// The caller is in charge of ensuring that `c` is properly initialized and all
	/// its members have a value that is not nullptr
	pub unsafe fn from_c_type(c: &sgx_ql_qve_collateral_t) -> Self {
		let pck_crl_issuer_chain = std::slice::from_raw_parts(
			c.pck_crl_issuer_chain as *const u8,
			c.pck_crl_issuer_chain_size as usize,
		)
		.to_vec();
		let root_ca_crl =
			std::slice::from_raw_parts(c.root_ca_crl as *const u8, c.root_ca_crl_size as usize)
				.to_vec();
		let pck_crl =
			std::slice::from_raw_parts(c.pck_crl as *const u8, c.pck_crl_size as usize).to_vec();
		let tcb_info_issuer_chain = std::slice::from_raw_parts(
			c.tcb_info_issuer_chain as *const u8,
			c.tcb_info_issuer_chain_size as usize,
		)
		.to_vec();
		let tcb_info =
			std::slice::from_raw_parts(c.tcb_info as *const u8, c.tcb_info_size as usize).to_vec();
		let qe_identity_issuer_chain = std::slice::from_raw_parts(
			c.qe_identity_issuer_chain as *const u8,
			c.qe_identity_issuer_chain_size as usize,
		)
		.to_vec();
		let qe_identity =
			std::slice::from_raw_parts(c.qe_identity as *const u8, c.qe_identity_size as usize)
				.to_vec();
		SgxQlQveCollateral {
			version: c.version,
			tee_type: c.tee_type,
			pck_crl_issuer_chain,
			root_ca_crl,
			pck_crl,
			tcb_info_issuer_chain,
			tcb_info,
			qe_identity_issuer_chain,
			qe_identity,
		}
	}

	pub fn dump_to_disk(&self) {
		Self::write_data_to_disk("pck_crl_issuer_chain", &self.pck_crl_issuer_chain);
		Self::write_data_to_disk("root_ca_crl", &self.root_ca_crl);
		Self::write_data_to_disk("pck_crl", &self.pck_crl);
		Self::write_data_to_disk("tcb_info_issuer_chain", &self.tcb_info_issuer_chain);
		Self::write_data_to_disk("tcb_info", &self.tcb_info);
		Self::write_data_to_disk("qe_identity_issuer_chain", &self.qe_identity_issuer_chain);
		Self::write_data_to_disk("qe_identity", &self.qe_identity);
	}

	/// Returns the tcb_info split into two parts: json_data and signature
	pub fn get_tcb_info_split(&self) -> Option<(String, Vec<u8>)> {
		let (json_data, signature) =
			Self::separate_json_data_and_signature("tcbInfo", &self.tcb_info)?;
		match hex::decode(signature) {
			Ok(hex_signature) => Some((json_data, hex_signature)),
			Err(_) => None,
		}
	}

	/// Returns the tcb_info split into two parts: json_data and signature
	pub fn get_quoting_enclave_split(&self) -> Option<(String, Vec<u8>)> {
		let (json_data, signature) =
			Self::separate_json_data_and_signature("enclaveIdentity", &self.qe_identity)?;
		match hex::decode(signature) {
			Ok(hex_signature) => Some((json_data, hex_signature)),
			Err(_) => None,
		}
	}

	/// Separates the actual data part from the signature for an Intel collateral in JSON format
	/// Returns the data part and signature as a pair
	fn separate_json_data_and_signature(data_name: &str, data: &[u8]) -> Option<(String, String)> {
		let json = String::from_utf8_lossy(data);
		// search pattern is something like `{"tcbInfo":`. Should be at the very beginning
		let search_pattern = format!("{{\"{}\":", data_name);
		let json = json.replace(&search_pattern, "");

		let parts = json.split(r#","signature":""#).collect::<Vec<&str>>();
		if parts.len() != 2 || parts[1].len() < 2 {
			return None
		}
		let data = &parts[0];
		let signature = &parts[1][0..parts[1].len() - 3]; // Remove the two last chars that 'close' the json
		Some((data.to_string(), signature.to_string()))
	}

	fn write_data_to_disk(filename: &str, contents: &[u8]) {
		let mut file = std::fs::File::create(filename).unwrap();
		file.write_all(contents).unwrap();
	}
}
