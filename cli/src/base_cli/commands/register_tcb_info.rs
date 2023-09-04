/*
	Copyright 2021 Integritee AG and Supercomputing Systems AG

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

use crate::{
	command_utils::{get_accountid_from_str, get_chain_api, *},
	Cli, CliError, CliResult, CliResultOk,
};
use base58::FromBase58;
use codec::{Decode, Encode};
use itp_attestation_handler::SgxQlQveCollateral;
use itp_node_api::api_client::{ParentchainExtrinsicSigner, TEEREX};
use itp_sgx_crypto::ShieldingCryptoEncrypt;
use itp_stf_primitives::types::ShardIdentifier;
use log::*;
use my_node_runtime::Balance;
use sgx_types::*;
use sp_core::sr25519 as sr25519_core;
use substrate_api_client::{compose_extrinsic, SubmitAndWatchUntilSuccess};
use teerex_primitives::Fmspc;

#[derive(Parser)]
pub struct RegisterTcbInfoCommand {
	/// Sender's parentchain AccountId in ss58check format.
	sender: String,
	/// Intel's Family-Model-Stepping-Platform-Custom SKU. 6-Byte `0x`-prefixed hex value
	fmspc: String,
}

impl RegisterTcbInfoCommand {
	pub(crate) fn run(&self, cli: &Cli) -> CliResult {
		let mut chain_api = get_chain_api(cli);

		// Get the sender.
		let from = get_pair_from_str(&self.sender);
		chain_api.set_signer(ParentchainExtrinsicSigner::new(sr25519_core::Pair::from(from)));

		let fmspc = Fmspc::decode(&mut hex::decode(&self.fmspc[2..]).unwrap().as_slice()).unwrap();

		let pck_ra = b"processor\x00";

		// SAFETY: Just get a nullptr for the FFI to overwrite later
		let mut collateral_ptr: *mut sgx_ql_qve_collateral_t = unsafe { std::mem::zeroed() };

		let collateral_ptr_ptr: *mut *mut sgx_ql_qve_collateral_t = &mut collateral_ptr;
		// SAFETY: All parameters are properly initialized so the FFI call should be fine
		let sgx_status = unsafe {
			sgx_ql_get_quote_verification_collateral(
				fmspc.as_ptr(),
				fmspc.len() as uint16_t, //fmspc len is fixed in the function signature
				pck_ra.as_ptr() as _,
				collateral_ptr_ptr,
			)
		};

		trace!("FMSPC: {:?}", hex::encode(fmspc));

		if collateral_ptr.is_null() {
			error!("PCK quote collateral data is null, sgx_status is: {}", sgx_status);
			return Err(CliError::Extrinsic { msg: format!("{:?}", sgx_status) })
		}

		// SAFETY: the previous block checks for `collateral_ptr` being null.
		// SAFETY: the fields should be nul terminated C strings.
		trace!("collateral: ");
		let collateral = unsafe {
			let collateral = &*collateral_ptr;
			trace!(
				"version: {}\n, \
				 tee_type: {}\n, \
				 pck_crl_issuer_chain: {:?}\n, \
				 pck_crl_issuer_chain_size: {}\n, \
				 root_ca_crl: {:?}\n, \
				 root_ca_crl_size: {}\n, \
				 pck_crl: {:?}\n, \
				 pck_crl_size: {}\n, \
				 tcb_info_issuer_chain: {:?}\n, \
				 tcb_info_issuer_chain_size: {}\n, \
				 tcb_info: {}\n, \
				 tcb_info_size: {}\n, \
				 qe_identity_issuer_chain: {:?}\n, \
				 qe_identity_issuer_chain_size: {}\n, \
				 qe_identity: {}\n, \
				 qe_identity_size: {}\n",
				collateral.version,
				collateral.tee_type,
				std::ffi::CStr::from_ptr(collateral.pck_crl_issuer_chain).to_string_lossy(),
				collateral.pck_crl_issuer_chain_size,
				std::ffi::CStr::from_ptr(collateral.root_ca_crl).to_string_lossy(),
				collateral.root_ca_crl_size,
				std::ffi::CStr::from_ptr(collateral.pck_crl).to_string_lossy(),
				collateral.pck_crl_size,
				std::ffi::CStr::from_ptr(collateral.tcb_info_issuer_chain).to_string_lossy(),
				collateral.tcb_info_issuer_chain_size,
				std::ffi::CStr::from_ptr(collateral.tcb_info).to_string_lossy(),
				collateral.tcb_info_size,
				std::ffi::CStr::from_ptr(collateral.qe_identity_issuer_chain).to_string_lossy(),
				collateral.qe_identity_issuer_chain_size,
				std::ffi::CStr::from_ptr(collateral.qe_identity).to_string_lossy(),
				collateral.qe_identity_size,
			);
			SgxQlQveCollateral::from_c_type(&*collateral_ptr)
		};

		let collateral_data = match collateral.get_tcb_info_split() {
			Some(d) => d,
			None => return Err(CliError::Extrinsic { msg: format!("could not split collateral") }),
		};
		// Compose the extrinsic.
		let xt = compose_extrinsic!(
			chain_api,
			TEEREX,
			"register_tcb_info",
			&collateral_data.0,
			&collateral_data.1,
			&collateral.qe_identity_issuer_chain
		);

		match chain_api.submit_and_watch_extrinsic_until_success(xt, true) {
			Ok(xt_report) => {
				println!(
					"[+] shield funds success. extrinsic hash: {:?} / status: {:?} / block hash: {:?}",
					xt_report.extrinsic_hash, xt_report.status, xt_report.block_hash.unwrap()
				);
				Ok(CliResultOk::H256 { hash: xt_report.block_hash.unwrap() })
			},
			Err(e) => {
				error!("shield_funds extrinsic failed {:?}", e);
				Err(CliError::Extrinsic { msg: format!("{:?}", e) })
			},
		}
	}
}
