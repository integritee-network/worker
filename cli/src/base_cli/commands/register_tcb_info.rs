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
	command_utils::{get_chain_api, *},
	Cli, CliError, CliResult, CliResultOk,
};
use itp_node_api::api_client::{ParentchainExtrinsicSigner, TEEREX};
use itp_utils::ToHexPrefixed;
use log::*;
use serde::Deserialize;
use serde_json::Value;
use sp_core::sr25519 as sr25519_core;
use std::fs::read_to_string;
use substrate_api_client::{compose_extrinsic, SubmitAndWatchUntilSuccess};

#[derive(Debug, Deserialize)]
struct TcbInfo {
	tcb_info: Value,
	signature: String,
}

#[derive(Parser)]
pub struct RegisterTcbInfoCommand {
	/// Sender's parentchain AccountId in ss58check format.
	sender: String,
	/// Intel's Family-Model-Stepping-Platform-Custom SKU. 6-Byte non-prefixed hex value
	fmspc: String,
	/// certificate chain PEM file
	pem_file: String,
}

impl RegisterTcbInfoCommand {
	pub(crate) fn run(&self, cli: &Cli) -> CliResult {
		let mut chain_api = get_chain_api(cli);

		let certificate_chain_pem = match read_to_string(&self.pem_file) {
			Ok(cert) => cert,
			Err(e) => panic!("Opening PEM file failed: {:#?}", e),
		};

		// Get the sender.
		let from = get_pair_from_str(&self.sender);
		chain_api.set_signer(ParentchainExtrinsicSigner::new(sr25519_core::Pair::from(from)));

		trace!("fetching tcb info from api.trustedservices.intel.com");

		let tcbinfo_json = reqwest::blocking::get(format!(
			"https://api.trustedservices.intel.com/sgx/certification/v4/tcb?fmspc={}",
			&self.fmspc
		))
		.unwrap();
		let tcb_info: TcbInfo = tcbinfo_json.json().expect("Error parsing JSON");
		let intel_signature = hex::decode(tcb_info.signature).unwrap();

		// Compose the extrinsic.
		let xt = compose_extrinsic!(
			chain_api,
			TEEREX,
			"register_tcb_info",
			tcb_info.tcb_info.to_string(),
			intel_signature,
			certificate_chain_pem
		);
		trace!("encoded call to be sent as extrinsic: {}", xt.function.to_hex());

		match chain_api.submit_and_watch_extrinsic_until_success(xt, true) {
			Ok(xt_report) => {
				println!(
					"[+] register_tcb_info. extrinsic hash: {:?} / status: {:?} / block hash: {:?}",
					xt_report.extrinsic_hash,
					xt_report.status,
					xt_report.block_hash.unwrap()
				);
				Ok(CliResultOk::H256 { hash: xt_report.block_hash.unwrap() })
			},
			Err(e) => {
				error!("register_tcb_info extrinsic failed {:?}", e);
				Err(CliError::Extrinsic { msg: format!("{:?}", e) })
			},
		}
	}
}
