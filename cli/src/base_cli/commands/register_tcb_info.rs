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
	Cli, CliResult, CliResultOk,
};
use itp_node_api::api_client::TEEREX;
use itp_types::{parentchain::Hash, OpaqueCall};
use itp_utils::ToHexPrefixed;
use log::*;
use regex::Regex;
use serde::Deserialize;
use substrate_api_client::{
	ac_compose_macros::{compose_call, compose_extrinsic_offline},
	SubmitAndWatch, XtStatus,
};
use urlencoding;

#[derive(Debug, Deserialize)]
struct Platform {
	fmspc: String,
	#[serde(rename = "platform")]
	_platform: String,
}

#[derive(Parser)]
pub struct RegisterTcbInfoCommand {
	/// Sender's parentchain AccountId in ss58check format.
	sender: String,
	/// Intel's Family-Model-Stepping-Platform-Custom SKU. 6-Byte non-prefixed hex value
	#[clap(short, long, action, conflicts_with = "all")]
	fmspc: Option<String>,
	/// registers all fmspc currently published by Intel
	#[clap(short, long, action)]
	all: bool,
}

impl RegisterTcbInfoCommand {
	pub(crate) fn run(&self, cli: &Cli) -> CliResult {
		let mut chain_api = get_chain_api(cli);

		// Get the sender.
		let from = get_pair_from_str(&self.sender);
		chain_api.set_signer(from.into());

		let fmspcs = if self.all {
			trace!("fetching all fmspc's from api.trustedservices.intel.com");
			let fmspcs = reqwest::blocking::get(
				"https://api.trustedservices.intel.com/sgx/certification/v4/fmspcs",
			)
			.unwrap();
			let fmspcs: Vec<Platform> = fmspcs.json().expect("Error parsing JSON");
			println!("{:?}", fmspcs);
			fmspcs.into_iter().map(|f| f.fmspc).collect()
		} else if let Some(fmspc) = self.fmspc.clone() {
			vec![fmspc]
		} else {
			panic!("must specify either '--all' or '--fmspc'");
		};
		let mut nonce = chain_api.get_nonce().unwrap();
		let xt_hashes: Vec<(String, Option<Hash>)> = fmspcs
			.into_iter()
			.map(|fmspc| {
				println!(
					"fetching tcb info for fmspc {} from api.trustedservices.intel.com",
					fmspc
				);
				let response = reqwest::blocking::get(format!(
					"https://api.trustedservices.intel.com/sgx/certification/v4/tcb?fmspc={}",
					fmspc
				))
				.unwrap();
				//extract certificate chain from header
				let certificate_chain = urlencoding::decode(
					response.headers().get("TCB-Info-Issuer-Chain").unwrap().to_str().unwrap(),
				)
				.unwrap()
				.to_string();
				trace!("certificate chain: \n{}", certificate_chain);

				let body = response.text().unwrap();
				trace!("raw json: \n{}", body);
				let re = Regex::new(r#"tcbInfo\"\s?:(\{.*\}),\s?\"signature"#).unwrap();
				let tcb_info = &re.captures(&body).unwrap()[1];
				let re = Regex::new(r#"\"signature\"\s?:\s?\"(.*)\"\}"#).unwrap();
				let intel_signature_hex = &re.captures(&body).unwrap()[1];
				trace!("TCB info: {}", tcb_info);
				trace!("signature: {}", intel_signature_hex);

				let intel_signature = hex::decode(intel_signature_hex).unwrap();

				let call = OpaqueCall::from_tuple(&compose_call!(
					chain_api.metadata(),
					TEEREX,
					"register_tcb_info",
					tcb_info,
					intel_signature,
					certificate_chain
				));

				trace!(
					"encoded call to be sent as extrinsic with nonce {}: {}",
					nonce,
					call.to_hex()
				);

				let xt = compose_extrinsic_offline!(
					chain_api.clone().signer().unwrap(),
					call,
					chain_api.extrinsic_params(nonce)
				);
				nonce += 1;
				match chain_api.submit_and_watch_extrinsic_until(xt, XtStatus::InBlock) {
					Ok(xt_report) => {
						println!(
							"[+] register_tcb_info. extrinsic hash: {:?} / status: {:?}",
							xt_report.extrinsic_hash, xt_report.status,
						);
						(fmspc, Some(xt_report.extrinsic_hash))
					},
					Err(e) => {
						error!("register_tcb_info extrinsic failed {:?}", e);
						(fmspc, None)
					},
				}
			})
			.collect();
		println!("{:?}", xt_hashes);
		Ok(CliResultOk::None)
	}
}
