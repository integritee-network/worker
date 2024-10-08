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
	command_utils::{get_chain_api, get_pair_from_str, mrenclave_from_base58},
	Cli,
};
use itp_node_api::api_client::{ADD_TO_WHITELIST, TEERACLE};
use substrate_api_client::{
	ac_compose_macros::{compose_call, compose_extrinsic},
	SubmitAndWatch, XtStatus,
};

/// Add a trusted market data source to the on-chain whitelist.
#[derive(Debug, Clone, Parser)]
pub struct AddToWhitelistCmd {
	/// Sender's on-chain AccountId in ss58check format, mnemonic or hex seed.
	///
	/// It has to be a sudo account.
	from: String,

	/// Market data URL
	source: String,

	/// MRENCLAVE of the oracle worker base58 encoded.
	mrenclave: String,
}

impl AddToWhitelistCmd {
	pub fn run(&self, cli: &Cli) {
		let mut api = get_chain_api(cli);
		let mrenclave = mrenclave_from_base58(&self.mrenclave);
		let from = get_pair_from_str(&self.from);

		let market_data_source = self.source.clone();

		api.set_signer(from.into());

		let call = compose_call!(
			api.metadata(),
			TEERACLE,
			ADD_TO_WHITELIST,
			market_data_source,
			mrenclave
		);

		// compose the extrinsic
		let xt = compose_extrinsic!(api, "Sudo", "sudo", call);

		let report = api.submit_and_watch_extrinsic_until(xt, XtStatus::Finalized).unwrap();
		println!("[+] Add to whitelist got finalized. Hash: {:?}\n", report.extrinsic_hash);
	}
}
