/*
	Copyright 2021 Integritee AG

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
	trusted_cli::TrustedCli,
	trusted_command_utils::{get_pair_from_str, get_trusted_account_info},
	Cli, CliResult, CliResultOk,
};

use sp_application_crypto::sr25519;
use sp_core::crypto::Ss58Codec;
use std::time::Instant;

#[derive(Parser)]
pub struct WatchdogCommand {
	/// watchdog AccountId in ss58check format. must have enough funds on shard
	account: String,
	/// session proxy who can sign on behalf of the account
	#[clap(long)]
	session_proxy: Option<String>,
}

impl WatchdogCommand {
	pub(crate) fn run(&self, cli: &Cli, trusted_args: &TrustedCli) -> CliResult {
		let sender: itp_stf_primitives::types::AccountId =
			sr25519::Public::from_ss58check(self.account.as_str()).unwrap().into();
		let signer = self
			.session_proxy
			.as_ref()
			.map(|proxy| get_pair_from_str(trusted_args, proxy.as_str()))
			.unwrap_or_else(|| get_pair_from_str(trusted_args, self.account.as_str()));

		let getter_start_timer = Instant::now();
		let _info = get_trusted_account_info(cli, trusted_args, &sender, &signer)
			.map(|info| info.nonce)
			.unwrap_or_default();
		let getter_duration = getter_start_timer.elapsed();
		println!("Getting AccountInfo took {}ms", getter_duration.as_millis());
		Ok(CliResultOk::None)
	}
}
