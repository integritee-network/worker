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
	get_sender_and_signer_from_args,
	trusted_cli::TrustedCli,
	trusted_command_utils::{get_pair_from_str, get_trusted_account_info},
	Cli, CliResult, CliResultOk,
};

#[derive(Parser)]
pub struct BalanceCommand {
	/// AccountId in ss58check format, mnemonic or hex seed
	account: String,
	/// session proxy who can sign on behalf of the account
	#[clap(long)]
	session_proxy: Option<String>,
}

impl BalanceCommand {
	pub(crate) fn run(&self, cli: &Cli, trusted_args: &TrustedCli) -> CliResult {
		let (sender, signer) =
			get_sender_and_signer_from_args!(self.account, self.session_proxy, trusted_args);

		let balance = get_trusted_account_info(cli, trusted_args, &sender, &signer)
			.unwrap_or_default()
			.data
			.free;
		println!("{}", balance);
		Ok(CliResultOk::Balance { balance })
	}
}
