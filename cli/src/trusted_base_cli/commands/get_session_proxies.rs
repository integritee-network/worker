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
	trusted_cli::TrustedCli, trusted_command_utils::get_pair_from_str,
	trusted_operation::perform_trusted_operation, Cli, CliResult, CliResultOk,
};
use ita_stf::{AccountEssentials, Getter, TrustedCallSigned, TrustedGetter};
use itp_stf_primitives::types::{KeyPair, TrustedOperation};
use log::info;

use sp_core::Pair;

#[derive(Parser)]
pub struct GetSessionProxiesCommand {
	/// AccountId in ss58check format, mnemonic or hex seed
	account: String,
}

impl GetSessionProxiesCommand {
	pub(crate) fn run(&self, cli: &Cli, trusted_args: &TrustedCli) -> CliResult {
		let who = get_pair_from_str(cli, trusted_args, self.account.as_str());
		let top = TrustedOperation::<TrustedCallSigned, Getter>::get(Getter::trusted(
			TrustedGetter::account_essentials(who.public().into())
				.sign(&KeyPair::Sr25519(Box::new(who))),
		));
		let data = perform_trusted_operation::<AccountEssentials>(cli, trusted_args, &top).unwrap();
		info!("Account essentials: {:?}", data);
		for proxy in &data.session_proxies {
			println!("{:?}", proxy);
		}
		Ok(CliResultOk::AccountEssentials { value: data })
	}
}
