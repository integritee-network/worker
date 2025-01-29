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
	get_basic_signing_info_from_args,
	trusted_cli::TrustedCli,
	trusted_command_utils::get_trusted_account_info,
	trusted_operation::{perform_trusted_operation, send_direct_request},
	Cli, CliResult, CliResultOk,
};
use ita_stf::{Getter, TrustedCall, TrustedCallSigned};
use itp_stf_primitives::{
	traits::TrustedCallSigning,
	types::{KeyPair, TrustedOperation},
};
use log::*;
use std::boxed::Box;

#[derive(Parser)]
pub struct NoteBloatCommand {
	/// subject's AccountId in ss58check format. must have maintainer privilege
	maintainer: String,

	/// kilobytes of notes to store
	kilobytes: u32,

	/// session proxy who can sign on behalf of the account
	#[clap(long)]
	session_proxy: Option<String>,
}

impl NoteBloatCommand {
	pub(crate) fn run(&self, cli: &Cli, trusted_args: &TrustedCli) -> CliResult {
		let (sender, signer, mrenclave, shard) = get_basic_signing_info_from_args!(
			self.maintainer,
			self.session_proxy,
			cli,
			trusted_args
		);

		println!("send trusted call note-bloat({}kB)", self.kilobytes);

		let nonce = get_trusted_account_info(cli, trusted_args, &sender, &signer)
			.map(|info| info.nonce)
			.unwrap_or_default();
		let top: TrustedOperation<TrustedCallSigned, Getter> =
			TrustedCall::note_bloat(sender, self.kilobytes)
				.sign(&KeyPair::Sr25519(Box::new(signer)), nonce, &mrenclave, &shard)
				.into_trusted_operation(trusted_args.direct);

		if trusted_args.direct {
			Ok(send_direct_request(cli, trusted_args, &top).map(|_| CliResultOk::None)?)
		} else {
			Ok(perform_trusted_operation::<()>(cli, trusted_args, &top)
				.map(|_| CliResultOk::None)?)
		}
	}
}
