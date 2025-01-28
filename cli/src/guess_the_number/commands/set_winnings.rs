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
	trusted_command_utils::{get_identifiers, get_trusted_account_info},
	trusted_operation::{perform_trusted_operation, send_direct_request},
	Cli, CliResult, CliResultOk,
};
use ita_parentchain_interface::integritee::Balance;
use ita_stf::{
	guess_the_number::GuessTheNumberTrustedCall, Getter, TrustedCall, TrustedCallSigned,
};
use itp_stf_primitives::{
	traits::TrustedCallSigning,
	types::{KeyPair, TrustedOperation},
};
use log::*;
use sp_core::{crypto::Ss58Codec, Pair};
use std::boxed::Box;

#[derive(Parser)]
pub struct SetWinningsCommand {
	/// sender's AccountId in ss58check format, mnemonic or hex seed. must by authorized as GuessMaster
	master: String,
	/// amount to be transferred
	winnings: Balance,
	/// session proxy who can sign on behalf of the account
	#[clap(long)]
	session_proxy: Option<String>,
}

impl SetWinningsCommand {
	pub(crate) fn run(&self, cli: &Cli, trusted_args: &TrustedCli) -> CliResult {
		let (sender, signer) =
			get_sender_and_signer_from_args!(self.master, self.session_proxy, trusted_args);

		println!(
			"send trusted call guess-the-number set winnings. sender {}, signer {}, winnings {})",
			sender.to_ss58check(),
			signer.public().to_ss58check(),
			self.winnings
		);

		let (mrenclave, shard) = get_identifiers(trusted_args);

		let nonce = get_trusted_account_info(cli, trusted_args, &sender, &signer)
			.map(|info| info.nonce)
			.unwrap_or_default();

		let top: TrustedOperation<TrustedCallSigned, Getter> = TrustedCall::guess_the_number(
			GuessTheNumberTrustedCall::set_winnings(signer.public().into(), self.winnings),
		)
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
