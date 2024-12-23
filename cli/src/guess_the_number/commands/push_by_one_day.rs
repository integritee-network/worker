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
	get_layer_two_nonce,
	trusted_cli::TrustedCli,
	trusted_command_utils::{get_identifiers, get_pair_from_str},
	trusted_operation::perform_trusted_operation,
	Cli, CliResult, CliResultOk,
};

use crate::trusted_operation::send_direct_request;
use ita_stf::{
	guess_the_number::GuessTheNumberTrustedCall, Getter, TrustedCall, TrustedCallSigned,
};
use itp_stf_primitives::{
	traits::TrustedCallSigning,
	types::{AccountId, KeyPair, TrustedOperation},
};
use log::*;
use sp_core::Pair;
use std::boxed::Box;

#[derive(Parser)]
pub struct PushByOneDayCommand {
	/// sender's AccountId in ss58check format, mnemonic or hex seed. must by authorized as GuessMaster
	master: String,
}

impl PushByOneDayCommand {
	pub(crate) fn run(&self, cli: &Cli, trusted_args: &TrustedCli) -> CliResult {
		let signer = get_pair_from_str(trusted_args, &self.master);

		println!("send trusted call guess-the-number push by one day");

		let (mrenclave, shard) = get_identifiers(trusted_args);
		let subject: AccountId = signer.public().into();
		let nonce = get_layer_two_nonce!(subject, signer, cli, trusted_args);
		let top: TrustedOperation<TrustedCallSigned, Getter> = TrustedCall::guess_the_number(
			GuessTheNumberTrustedCall::push_by_one_day(signer.public().into()),
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
