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
use ita_parentchain_interface::integritee::Balance;
use ita_stf::{Getter, Index, TrustedCall, TrustedCallSigned};
use itp_stf_primitives::{
	traits::TrustedCallSigning,
	types::{KeyPair, TrustedOperation},
};
use log::*;
use sp_core::{crypto::Ss58Codec, Pair};
use std::boxed::Box;

#[derive(Parser)]
pub struct SetBalanceCommand {
	/// subject's AccountId in ss58check format, mnemonic or hex seed
	account: String,

	/// amount to be transferred
	amount: Balance,
}

impl SetBalanceCommand {
	pub(crate) fn run(&self, cli: &Cli, trusted_args: &TrustedCli) -> CliResult {
		let who = get_pair_from_str(trusted_args, &self.account);
		let signer = get_pair_from_str(trusted_args, "//Alice");
		info!("account ss58 is {}", who.public().to_ss58check());

		println!("send trusted call set-balance({}, {})", who.public(), self.amount);

		let (mrenclave, shard) = get_identifiers(trusted_args);
		let nonce = get_layer_two_nonce!(signer, cli, trusted_args);
		let top: TrustedOperation<TrustedCallSigned, Getter> = TrustedCall::balance_set_balance(
			signer.public().into(),
			who.public().into(),
			self.amount,
			self.amount,
		)
		.sign(&KeyPair::Sr25519(Box::new(signer)), nonce, &mrenclave, &shard)
		.into_trusted_operation(trusted_args.direct);
		Ok(perform_trusted_operation::<()>(cli, trusted_args, &top).map(|_| CliResultOk::None)?)
	}
}
