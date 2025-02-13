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
	trusted_command_utils::{get_accountid_from_str, get_trusted_account_info},
	trusted_operation::{perform_trusted_operation, send_direct_request},
	Cli, CliResult, CliResultOk,
};
use ita_parentchain_interface::integritee::Balance;
use ita_stf::{Getter, TrustedCall, TrustedCallSigned};
use itp_stf_primitives::{
	traits::TrustedCallSigning,
	types::{KeyPair, TrustedOperation},
};
use log::*;
use sp_core::crypto::Ss58Codec;
use std::boxed::Box;

#[derive(Parser)]
pub struct UnshieldFundsCommand {
	/// Sender's incognito AccountId in ss58check format, mnemonic or hex seed
	from: String,

	/// Recipient's parentchain AccountId in ss58check format
	to: String,

	/// amount to be transferred
	amount: Balance,

	/// use enclave bridge instead of shard vault account. Only do this if you know what you're doing
	#[clap(short, long, action)]
	enclave_bridge: bool,

	/// session proxy who can sign on behalf of the account
	#[clap(long)]
	session_proxy: Option<String>,
}

impl UnshieldFundsCommand {
	pub(crate) fn run(&self, cli: &Cli, trusted_args: &TrustedCli) -> CliResult {
		let (sender, signer, mrenclave, shard) =
			get_basic_signing_info_from_args!(self.from, self.session_proxy, cli, trusted_args);
		let to = get_accountid_from_str(&self.to);

		println!(
			"send trusted call unshield_funds from {} to {}: {} {}",
			sender.to_ss58check(),
			to.to_ss58check(),
			self.amount,
			if self.enclave_bridge { "through enclave-bridge" } else { "" }
		);

		let nonce = get_trusted_account_info(cli, trusted_args, &sender, &signer)
			.map(|info| info.nonce)
			.unwrap_or_default();

		let top: TrustedOperation<TrustedCallSigned, Getter> = if self.enclave_bridge {
			TrustedCall::balance_unshield_through_enclave_bridge_pallet(
				sender,
				to,
				self.amount,
				shard,
			)
			.sign(&KeyPair::Sr25519(Box::new(signer)), nonce, &mrenclave, &shard)
			.into_trusted_operation(trusted_args.direct)
		} else {
			TrustedCall::balance_unshield(sender, to, self.amount, shard)
				.sign(&KeyPair::Sr25519(Box::new(signer)), nonce, &mrenclave, &shard)
				.into_trusted_operation(trusted_args.direct)
		};

		if trusted_args.direct {
			Ok(send_direct_request(cli, trusted_args, &top).map(|_| CliResultOk::None)?)
		} else {
			Ok(perform_trusted_operation::<()>(cli, trusted_args, &top)
				.map(|_| CliResultOk::None)?)
		}
	}
}
