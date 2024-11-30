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
	trusted_command_utils::{get_accountid_from_str, get_identifiers, get_pair_from_str},
	trusted_operation::{perform_trusted_operation, send_direct_request},
	Cli, CliResult, CliResultOk,
};
use base58::ToBase58;
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
pub struct TransferCommand {
	/// sender's AccountId in ss58check format, mnemonic or hex seed
	from: String,

	/// recipient's AccountId in ss58check format
	to: String,

	/// amount to be transferred
	amount: Balance,

	/// an optional note for the recipient to pass along with the funds
	note: Option<String>,

	/// session proxy who can sign on behalf of the account
	#[clap(long)]
	session_proxy: Option<String>,
}

impl TransferCommand {
	pub(crate) fn run(&self, cli: &Cli, trusted_args: &TrustedCli) -> CliResult {
		let from = get_accountid_from_str(&self.from);
		let to = get_accountid_from_str(&self.to);
		info!("from ss58 is {}", from.to_ss58check());
		info!("to ss58 is {}", to.to_ss58check());
		let signer = self
			.session_proxy
			.as_ref()
			.map(|proxy| get_pair_from_str(trusted_args, proxy.as_str()))
			.unwrap_or_else(|| get_pair_from_str(trusted_args, &self.from));
		info!("signer ss58 is {}", signer.public().to_ss58check());

		let (mrenclave, shard) = get_identifiers(trusted_args);
		let nonce = get_layer_two_nonce!(from, signer, cli, trusted_args);
		println!(
            "send trusted call transfer from {} to {}: {}, nonce: {}, signing using mrenclave: {} and shard: {}",
            from,
            to,
            self.amount,
            nonce, mrenclave.to_base58(), shard.0.to_base58()
        );
		let top: TrustedOperation<TrustedCallSigned, Getter> = if let Some(note) = &self.note {
			TrustedCall::balance_transfer_with_note(from, to, self.amount, note.as_bytes().into())
				.sign(&KeyPair::Sr25519(Box::new(signer)), nonce, &mrenclave, &shard)
				.into_trusted_operation(trusted_args.direct)
		} else {
			TrustedCall::balance_transfer(from, to, self.amount)
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
