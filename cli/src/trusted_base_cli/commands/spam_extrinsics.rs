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
use itp_types::parentchain::ParentchainId;
use log::*;
use sp_core::Pair;
use std::boxed::Box;

#[derive(Parser)]
pub struct SpamExtrinsicsCommand {
	/// subject's AccountId in ss58check format. must have maintainer privilege
	maintainer: String,
	/// session proxy who can sign on behalf of the account
	#[clap(long)]
	session_proxy: Option<String>,

	/// number of xt to send to parentchain
	number: u32,

	/// parentchain to spam
	parentchain_id: ParentchainId,
}

impl SpamExtrinsicsCommand {
	pub(crate) fn run(&self, cli: &Cli, trusted_args: &TrustedCli) -> CliResult {
		let (sender, signer, mrenclave, shard) = get_basic_signing_info_from_args!(
			self.maintainer,
			self.session_proxy,
			cli,
			trusted_args
		);

		println!(
			"send trusted call spam-extrinsics ({} xt to {:?})",
			self.number, self.parentchain_id
		);

		let nonce = get_trusted_account_info(cli, trusted_args, &sender, &signer)
			.map(|info| info.nonce)
			.unwrap_or_default();

		let top: TrustedOperation<TrustedCallSigned, Getter> =
			TrustedCall::spam_extrinsics(signer.public().into(), self.number, self.parentchain_id)
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
