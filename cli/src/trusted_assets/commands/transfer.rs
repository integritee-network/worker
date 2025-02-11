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
use base58::ToBase58;
use ita_assets_map::AssetId;
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
pub struct TransferCommand {
	/// sender's AccountId in ss58check format, mnemonic or hex seed
	from: String,

	/// recipient's AccountId in ss58check format
	to: String,

	/// amount to be transferred
	amount: Balance,

	/// Asset ID. must be supported. i.e. 'USDC.e'
	asset_id: String,

	/// an optional note for the recipient to pass along with the funds
	note: Option<String>,

	/// session proxy who can sign on behalf of the account
	#[clap(long)]
	session_proxy: Option<String>,
}

impl TransferCommand {
	pub(crate) fn run(&self, cli: &Cli, trusted_args: &TrustedCli) -> CliResult {
		let (sender, signer, mrenclave, shard) =
			get_basic_signing_info_from_args!(self.from, self.session_proxy, cli, trusted_args);
		let to = get_accountid_from_str(&self.to);
		let asset_id = AssetId::try_from(self.asset_id.clone().as_str()).expect("Invalid asset id");
		info!("from ss58 is {}", sender.to_ss58check());
		info!("to ss58 is {}", to.to_ss58check());
		info!("asset_id is {}", asset_id);

		let nonce = get_trusted_account_info(cli, trusted_args, &sender, &signer)
			.map(|info| info.nonce)
			.unwrap_or_default();

		println!(
            "send trusted call transfer asset from {} to {}: {} {}, nonce: {}, signing using mrenclave: {} and shard: {}",
            sender,
            to,
            self.amount,
			asset_id,
            nonce, mrenclave.to_base58(), shard.0.to_base58()
        );
		let top: TrustedOperation<TrustedCallSigned, Getter> = if let Some(note) = &self.note {
			TrustedCall::assets_transfer_with_note(
				sender,
				to,
				asset_id,
				self.amount,
				note.as_bytes().into(),
			)
			.sign(&KeyPair::Sr25519(Box::new(signer)), nonce, &mrenclave, &shard)
			.into_trusted_operation(trusted_args.direct)
		} else {
			TrustedCall::assets_transfer(sender, to, asset_id, self.amount)
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
