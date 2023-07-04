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
	command_utils::{get_accountid_from_str, get_chain_api, *},
	Cli, CliResult, CliResultOk,
};
use base58::FromBase58;
use codec::{Decode, Encode};
use itp_node_api::api_client::{ParentchainExtrinsicSigner, TEEREX};
use itp_sgx_crypto::ShieldingCryptoEncrypt;
use itp_stf_primitives::types::ShardIdentifier;
use log::*;
use my_node_runtime::Balance;
use sp_core::sr25519 as sr25519_core;
use substrate_api_client::{compose_extrinsic, SubmitAndWatch, XtStatus};

#[derive(Parser)]
pub struct ShieldFundsCommand {
	/// Sender's parentchain AccountId in ss58check format.
	from: String,
	/// Recipient's incognito AccountId in ss58check format.
	to: String,
	/// Amount to be transferred.
	amount: Balance,
	/// Shard identifier.
	shard: String,
}

impl ShieldFundsCommand {
	pub(crate) fn run(&self, cli: &Cli) -> CliResult {
		let mut chain_api = get_chain_api(cli);

		let shard_opt = match self.shard.from_base58() {
			Ok(s) => ShardIdentifier::decode(&mut &s[..]),
			_ => panic!("shard argument must be base58 encoded"),
		};

		let shard = match shard_opt {
			Ok(shard) => shard,
			Err(e) => panic!("{}", e),
		};

		// Get the sender.
		let from = get_pair_from_str(&self.from);
		chain_api.set_signer(ParentchainExtrinsicSigner::new(sr25519_core::Pair::from(from)));

		// Get the recipient.
		let to = get_accountid_from_str(&self.to);

		let encryption_key = get_shielding_key(cli).unwrap();
		let encrypted_recevier = encryption_key.encrypt(&to.encode()).unwrap();

		// Compose the extrinsic.
		let xt = compose_extrinsic!(
			chain_api,
			TEEREX,
			"shield_funds",
			encrypted_recevier,
			self.amount,
			shard
		);

		let tx_hash = chain_api.submit_and_watch_extrinsic_until(xt, XtStatus::Finalized).unwrap();
		println!("[+] TrustedOperation got finalized. Hash: {:?}\n", tx_hash);

		Ok(CliResultOk::None)
	}
}
