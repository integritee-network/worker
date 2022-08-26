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
	Cli,
};
use log::*;
use my_node_runtime::Balance;
use sp_core::{crypto::Ss58Codec, sr25519 as sr25519_core, Pair};
use substrate_api_client::{GenericAddress, XtStatus};

#[derive(Parser)]
pub struct TransferCommand {
	/// sender's AccountId in ss58check format
	from: String,

	/// recipient's AccountId in ss58check format
	to: String,

	/// amount to be transferred
	amount: Balance,
}

impl TransferCommand {
	pub(crate) fn run(&self, cli: &Cli) {
		let from_account = get_pair_from_str(&self.from);
		let to_account = get_accountid_from_str(&self.to);
		info!("from ss58 is {}", from_account.public().to_ss58check());
		info!("to ss58 is {}", to_account.to_ss58check());
		let api = get_chain_api(cli).set_signer(sr25519_core::Pair::from(from_account));
		let xt = api.balance_transfer(GenericAddress::Id(to_account.clone()), self.amount);
		let tx_hash = api.send_extrinsic(xt.hex_encode(), XtStatus::InBlock).unwrap();
		println!("[+] TrustedOperation got finalized. Hash: {:?}\n", tx_hash);
		let result = api.get_account_data(&to_account).unwrap().unwrap();
		println!("balance for {} is now {}", to_account, result.free);
	}
}
