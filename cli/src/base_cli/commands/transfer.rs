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
use itp_node_api::api_client::{Address, ParentchainExtrinsicSigner};
use log::*;
use my_node_runtime::Balance;
use sp_core::{crypto::Ss58Codec, sr25519 as sr25519_core, Pair};
use substrate_api_client::{
	extrinsic::BalancesExtrinsics, GetAccountInformation, SubmitAndWatchUntilSuccess,
};

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
	pub(crate) fn run(&self, cli: &Cli) -> CliResult {
		let from_account = get_pair_from_str(&self.from);
		let to_account = get_accountid_from_str(&self.to);
		info!("from ss58 is {}", from_account.public().to_ss58check());
		info!("to ss58 is {}", to_account.to_ss58check());
		let mut api = get_chain_api(cli);
		api.set_signer(ParentchainExtrinsicSigner::new(sr25519_core::Pair::from(from_account)));
		let xt = api.balance_transfer_allow_death(Address::Id(to_account.clone()), self.amount);
		let tx_report = api.submit_and_watch_extrinsic_until_success(xt, false).unwrap();
		println!(
			"[+] L1 extrinsic success. extrinsic hash: {:?} / status: {:?}",
			tx_report.extrinsic_hash, tx_report.status
		);
		let result = api.get_account_data(&to_account).unwrap().unwrap();
		let balance = result.free;
		println!("balance for {} is now {}", to_account, balance);

		Ok(CliResultOk::Balance { balance })
	}
}
