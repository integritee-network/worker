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
use codec::Encode;
use ita_parentchain_interface::integritee::Balance;
use itp_utils::hex::hex_encode;
use log::*;
use sp_core::{crypto::Ss58Codec, Pair};
use substrate_api_client::{
	extrinsic::BalancesExtrinsics, GetAccountInformation, SubmitAndWatch, XtStatus,
};

#[derive(Parser)]
pub struct TransferCommand {
	/// sender's AccountId in ss58check format, mnemonic or hex seed
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
		let result = if api.metadata().pallet_by_name("AssetTxPayment").is_some() {
			// if the chain uses AssetTip, we need to use a different API type
			debug!("using AssetTip API");
			let mut api = get_target_b_chain_api(cli);
			api.set_signer(from_account.into());
			let xt = api.balance_transfer_allow_death(to_account.clone().into(), self.amount);
			debug!("encoded call: {}", hex_encode(xt.function.encode().as_slice()));
			debug!("encoded extrinsic will be sent: {}", hex_encode(xt.encode().as_slice()));
			let tx_report = api.submit_and_watch_extrinsic_until(xt, XtStatus::InBlock).unwrap();
			println!(
				"[+] L1 extrinsic success. extrinsic hash: {:?} / status: {:?}",
				tx_report.extrinsic_hash, tx_report.status
			);
			api.get_account_data(&to_account).unwrap().unwrap()
		} else {
			debug!("using PlainTip API");
			api.set_signer(from_account.into());
			let xt = api.balance_transfer_allow_death(to_account.clone().into(), self.amount);
			debug!("encoded call: {}", hex_encode(xt.function.encode().as_slice()));
			debug!("encoded extrinsic will be sent: {}", hex_encode(xt.encode().as_slice()));
			let tx_report = api.submit_and_watch_extrinsic_until(xt, XtStatus::InBlock).unwrap();
			println!(
				"[+] L1 extrinsic success. extrinsic hash: {:?} / status: {:?}",
				tx_report.extrinsic_hash, tx_report.status
			);
			api.get_account_data(&to_account).unwrap().unwrap()
		};
		let balance = result.free;
		println!("balance for {} is now {}", to_account, balance);

		Ok(CliResultOk::Balance { balance })
	}
}
