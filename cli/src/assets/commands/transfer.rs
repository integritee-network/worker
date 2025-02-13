/*
	Copyright 2021 Integritee AG

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
	command_utils::{get_accountid_from_str, get_target_b_chain_api, *},
	Cli, CliResult, CliResultOk,
};
use codec::{Compact, Encode};
use ita_assets_map::{AssetId, AssetTranslation};
use ita_parentchain_interface::integritee::Balance;
use itp_types::parentchain::AccountId;
use log::*;
use sp_core::{crypto::Ss58Codec, Pair};
use sp_runtime::MultiAddress;
use substrate_api_client::{ac_compose_macros::compose_extrinsic, SubmitAndWatch, XtStatus};

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
}

impl TransferCommand {
	pub(crate) fn run(&self, cli: &Cli) -> CliResult {
		let from_account = get_pair_from_str(&self.from);
		let to_account = get_accountid_from_str(&self.to);
		let asset_id = AssetId::try_from(self.asset_id.clone().as_str()).expect("Invalid asset id");
		let mut api = get_target_b_chain_api(cli);
		let location = asset_id.into_location(api.genesis_hash()).unwrap();
		info!("from ss58 is {}", from_account.public().to_ss58check());
		info!("to ss58 is {}", to_account.to_ss58check());
		info!("Amount {}", self.amount);
		info!("AssetId {} location is {:?}", asset_id, location);

		api.set_signer(from_account.into());
		let assets_pallet_instance = asset_id.reserve_instance().unwrap();
		let xt = compose_extrinsic!(
			api,
			assets_pallet_instance,
			"transfer",
			location,
			MultiAddress::<AccountId, ()>::Id(to_account),
			Compact(self.amount)
		);
		info!("encoded call: {}", hex::encode(xt.function.encode()));
		let tx_report = api.submit_and_watch_extrinsic_until(xt, XtStatus::InBlock).unwrap();
		println!(
			"[+] L1 extrinsic success. extrinsic hash: {:?} / status: {:?}",
			tx_report.extrinsic_hash, tx_report.status
		);
		Ok(CliResultOk::None)
	}
}
