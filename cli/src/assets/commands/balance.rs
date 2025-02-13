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
	command_utils::{get_accountid_from_str, get_chain_api},
	Cli, CliResult, CliResultOk,
};
use ita_assets_map::{AssetId, AssetTranslation, FOREIGN_ASSETS, NATIVE_ASSETS};
use itp_types::parentchain::AssetAccount;
use log::info;
use substrate_api_client::GetStorage;

#[derive(Parser)]
pub struct BalanceCommand {
	/// AccountId in ss58check format, mnemonic or hex seed
	account: String,
	/// Asset ID. must be supported. i.e. 'USDC.e'
	asset_id: String,
}

impl BalanceCommand {
	pub(crate) fn run(&self, cli: &Cli) -> CliResult {
		let api = get_chain_api(cli);
		let accountid = get_accountid_from_str(&self.account);
		let asset_id = AssetId::try_from(self.asset_id.clone().as_str()).expect("Invalid asset id");
		let asset_account: AssetAccount =
			match asset_id.reserve_instance().expect("Invalid asset reserve") {
				FOREIGN_ASSETS => api
					.get_storage_double_map(
						FOREIGN_ASSETS,
						"Account",
						asset_id.into_location(api.genesis_hash()).expect("Invalid asset"),
						accountid,
						None,
					)
					.unwrap()
					.unwrap_or_default(),
				NATIVE_ASSETS => api
					.get_storage_double_map(
						FOREIGN_ASSETS,
						"Account",
						asset_id.into_asset_hub_index(api.genesis_hash()).expect("Invalid asset"),
						accountid,
						None,
					)
					.unwrap()
					.unwrap_or_default(),
				_ => panic!("Invalid asset reserve"),
			};
		info!("{:?}", asset_account);
		println!("{}", asset_account.balance);
		Ok(CliResultOk::Balance { balance: asset_account.balance })
	}
}
