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
	command_utils::{get_accountid_from_str, get_chain_api},
	Cli,
};
use substrate_api_client::GetAccountInformation;

#[derive(Parser)]
pub struct BalanceCommand {
	/// AccountId in ss58check format
	account: String,
}

impl BalanceCommand {
	pub(crate) fn run(&self, cli: &Cli) {
		let api = get_chain_api(cli);
		let accountid = get_accountid_from_str(&self.account);
		let balance =
			if let Some(data) = api.get_account_data(&accountid).unwrap() { data.free } else { 0 };
		println!("{}", balance);
	}
}
