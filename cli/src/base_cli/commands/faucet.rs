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
use my_node_runtime::{BalancesCall, RuntimeCall};
use sp_keyring::AccountKeyring;
use sp_runtime::MultiAddress;
use std::vec::Vec;
use substrate_api_client::{compose_extrinsic_offline, UncheckedExtrinsicV4, XtStatus};

const PREFUNDING_AMOUNT: u128 = 1_000_000_000;

#[derive(Parser)]
pub struct FaucetCommand {
	/// Account(s) to be funded, ss58check encoded
	#[clap(min_values = 1, required = true)]
	accounts: Vec<String>,
}

impl FaucetCommand {
	pub(crate) fn run(&self, cli: &Cli) {
		let api = get_chain_api(cli).set_signer(AccountKeyring::Alice.pair());
		let mut nonce = api.get_nonce().unwrap();
		for account in &self.accounts {
			let to = get_accountid_from_str(account);
			#[allow(clippy::redundant_clone)]
			let xt: UncheckedExtrinsicV4<_, _> = compose_extrinsic_offline!(
				api.clone().signer.unwrap(),
				RuntimeCall::Balances(BalancesCall::transfer {
					dest: MultiAddress::Id(to.clone()),
					value: PREFUNDING_AMOUNT
				}),
				api.extrinsic_params(nonce)
			);
			// send and watch extrinsic until finalized
			println!("Faucet drips to {} (Alice's nonce={})", to, nonce);
			let _blockh = api.send_extrinsic(xt.hex_encode(), XtStatus::Ready).unwrap();
			nonce += 1;
		}
	}
}
