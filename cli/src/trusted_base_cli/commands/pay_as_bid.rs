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
	trusted_cli::TrustedCli, trusted_command_utils::get_pair_from_str,
	trusted_operation::perform_trusted_operation, Cli,
};
use codec::Decode;
use ita_stf::{TrustedGetter, TrustedOperation};
use itp_stf_primitives::types::KeyPair;
use log::{debug, info};
use simplyr_lib::MarketOutput;
use sp_core::Pair;

#[derive(Parser)]
pub struct PayAsBidCommand {
	/// AccountId in ss58check format
	account: String,
}

impl PayAsBidCommand {
	pub(crate) fn run(&self, cli: &Cli, trusted_args: &TrustedCli) {
		println!("Result: {:?}", pay_as_bid(cli, trusted_args, &self.account));
	}
}

pub(crate) fn pay_as_bid(
	cli: &Cli,
	trusted_args: &TrustedCli,
	arg_who: &str,
) -> Option<MarketOutput> {
	debug!("arg_who = {:?}", arg_who);
	let who = get_pair_from_str(trusted_args, arg_who);
	let top: TrustedOperation = TrustedGetter::pay_as_bid(who.public().into())
		.sign(&KeyPair::Sr25519(Box::new(who)))
		.into();

	let res = perform_trusted_operation(cli, trusted_args, &top);
	match res {
		Some(value) => match MarketOutput::decode(&mut value.as_slice()) {
			Ok(docoded_matches) => Some(docoded_matches),
			Err(e) => {
				info!("Error decoding matches: {:?}", e);
				None
			},
		},
		None => {
			info!("Matches not found");
			None
		},
	}
}
