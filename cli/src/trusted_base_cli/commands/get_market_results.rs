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
	trusted_operation::perform_trusted_operation, Cli, CliResult, CliResultOk,
};

use codec::Decode;
use ita_stf::{TrustedGetter, TrustedOperation};
use itp_stf_primitives::types::KeyPair;
use log::debug;
use simplyr_lib::MarketOutput;
use sp_core::Pair;

#[derive(Parser)]
pub struct GetMarketResultsCommand {
	/// AccountId in ss58check format
	pub account: String,
	pub timestamp: String,
}

impl GetMarketResultsCommand {
	pub(crate) fn run(&self, cli: &Cli, trusted_args: &TrustedCli) -> CliResult {
		println!(
			"{:?}",
			// if we serialize with serde-json we can easily just pass it as
			// an argument in the verify-proof command.
			serde_json::to_string(&get_market_results(
				cli,
				trusted_args,
				&self.account,
				self.timestamp.clone(),
			))
			.unwrap()
		);
		Ok(CliResultOk::None)
	}
}

pub(crate) fn get_market_results(
	cli: &Cli,
	trusted_args: &TrustedCli,
	arg_who: &str,
	timestamp: String,
) -> MarketOutput {
	debug!("arg_who = {:?}", arg_who);
	let who = get_pair_from_str(trusted_args, arg_who);

	let top: TrustedOperation = TrustedGetter::get_market_results(who.public().into(), timestamp)
		.sign(&KeyPair::Sr25519(Box::new(who)))
		.into();

	let res = perform_trusted_operation(cli, trusted_args, &top).unwrap();

	match res {
		Some(market_results) => match MarketOutput::decode(&mut market_results.as_slice()) {
			Ok(market_output) => market_output,
			Err(err) => panic!("Error deserializing market results: {}", err),
		},
		None => {
			panic!("Results not found");
		},
	}
}
