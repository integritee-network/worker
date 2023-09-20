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

use crate::CliError;
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
		let results = get_market_results(cli, trusted_args, &self.account, self.timestamp.clone());
		match results {
			Ok(res) => Ok(CliResultOk::Matches(res)),
			Err(e) => {
				log::error!("Error getting results: {}", e);
				Err(CliError::TrustedOp { msg: "Error getting results".into() })
			},
		}
	}
}

pub(crate) fn get_market_results(
	cli: &Cli,
	trusted_args: &TrustedCli,
	arg_who: &str,
	timestamp: String,
) -> Result<MarketOutput, CliError> {
	debug!("arg_who = {:?}", arg_who);
	let who = get_pair_from_str(trusted_args, arg_who);

	let top: TrustedOperation = TrustedGetter::get_market_results(who.public().into(), timestamp)
		.sign(&KeyPair::Sr25519(Box::new(who)))
		.into();

	let res = perform_trusted_operation(cli, trusted_args, &top).unwrap();

	match res {
		Some(market_results) => match MarketOutput::decode(&mut market_results.as_slice()) {
			Ok(market_output) => Ok(market_output),
			Err(err) => {
				log::error!("Error deserializing results: {}", err);
				Err(CliError::TrustedOp {
					msg: format!("Error deserializing market results: {}", err),
				})
			},
		},
		None => {
			log::error!("Results not found");
			Err(CliError::TrustedOp { msg: "Results not found".into() })
		},
	}
}
