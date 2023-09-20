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
	get_layer_two_nonce,
	trusted_cli::TrustedCli,
	trusted_command_utils::{get_identifiers, get_pair_from_str},
	trusted_operation::perform_trusted_operation,
	Cli, CliError, CliResult, CliResultOk,
};
use codec::Decode;
use ita_stf::{Index, TrustedCall, TrustedGetter, TrustedOperation};
use itp_stf_primitives::types::KeyPair;
use log::debug;
use sp_core::Pair;

#[derive(Parser)]
pub struct PayAsBidCommand {
	/// AccountId in ss58check format
	pub account: String,
	pub orders_string: String,
}

impl PayAsBidCommand {
	pub(crate) fn run(&self, cli: &Cli, trusted_args: &TrustedCli) -> CliResult {
		let results = pay_as_bid(cli, trusted_args, &self.account, &self.orders_string);
		match results {
			Ok(res) => Ok(CliResultOk::PayAsBidOutput(res)),
			Err(e) => {
				log::error!("Error: {}", e);
				Err(CliError::TrustedOp { msg: "Error savings Orders".into() })
			},
		}
	}
}

pub(crate) fn pay_as_bid(
	cli: &Cli,
	trusted_args: &TrustedCli,
	arg_who: &str,
	orders_string: &str,
) -> Result<Option<Vec<u8>>, CliError> {
	debug!("arg_who = {:?}", arg_who);
	let who = get_pair_from_str(trusted_args, arg_who);
	let signer = get_pair_from_str(trusted_args, arg_who);
	let (mrenclave, shard) = get_identifiers(trusted_args);
	let nonce = get_layer_two_nonce!(signer, cli, trusted_args);
	let top: TrustedOperation =
		TrustedCall::pay_as_bid(who.public().into(), orders_string.to_string())
			.sign(&KeyPair::Sr25519(Box::new(signer)), nonce, &mrenclave, &shard)
			.into_trusted_operation(trusted_args.direct);

	let res = perform_trusted_operation(cli, trusted_args, &top);
	match res {
		Ok(opt) => match opt {
			Some(_results) => Ok(Some(_results)),
			None => Ok(None),
		},
		Err(err) => {
			log::error!("Error in saving Orders: {}", err);
			Err(CliError::TrustedOp { msg: format!("Error in saving Orders: {}", err) })
		},
	}
}
