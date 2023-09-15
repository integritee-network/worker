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
use ita_stf::{MerkleProofWithCodec, TrustedGetter, TrustedOperation};
use itp_stf_primitives::types::KeyPair;
use log::debug;
use sp_core::{Pair, H256};

use crate::CliError;
use codec;
#[derive(Parser)]
pub struct PayAsBidProofCommand {
	/// AccountId in ss58check format
	pub account: String,
	pub timestamp: String,
	pub actor_id: String,
}

impl PayAsBidProofCommand {
	pub(crate) fn run(&self, cli: &Cli, trusted_args: &TrustedCli) -> CliResult {
		// if we serialize with serde-json we can easily just pass it as
		// an argument in the verify-proof command.
		let results = pay_as_bid_proof(
			cli,
			trusted_args,
			&self.account,
			self.timestamp.clone(),
			self.actor_id.clone(),
		);

		match results {
			Ok(res) => Ok(CliResultOk::PayAsBidProofOutput(res)),
			Err(e) => {
				log::error!("Error getting proof: {}", e);
				Err(CliError::TrustedOp { msg: "Error getting proof".into() })
			},
		}
	}
}

pub(crate) fn pay_as_bid_proof(
	cli: &Cli,
	trusted_args: &TrustedCli,
	arg_who: &str,
	timestamp: String,
	actor_id: String,
) -> Result<MerkleProofWithCodec<H256, Vec<u8>>, CliError> {
	debug!("arg_who = {:?}", arg_who);
	let who = get_pair_from_str(trusted_args, arg_who);

	let top: TrustedOperation =
		TrustedGetter::pay_as_bid_proof(who.public().into(), timestamp, actor_id)
			.sign(&KeyPair::Sr25519(Box::new(who)))
			.into();

	let res = perform_trusted_operation(cli, trusted_args, &top).unwrap();

	match res {
		Some(_proof) => match MerkleProofWithCodec::decode(&mut &_proof[..]) {
			Ok(_proof) => Ok(_proof),
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
