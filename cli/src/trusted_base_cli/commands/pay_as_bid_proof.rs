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
	Cli,
};
use codec::Decode;
use ita_stf::{Index, TrustedCall, TrustedGetter, TrustedOperation};
use itp_stf_primitives::types::KeyPair;
use itp_types::H256;
use log::{debug, info};
use sp_core::Pair;

#[derive(Parser)]
pub struct PayAsBidProofCommand {
	/// AccountId in ss58check format
	account: String,
	orders_file: String,
	leaf_index: u8,
}

impl PayAsBidProofCommand {
	pub(crate) fn run(&self, cli: &Cli, trusted_args: &TrustedCli) {
		println!(
			"Result: {:?}",
			pay_as_bid_proof(cli, trusted_args, &self.account, &self.orders_file, self.leaf_index)
		);
	}
}

pub(crate) fn pay_as_bid_proof(
	cli: &Cli,
	trusted_args: &TrustedCli,
	arg_who: &str,
	orders_file: &str,
	leaf_index: u8,
) -> Option<Vec<u8>> {
	debug!("arg_who = {:?}", arg_who);
	let who = get_pair_from_str(trusted_args, arg_who);
	let signer = get_pair_from_str(trusted_args, arg_who);
	let (mrenclave, shard) = get_identifiers(trusted_args);
	let nonce = get_layer_two_nonce!(signer, cli, trusted_args);
	let top: TrustedOperation =
		TrustedCall::pay_as_bid_proof(who.public().into(), orders_file.to_string(), leaf_index)
			.sign(&KeyPair::Sr25519(Box::new(signer)), nonce, &mrenclave, &shard)
			.into_trusted_operation(trusted_args.direct);

	let res = perform_trusted_operation(cli, trusted_args, &top);
	match res {
		Some(value) => {
			let proof = H256::decode(&mut &value[..]).unwrap();
			println!("Merkle proof: {:?}", proof);
			Some(proof.0.to_vec())
		},
		None => {
			info!("Proof not found");
			None
		},
	}
}
