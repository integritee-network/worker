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
use ita_stf::{
	merkle_tree::{verify_proof, Keccak256, MerkleProofWithCodec},
	Getter, RaffleIndex, RaffleTrustedGetter, TrustedGetter,
};
use itp_types::AccountId;
use log::*;
use sp_core::{crypto::Ss58Codec, Pair, H256};

#[derive(Debug, Parser)]
pub struct GetAndVerifyRegistrationProof {
	/// Sender's incognito AccountId in ss58check format
	from: String,

	/// Raffle index to get the proof for
	raffle_index: RaffleIndex,
}

impl GetAndVerifyRegistrationProof {
	pub(crate) fn run(&self, cli: &Cli, trusted_args: &TrustedCli) -> CliResult {
		let sender = get_pair_from_str(trusted_args, &self.from);
		let sender_acc: AccountId = sender.public().into();
		info!("senders ss58 is {}", sender.public().to_ss58check());

		let get_registration_proof = RaffleTrustedGetter::merkle_proof {
			origin: sender_acc,
			raffle_index: self.raffle_index,
		};

		let getter =
			Getter::trusted(TrustedGetter::raffle(get_registration_proof).sign(&sender.into()));

		let proof = perform_trusted_operation::<MerkleProofWithCodec<H256, Vec<u8>>>(
			cli,
			trusted_args,
			&getter.into(),
		)?;

		println!("{:?}", proof);

		let is_valid = verify_proof::<Keccak256, _, _>(
			&proof.root,
			proof.proof.clone(),
			proof
				.number_of_leaves
				.try_into()
				.expect("Target Architecture needs usize > 32bits "),
			proof.leaf_index.try_into().expect("Target Architecture needs usize > 32bits "),
			&proof.leaf,
		);

		println!("Proof is valid: {:?}", is_valid);

		Ok(CliResultOk::String { string: format!("Merkle proof is valid: {}", is_valid) })
	}
}
