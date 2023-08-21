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

use crate::{trusted_cli::TrustedCli, Cli, CliResult, CliResultOk};
use binary_merkle_tree::verify_proof;
use ita_stf::MerkleProofWithCodec;
use log::info;
use primitive_types::H256;
use sp_runtime::traits::Keccak256;

#[derive(Parser)]
pub struct VerifyMerkleProofCommand {
	pub merkle_proof_json: String,
}

impl VerifyMerkleProofCommand {
	pub(crate) fn run(&self, cli: &Cli, trusted_args: &TrustedCli) -> CliResult {
		info!("Proof is valid:");
		println!("{:?}", verify_merkle_proof(cli, trusted_args, &self.merkle_proof_json));
		Ok(CliResultOk::None)
	}
}

pub(crate) fn verify_merkle_proof(
	_cli: &Cli,
	_trusted_args: &TrustedCli,
	merkle_proof: &str,
) -> bool {
	// Remove starting and trailing `"` and `\\\` in the string, which occur when we
	// pass the proof in the bash script for whatever reason. This is probably a hack,
	// but I don't know bash well enough to fix it in the bash script.
	let proof_sanitized = merkle_proof.replace('\\', "").trim_matches('\"').to_string();
	info!("Sanitized input merkle proof: {}", &proof_sanitized);

	let proof: MerkleProofWithCodec<H256, Vec<u8>> =
		serde_json::from_str(&proof_sanitized).expect("Could not parse merkle proof");

	info!("Proof: {:?}", proof);

	verify_proof::<Keccak256, _, _>(
		&proof.root,
		proof.proof.clone(),
		proof
			.number_of_leaves
			.try_into()
			.expect("Target Architecture needs usize > 32bits "),
		proof.leaf_index.try_into().expect("Target Architecture needs usize > 32bits "),
		&proof.leaf,
	)
}
