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

use crate::{trusted_cli::TrustedCli, Cli};
use binary_merkle_tree::verify_proof;
use sp_runtime::traits::Keccak256;

#[derive(Parser)]
pub struct VerifyMerkleProofCommand {
	merkle_root: String,
	merkle_proof: String,
	orders_encoded_len: usize,
	leaf_index: usize,
	leaf: String,
}

impl VerifyMerkleProofCommand {
	pub(crate) fn run(&self, cli: &Cli, trusted_args: &TrustedCli) {
		println!(
			"Result: {:?}",
			verify_merkle_proof::<H>(
				cli,
				trusted_args,
				&self.merkle_root,
				&self.merkle_proof,
				&self.orders_encoded_len,
				self.leaf_index,
				self.leaf.as_bytes(),
			)
		);
	}
}

pub(crate) fn verify_merkle_proof<'a, H>(
	cli: &Cli,
	trusted_args: &TrustedCli,
	merkle_root: &str,
	merkle_proof: &str,
	orders_encoded_len: &usize,
	leaf_index: usize,
	leaf: &[u8],
) -> Option<bool> {
	let res = verify_proof::<Sha256Hasher, _, _>(
		&hex::decode(merkle_root).unwrap(),
		merkle_proof.chars(),
		*orders_encoded_len,
		leaf_index.try_into().unwrap(),
		leaf.into(),
	);

	info!("{}", res);

	match res {
		Some(value) => Some(res),
		None => {
			info!("Proof not found");
			None
		},
	}
}
