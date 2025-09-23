/*
	Copyright 2021 Integritee AG

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
use rand::Rng;
use sp_core::blake2_256;

#[derive(Parser)]
pub struct GenerateCommitmentCommand {}

impl GenerateCommitmentCommand {
	pub(crate) fn run(&self, _cli: &Cli, _trusted_args: &TrustedCli) -> CliResult {
		let mut rng = rand::thread_rng();
		let random_bytes: [u8; 32] = rng.gen();
		let commitment = blake2_256(&random_bytes);
		println!("generated random secret and its commitment hash:");
		println!("secret: 0x{}", hex::encode(random_bytes));
		println!("commitment: 0x{}", hex::encode(commitment));
		Ok(CliResultOk::None)
	}
}
