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
	trusted_cli::TrustedCli, trusted_command_utils::get_fingerprint, Cli, CliResult, CliResultOk,
};
use base58::ToBase58;
use codec::Encode;

#[derive(Parser)]
pub struct GetFingerprintCommand {
	/// also print as hex
	#[clap(short = 'x', long = "hex")]
	hex: bool,
}

impl GetFingerprintCommand {
	pub(crate) fn run(&self, cli: &Cli, _trusted_args: &TrustedCli) -> CliResult {
		let fingerprint = get_fingerprint(cli)?;
		let fingerprint_b58 = fingerprint.encode().to_base58();
		println!("{}", fingerprint_b58);
		if self.hex {
			println!("0x{}", hex::encode(fingerprint.encode()));
		}
		Ok(CliResultOk::FingerprintBase58 { fingerprints: vec![fingerprint_b58] })
	}
}
