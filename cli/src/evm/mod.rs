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
	evm::commands::{
		evm_call::EvmCallCommands, evm_create::EvmCreateCommands, evm_read::EvmReadCommands,
	},
	trusted_cli::TrustedCli,
	Cli, CliResult,
};

mod commands;

#[allow(clippy::enum_variant_names)]
#[derive(Subcommand)]
pub enum EvmCommand {
	/// Create smart contract
	EvmCreate(EvmCreateCommands),

	/// Read smart contract storage
	EvmRead(EvmReadCommands),

	/// Create smart contract
	EvmCall(EvmCallCommands),
}

impl EvmCommand {
	pub fn run(&self, cli: &Cli, trusted_args: &TrustedCli) -> CliResult {
		match self {
			EvmCommand::EvmCreate(cmd) => cmd.run(cli, trusted_args),
			EvmCommand::EvmRead(cmd) => cmd.run(cli, trusted_args),
			EvmCommand::EvmCall(cmd) => cmd.run(cli, trusted_args),
		}
	}
}
