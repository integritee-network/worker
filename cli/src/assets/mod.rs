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

use crate::{Cli, CliResult};

mod commands;
use commands::{balance::BalanceCommand, transfer::TransferCommand};

/// Attesteer subcommands for the CLI.
#[derive(clap::Subcommand)]
pub enum AssetsCommand {
	/// query parentchain asset balance for AccountId
	Balance(BalanceCommand),

	/// transfer funds from one parentchain account to another
	Transfer(TransferCommand),
}

impl AssetsCommand {
	pub fn run(&self, cli: &Cli) -> CliResult {
		match self {
			AssetsCommand::Balance(cmd) => cmd.run(cli),
			AssetsCommand::Transfer(cmd) => cmd.run(cli),
		}
	}
}
