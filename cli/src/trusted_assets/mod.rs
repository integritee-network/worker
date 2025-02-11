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

use crate::{trusted_cli::TrustedCli, Cli, CliResult};
mod commands;
use commands::{
	balance::BalanceCommand, transfer::TransferCommand, unshield_funds::UnshieldFundsCommand,
};

#[derive(Subcommand)]
pub enum TrustedAssetsCommand {
	/// send funds from one incognito account to another
	Transfer(TransferCommand),
	/// query balance for incognito account in keystore
	Balance(BalanceCommand),
	/// Transfer funds from an incognito account to an parentchain account
	UnshieldFunds(UnshieldFundsCommand),
}

impl TrustedAssetsCommand {
	pub fn run(&self, cli: &Cli, trusted_cli: &TrustedCli) -> CliResult {
		match self {
			TrustedAssetsCommand::Balance(cmd) => cmd.run(cli, trusted_cli),
			TrustedAssetsCommand::Transfer(cmd) => cmd.run(cli, trusted_cli),
			TrustedAssetsCommand::UnshieldFunds(cmd) => cmd.run(cli, trusted_cli),
		}
	}
}
