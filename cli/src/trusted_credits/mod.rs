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

use crate::{trusted_cli::TrustedCli, Cli, CliResult};
use commands::{
	claim::ClaimCommand, create_class::CreateClassCommand, destroy_class::DestroyClassCommand,
	get_credit_class_info::GetCreditClassInfoCommand, get_credits::GetCreditsCommand,
	mint::MintCommand, redeem::RedeemCommand,
};
mod commands;

#[derive(Subcommand)]
pub enum CreditsCommand {
	CreateClass(CreateClassCommand),
	DestroyClass(DestroyClassCommand),
	Claim(ClaimCommand),
	Mint(MintCommand),
	Redeem(RedeemCommand),
	GetCredits(GetCreditsCommand),
	GetCreditClassInfo(GetCreditClassInfoCommand),
}

impl CreditsCommand {
	pub fn run(&self, cli: &Cli, trusted_cli: &TrustedCli) -> CliResult {
		match self {
			Self::CreateClass(cmd) => cmd.run(cli, trusted_cli),
			Self::DestroyClass(cmd) => cmd.run(cli, trusted_cli),
			Self::Claim(cmd) => cmd.run(cli, trusted_cli),
			Self::Mint(cmd) => cmd.run(cli, trusted_cli),
			Self::Redeem(cmd) => cmd.run(cli, trusted_cli),
			Self::GetCredits(cmd) => cmd.run(cli, trusted_cli),
			Self::GetCreditClassInfo(cmd) => cmd.run(cli, trusted_cli),
		}
	}
}
