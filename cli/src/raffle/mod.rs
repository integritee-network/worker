use crate::{Cli, CliResult};

use crate::{raffle::trusted_commands::RegisterForRaffleCmd, trusted_cli::TrustedCli};
use trusted_commands::{AddRaffleCmd, GetAllRafflesCmd};

mod trusted_commands;

/// Attesteer subcommands for the CLI.
#[derive(Debug, clap::Subcommand)]
pub enum RaffleTrustedCommand {
	/// Forward DCAP quote for verification.
	AddRaffle(AddRaffleCmd),

	/// Forward DCAP quote for verification.
	RegisterForRaffle(RegisterForRaffleCmd),

	/// Get all ongoing raffles
	GetAllRaffles(GetAllRafflesCmd),
}

impl RaffleTrustedCommand {
	pub fn run(&self, cli: &Cli, trusted_args: &TrustedCli) -> CliResult {
		match self {
			Self::AddRaffle(cmd) => cmd.run(cli, trusted_args),
			Self::RegisterForRaffle(cmd) => cmd.run(cli, trusted_args),
			Self::GetAllRaffles(cmd) => cmd.run(cli, trusted_args),
		}
	}
}
