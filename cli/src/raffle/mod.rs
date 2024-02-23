use crate::{Cli, CliResult};

use crate::{
	raffle::trusted_commands::{DrawWinnersCmd, RegisterForRaffleCmd},
	trusted_cli::TrustedCli,
};
use trusted_commands::{AddRaffleCmd, GetAllRafflesCmd};

mod trusted_commands;

/// Attesteer subcommands for the CLI.
#[derive(Debug, clap::Subcommand)]
pub enum RaffleTrustedCommand {
	/// Add a new raffle
	AddRaffle(AddRaffleCmd),

	/// Register for a raffle
	RegisterForRaffle(RegisterForRaffleCmd),

	/// Register for a raffle
	DrawWinners(DrawWinnersCmd),

	/// Get all ongoing raffles
	GetAllRaffles(GetAllRafflesCmd),
}

impl RaffleTrustedCommand {
	pub fn run(&self, cli: &Cli, trusted_args: &TrustedCli) -> CliResult {
		match self {
			Self::AddRaffle(cmd) => cmd.run(cli, trusted_args),
			Self::RegisterForRaffle(cmd) => cmd.run(cli, trusted_args),
			Self::DrawWinners(cmd) => cmd.run(cli, trusted_args),
			Self::GetAllRaffles(cmd) => cmd.run(cli, trusted_args),
		}
	}
}
