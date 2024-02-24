use crate::{trusted_cli::TrustedCli, Cli, CliResult};
use trusted_commands::{
	AddRaffleCmd, DrawWinnersCmd, GetAllRafflesCmd, GetAndVerifyRegistrationProof,
	RegisterForRaffleCmd,
};

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

	/// Get and verify the proof of raffle registration
	GetAndVerifyRegistrationProof(GetAndVerifyRegistrationProof),
}

impl RaffleTrustedCommand {
	pub fn run(&self, cli: &Cli, trusted_args: &TrustedCli) -> CliResult {
		match self {
			Self::AddRaffle(cmd) => cmd.run(cli, trusted_args),
			Self::RegisterForRaffle(cmd) => cmd.run(cli, trusted_args),
			Self::DrawWinners(cmd) => cmd.run(cli, trusted_args),
			Self::GetAllRaffles(cmd) => cmd.run(cli, trusted_args),
			Self::GetAndVerifyRegistrationProof(cmd) => cmd.run(cli, trusted_args),
		}
	}
}
