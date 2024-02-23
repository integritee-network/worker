use crate::{Cli, CliResult};

use crate::trusted_cli::TrustedCli;
use trusted_commands::AddRaffleCmd;

mod trusted_commands;

/// Attesteer subcommands for the CLI.
#[derive(Debug, clap::Subcommand)]
pub enum RaffleTrustedCommand {
	/// Forward DCAP quote for verification.
	AddRaffle(AddRaffleCmd),
}

impl RaffleTrustedCommand {
	pub fn run(&self, cli: &Cli, trusted_args: &TrustedCli) -> CliResult {
		match self {
			Self::AddRaffle(cmd) => cmd.run(cli, trusted_args),
		}
	}
}
