//! Add cli commands for the exchange-rate oracle
//!
//! Todo: This shall be a standalone crate in app-libs/exchange-oracle. However, this needs:
//! https://github.com/integritee-network/worker/issues/852

use crate::Cli;
use commands::{AddWhitelistCmd, ListenToExchangeCmd};

mod commands;

/// Exchange oracle subcommands for the cli.
#[derive(Debug, clap::Subcommand)]
pub enum ExchangeOracleSubCommand {
	/// Add a market source to the teeracle's whitelist.
	AddWhitelistCmd(AddWhitelistCmd),

	/// Listen to exchange rate events
	ListenToExchangeCmd(ListenToExchangeCmd),
}

impl ExchangeOracleSubCommand {
	pub fn run(&self, cli: &Cli) {
		match self {
			ExchangeOracleSubCommand::AddWhitelistCmd(cmd) => cmd.run(cli),
			ExchangeOracleSubCommand::ListenToExchangeCmd(cmd) => cmd.run(cli),
		}
	}
}
