//! Add cli commands for the exchange-rate oracle
//!
//! Todo: This shall be a standalone crate in app-libs/exchange-oracle. However, this needs:
//! https://github.com/integritee-network/worker/issues/852

use crate::Cli;
use commands::{AddToWhitelistCmd, ListenToExchangeRateEventsCmd};

mod commands;

/// Exchange oracle subcommands for the cli.
#[derive(Debug, clap::Subcommand)]
pub enum ExchangeOracleSubCommand {
	/// Add a market source to the teeracle's whitelist.
	AddToWhitelist(AddToWhitelistCmd),

	/// Listen to exchange rate events
	ListenToExchangeRateEvents(ListenToExchangeRateEventsCmd),
}

impl ExchangeOracleSubCommand {
	pub fn run(&self, cli: &Cli) {
		match self {
			ExchangeOracleSubCommand::AddToWhitelist(cmd) => cmd.run(cli),
			ExchangeOracleSubCommand::ListenToExchangeRateEvents(cmd) => cmd.run(cli),
		}
	}
}
