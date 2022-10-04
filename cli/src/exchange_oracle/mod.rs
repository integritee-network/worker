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
