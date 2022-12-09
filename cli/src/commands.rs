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

extern crate chrono;
use crate::{base_cli::BaseCli, trusted_commands::TrustedArgs, Cli};
use clap::Subcommand;

#[cfg(feature = "teeracle")]
use crate::oracle::OracleSubCommand;

#[derive(Subcommand)]
pub enum Commands {
	#[clap(flatten)]
	Base(BaseCli),

	/// trusted calls to worker enclave
	#[clap(after_help = "stf subcommands depend on the stf crate this has been built against")]
	Trusted(TrustedArgs),

	/// Subcommands for the oracle.
	#[cfg(feature = "teeracle")]
	#[clap(subcommand)]
	Oracle(OracleSubCommand),
}

pub fn match_command(cli: &Cli) {
	match &cli.command {
		Commands::Base(cmd) => cmd.run(cli),
		Commands::Trusted(cmd) => cmd.run(cli),
		#[cfg(feature = "teeracle")]
		Commands::Oracle(cmd) => cmd.run(cli),
	};
}
