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

use crate::Cli;

use self::commands::{SendDcapQuoteCmd, SendIasAttestationReportCmd};

mod commands;

/// Attesteer subcommands for the CLI.
#[derive(Debug, clap::Subcommand)]
pub enum AttesteerCommand {
	/// Forward DCAP quote for verification.
	SendDCAPQuote(SendDcapQuoteCmd),

	/// Forward IAS attestation report for verification.
	SendIASAttestationReport(SendIasAttestationReportCmd),
}

impl AttesteerCommand {
	pub fn run(&self, cli: &Cli) {
		match self {
			AttesteerCommand::SendDCAPQuote(cmd) => cmd.run(cli),
			AttesteerCommand::SendIASAttestationReport(cmd) => cmd.run(cli),
		}
	}
}
