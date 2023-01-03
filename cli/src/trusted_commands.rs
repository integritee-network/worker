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

use crate::{benchmark::BenchmarkCommand, Cli};

#[cfg(feature = "evm")]
use crate::evm::EvmCommand;
use crate::trusted_base_cli::TrustedBaseCommands;

#[derive(Args)]
pub struct TrustedCli {
	/// targeted worker MRENCLAVE
	#[clap(short, long)]
	pub(crate) mrenclave: String,

	/// shard identifier
	#[clap(short, long)]
	pub(crate) shard: Option<String>,

	/// signer for publicly observable extrinsic
	#[clap(short='a', long, default_value_t = String::from("//Alice"))]
	pub(crate) xt_signer: String,

	/// insert if direct invocation call is desired
	#[clap(short, long)]
	pub(crate) direct: bool,

	#[clap(subcommand)]
	pub(crate) command: TrustedCommands,
}

#[derive(Subcommand)]
pub enum TrustedCommands {
	#[clap(flatten)]
	BaseTrusted(TrustedBaseCommands),

	#[cfg(feature = "evm")]
	#[clap(flatten)]
	EvmCommands(EvmCommand),

	/// Run Benchmark
	Benchmark(BenchmarkCommand),
}

impl TrustedCli {
	pub(crate) fn run(&self, cli: &Cli) {
		match &self.command {
			TrustedCommands::BaseTrusted(cmd) => cmd.run(cli, self),
			TrustedCommands::Benchmark(benchmark_commands) => benchmark_commands.run(cli, self),
			#[cfg(feature = "evm")]
			TrustedCommands::EvmCommands(evm_commands) => evm_commands.run(cli, self),
		}
	}
}
