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
use crate::{
	trusted_cli::TrustedCli, trusted_command_utils::get_sidechain_header, Cli, CliResult,
	CliResultOk,
};

#[derive(Parser)]
pub struct GetSidechainHeaderCommand {}

impl GetSidechainHeaderCommand {
	pub(crate) fn run(&self, cli: &Cli, _trusted_args: &TrustedCli) -> CliResult {
		let header = get_sidechain_header(cli)?;
		println!("{:?}", header);
		Ok(CliResultOk::SidechainHeader { header })
	}
}
