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
	trusted_cli::TrustedCli, trusted_operation::perform_trusted_operation, Cli, CliResult,
	CliResultOk,
};
use ita_stf::{Getter, PublicGetter, RaffleMetadata, RafflePublicGetter};
use itp_types::AccountId;
use log::*;
use std::vec::Vec;

#[derive(Debug, Parser)]
pub struct GetAllRafflesCmd;

impl GetAllRafflesCmd {
	pub(crate) fn run(&self, cli: &Cli, trusted_args: &TrustedCli) -> CliResult {
		info!("Getting all raffles");

		let function_call =
			Getter::public(PublicGetter::raffle(RafflePublicGetter::all_ongoing_raffles));

		let res = perform_trusted_operation::<Vec<RaffleMetadata<AccountId>>>(
			cli,
			trusted_args,
			&function_call.into(),
		)?;

		println!("{:?}", res);
		Ok(CliResultOk::String { string: format!("{:?}", res) })
	}
}
