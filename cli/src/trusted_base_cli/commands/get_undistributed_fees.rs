/*
	Copyright 2021 Integritee AG

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
use ita_assets_map::AssetId;
use ita_stf::{Balance, Getter, PublicGetter, TrustedCallSigned};
use itp_stf_primitives::types::TrustedOperation;

#[derive(Parser)]
pub struct GetUndistributedFeesCommand {
	#[clap(short = 'a', long = "asset")]
	pub asset: Option<String>,
}

impl GetUndistributedFeesCommand {
	pub(crate) fn run(&self, cli: &Cli, trusted_args: &TrustedCli) -> CliResult {
		let maybe_asset_id = self
			.asset
			.clone()
			.map(|id| AssetId::try_from(id.as_str()).expect("Invalid asset id"));
		let top = TrustedOperation::<TrustedCallSigned, Getter>::get(Getter::public(
			PublicGetter::undistributed_fees(maybe_asset_id),
		));
		let fees: Balance = perform_trusted_operation(cli, trusted_args, &top).unwrap();
		println!("{:?}", fees);
		Ok(CliResultOk::Balance { balance: fees })
	}
}
