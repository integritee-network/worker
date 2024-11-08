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
use ita_stf::{Getter, ParentchainsInfo, PublicGetter, TrustedCallSigned};
use itp_stf_primitives::types::TrustedOperation;
use pallet_notes::BucketInfo;

#[derive(Parser)]
pub struct GetNoteBucketsInfoCommand {}

impl GetNoteBucketsInfoCommand {
	pub(crate) fn run(&self, cli: &Cli, trusted_args: &TrustedCli) -> CliResult {
		let top = TrustedOperation::<TrustedCallSigned, Getter>::get(Getter::public(
			PublicGetter::note_buckets_info,
		));
		let (first, last): (Option<BucketInfo>, Option<BucketInfo>) =
			perform_trusted_operation(cli, trusted_args, &top).unwrap();
		println!("first bucket: {:?}", first);
		println!("last bucket: {:?}", last);
		Ok(CliResultOk::NoteBucketsInfo { first, last })
	}
}
