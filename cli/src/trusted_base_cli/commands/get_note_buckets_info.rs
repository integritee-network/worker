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
	command_utils::format_moment, trusted_cli::TrustedCli,
	trusted_operation::perform_trusted_operation, Cli, CliResult, CliResultOk,
};
use ita_stf::{Getter, PublicGetter, TrustedCallSigned};
use itp_stf_primitives::types::TrustedOperation;
use itp_types::Moment;
use pallet_notes::{BucketInfo, BucketRange};

#[derive(Parser)]
pub struct GetNoteBucketsInfoCommand {}

impl GetNoteBucketsInfoCommand {
	pub(crate) fn run(&self, cli: &Cli, trusted_args: &TrustedCli) -> CliResult {
		let top = TrustedOperation::<TrustedCallSigned, Getter>::get(Getter::public(
			PublicGetter::note_buckets_info,
		));
		let range: BucketRange<Moment> =
			perform_trusted_operation(cli, trusted_args, &top).unwrap();
		if let Some(bucket) = range.maybe_first {
			println!(
				"first bucket : index {}, bytes: {}, begins at {}",
				bucket.index,
				bucket.bytes,
				format_moment(bucket.begins_at)
			);
		}
		if let Some(bucket) = range.maybe_last {
			println!(
				"last bucket  : index {}, bytes: {}, ends at {}",
				bucket.index,
				bucket.bytes,
				format_moment(bucket.ends_at)
			);
		}
		Ok(CliResultOk::NoteBucketRange { range })
	}
}
