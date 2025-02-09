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
use crate::{error::Result, ConfirmBlockImport};
use itp_types::{parentchain::SidechainBlockConfirmation, ShardIdentifier};
use its_primitives::types::header::SidechainHeader;
use sp_runtime::traits::Block;

/// Mock implementation of the `ConfirmBlockImport` trait.
pub struct ConfirmBlockImportMock;

impl<ParentchainBlock: Block> ConfirmBlockImport<SidechainHeader, ParentchainBlock>
	for ConfirmBlockImportMock
{
	fn confirm_import(
		&self,
		_header: &SidechainHeader,
		_shard: &ShardIdentifier,
		_maybe_confirmation: &Option<SidechainBlockConfirmation>,
		_latest_parentchain_header: &<ParentchainBlock as Block>::Header,
	) -> Result<()> {
		Ok(())
	}
}
