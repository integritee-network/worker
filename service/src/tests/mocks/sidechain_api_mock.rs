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

use frame_support::sp_runtime::traits::Block as ParentchainBlockTrait;
use itp_enclave_api::{sidechain::Sidechain, EnclaveResult};

/// Mock for Parentchain Api
pub struct SidechainApiMock;

impl Sidechain for SidechainApiMock {
	fn sync_parentchain<ParentchainBlock: ParentchainBlockTrait>(
		&self,
		_blocks: &[sp_runtime::generic::SignedBlock<ParentchainBlock>],
		_nonce: u32,
	) -> EnclaveResult<()> {
		Ok(())
	}

	fn execute_trusted_getters(&self) -> EnclaveResult<()> {
		todo!()
	}

	fn execute_trusted_calls(&self) -> EnclaveResult<()> {
		todo!()
	}
}
