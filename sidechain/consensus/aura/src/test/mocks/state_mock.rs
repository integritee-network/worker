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

use its_state::LastBlockExt;
use sidechain_primitives::traits::Block as SidechainBlockTrait;

pub struct StateMock<SidechainBlock: SidechainBlockTrait> {
	pub last_block: Option<SidechainBlock>,
}

impl<SidechainBlock: SidechainBlockTrait> LastBlockExt<SidechainBlock>
	for StateMock<SidechainBlock>
{
	fn get_last_block(&self) -> Option<SidechainBlock> {
		self.last_block.clone()
	}

	fn set_last_block(&mut self, block: &SidechainBlock) {
		self.last_block = Some(block.clone())
	}
}
