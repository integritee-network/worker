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
mod event_filter;
mod event_handler;
mod extrinsic_parser;

use codec::{Decode, Encode};
use core::marker::PhantomData;
pub use event_filter::FilterableEvents;
pub use event_handler::ParentchainEventHandler;
pub use extrinsic_parser::ParentchainExtrinsicParser;
use extrinsic_parser::ParseExtrinsic;
use ita_stf::TrustedCallSigned;
use itc_parentchain_indirect_calls_executor::{
	error::{Error, Result},
	filter_metadata::FilterIntoDataFrom,
	IndirectDispatch,
};
use itp_node_api::metadata::pallet_balances::BalancesCallIndexes;
use itp_stf_primitives::traits::IndirectExecutor;
use log::error;

/// The default indirect call (extrinsic-triggered) of the Target-A-Parachain.
#[derive(Debug, Clone, Encode, Decode, Eq, PartialEq)]
pub enum IndirectCall {}

impl<Executor: IndirectExecutor<TrustedCallSigned, Error>>
	IndirectDispatch<Executor, TrustedCallSigned> for IndirectCall
{
	fn dispatch(&self, _executor: &Executor) -> Result<()> {
		Err(Error::Other("no indirect calls defined for target_b".into()))
	}
}

pub struct TargetBExtrinsicFilter<ExtrinsicParser> {
	_phantom: PhantomData<ExtrinsicParser>,
}

impl<ExtrinsicParser, NodeMetadata: BalancesCallIndexes> FilterIntoDataFrom<NodeMetadata>
	for TargetBExtrinsicFilter<ExtrinsicParser>
where
	ExtrinsicParser: ParseExtrinsic,
{
	type Output = IndirectCall;
	type ParseParentchainMetadata = ExtrinsicParser;

	fn filter_into_from_metadata(
		_encoded_data: &[u8],
		_metadata: &NodeMetadata,
	) -> Option<Self::Output> {
		error!("no indirect calls filter has been implemented for target_b");
		None
	}
}
