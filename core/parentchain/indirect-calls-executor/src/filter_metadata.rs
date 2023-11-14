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

use crate::{error::Result, IndirectDispatch};
use codec::{Decode, Encode};
use core::marker::PhantomData;
use itp_api_client_types::{Events, Metadata};
use itp_node_api::metadata::{
	pallet_balances::BalancesCallIndexes, NodeMetadata, NodeMetadataTrait,
};
use itp_stf_primitives::traits::IndirectExecutor;
use itp_types::{parentchain::FilterEvents, H256};
use log::trace;

pub trait EventsFromMetadata<NodeMetadata> {
	type Output: FilterEvents;

	fn create_from_metadata(
		metadata: NodeMetadata,
		block_hash: H256,
		events: &[u8],
	) -> Option<Self::Output>;
}

pub struct EventCreator<FilterableEvents> {
	_phantom: PhantomData<FilterableEvents>,
}

impl<NodeMetadata: TryInto<Metadata> + Clone, FilterableEvents> EventsFromMetadata<NodeMetadata>
	for EventCreator<FilterableEvents>
where
	FilterableEvents: From<Events<H256>> + FilterEvents,
{
	type Output = FilterableEvents;

	fn create_from_metadata(
		metadata: NodeMetadata,
		block_hash: H256,
		events: &[u8],
	) -> Option<Self::Output> {
		let raw_metadata: Metadata = metadata.try_into().ok()?;
		Some(Events::<H256>::new(raw_metadata, block_hash, events.to_vec()).into())
	}
}

/// Trait to filter an indirect call and decode into it, where the decoding
/// is based on the metadata provided.
pub trait FilterIntoDataFrom<NodeMetadata> {
	/// Type to decode into.
	type Output;

	/// Knows how to parse the parentchain metadata.
	type ParseParentchainMetadata;

	/// Filters some bytes and returns `Some(Self::Output)` if the filter matches some criteria.
	fn filter_into_from_metadata(
		encoded_data: &[u8],
		metadata: &NodeMetadata,
	) -> Option<Self::Output>;
}

/// Indirect calls filter denying all indirect calls.
pub struct DenyAll;

mod seal {
	use super::*;
	use crate::Error;
	use core::fmt::Debug;
	use itp_stf_primitives::traits::TrustedCallVerification;

	/// Stub struct for the `DenyAll` filter that never executes anything.
	#[derive(Debug, Encode)]
	pub struct CantExecute;

	impl FilterIntoDataFrom<NodeMetadata> for DenyAll {
		type Output = CantExecute;
		type ParseParentchainMetadata = ();

		fn filter_into_from_metadata(_: &[u8], _: &NodeMetadata) -> Option<CantExecute> {
			None
		}
	}

	impl<Executor: IndirectExecutor<TCS, Error>, TCS> IndirectDispatch<Executor, TCS> for CantExecute
	where
		TCS: PartialEq + Encode + Decode + Debug + Clone + Send + Sync + TrustedCallVerification,
	{
		fn dispatch(&self, _: &Executor) -> Result<()> {
			// We should never get here because `CantExecute` is in a private module and the trait
			// implementation is sealed and always returns `None` instead of a `CantExecute` instance.
			// Regardless, we never want the enclave to panic, this is why we take this extra safety
			// measure.
			log::warn!(
				"Executed indirect dispatch for 'CantExecute'\
			 	this means there is some logic error."
			);
			Ok(())
		}
	}
}
