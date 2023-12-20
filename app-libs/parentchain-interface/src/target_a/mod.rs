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

use crate::{
	decode_and_log_error,
	indirect_calls::{
		transfer_to_alice_shields_funds::TransferToAliceShieldsFundsArgs, ALICE_ACCOUNT_ID,
	},
};
use codec::{Decode, Encode};
use core::marker::PhantomData;
pub use event_filter::FilterableEvents;
pub use event_handler::ParentchainEventHandler;
pub use extrinsic_parser::ParentchainExtrinsicParser;
use extrinsic_parser::ParseExtrinsic;
#[cfg(feature = "std")]
pub use integritee_parachain_runtime::{
	Block, Hash, Header, Runtime, RuntimeCall, RuntimeEvent, UncheckedExtrinsic,
};
use ita_stf::TrustedCallSigned;
use itc_parentchain_indirect_calls_executor::{
	error::{Error, Result},
	filter_metadata::FilterIntoDataFrom,
	IndirectDispatch,
};
use itp_node_api::metadata::pallet_balances::BalancesCallIndexes;
use itp_stf_primitives::traits::IndirectExecutor;
use log::{debug, trace};

#[cfg(feature = "std")]
pub mod parachain {
	pub use integritee_parachain_runtime::{
		AccountId, Balance, BalancesCall, Block, Hash, Header, Runtime, RuntimeCall, RuntimeEvent,
		Signature, UncheckedExtrinsic,
	};
}
#[cfg(feature = "std")]
pub mod solochain {
	pub use polkadot_primitives::{AccountId, Balance, Hash, Signature};
	pub use rococo_relaychain_runtime::{
		BalancesCall, Block, Header, Runtime, RuntimeCall, RuntimeEvent, UncheckedExtrinsic,
	};
}

/// The default indirect call (extrinsic-triggered) of the Target-A-Parachain.
#[derive(Debug, Clone, Encode, Decode, Eq, PartialEq)]
pub enum IndirectCall {
	TransferToAliceShieldsFunds(TransferToAliceShieldsFundsArgs),
}

impl<Executor: IndirectExecutor<TrustedCallSigned, Error>>
	IndirectDispatch<Executor, TrustedCallSigned> for IndirectCall
{
	fn dispatch(&self, _executor: &Executor) -> Result<()> {
		debug!("shielding from TargetA extrinsic to Alice suppressed");
		/*
		trace!("dispatching indirect call {:?}", self);
		match self {
			IndirectCall::TransferToAliceShieldsFunds(args) => args.dispatch(executor),
		}

		 */
		Ok(())
	}
}

/// Simple demo filter for testing.
///
/// A transfer to Alice will issue the corresponding balance to Alice in the enclave.
/// It does not do anything else.
pub struct TransferToAliceShieldsFundsFilter<ExtrinsicParser> {
	_phantom: PhantomData<ExtrinsicParser>,
}

impl<ExtrinsicParser, NodeMetadata: BalancesCallIndexes> FilterIntoDataFrom<NodeMetadata>
	for TransferToAliceShieldsFundsFilter<ExtrinsicParser>
where
	ExtrinsicParser: ParseExtrinsic,
{
	type Output = IndirectCall;
	type ParseParentchainMetadata = ExtrinsicParser;

	fn filter_into_from_metadata(
		encoded_data: &[u8],
		metadata: &NodeMetadata,
	) -> Option<Self::Output> {
		let call_mut = &mut &encoded_data[..];

		// Todo: the filter should not need to parse, only filter. This should directly be configured
		// in the indirect executor.
		let xt = match Self::ParseParentchainMetadata::parse(call_mut) {
			Ok(xt) => xt,
			Err(e) => {
				log::error!("[TransferToAliceShieldsFundsFilter] Could not parse parentchain extrinsic: {:?}", e);
				return None
			},
		};
		let index = xt.call_index;
		let call_args = &mut &xt.call_args[..];
		trace!("[TransferToAliceShieldsFundsFilter] attempting to execute indirect call with index {:?}", index);
		if index == metadata.transfer_call_indexes().ok()?
			|| index == metadata.transfer_keep_alive_call_indexes().ok()?
			|| index == metadata.transfer_allow_death_call_indexes().ok()?
		{
			debug!("found `transfer` or `transfer_allow_death` or `transfer_keep_alive` call.");
			let args = decode_and_log_error::<TransferToAliceShieldsFundsArgs>(call_args)?;
			if args.destination == ALICE_ACCOUNT_ID.into() {
				Some(IndirectCall::TransferToAliceShieldsFunds(args))
			} else {
				debug!("Parentchain transfer extrinsic was not for Alice; ignoring...");
				// No need to put it into the top pool if it isn't executed in the first place.
				None
			}
		} else {
			None
		}
	}
}
