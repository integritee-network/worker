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

use crate::{
	decode_and_log_error,
	extrinsic_parser::{ExtrinsicParser, ParseExtrinsic},
	indirect_calls::{
		timestamp_set::TimestampSetArgs,
		transfer_to_alice_shields_funds::TransferToAliceShieldsFundsArgs, InvokeArgs,
		ShieldFundsArgs,
	},
};
use codec::{Decode, Encode};
use core::marker::PhantomData;
pub use event_filter::FilterableEvents;
pub use event_handler::ParentchainEventHandler;
use ita_stf::TrustedCallSigned;
use itc_parentchain_indirect_calls_executor::{
	error::{Error, Result},
	filter_metadata::FilterIntoDataFrom,
	IndirectDispatch,
};
use itp_api_client_types::ParentchainSignedExtra;
use itp_node_api::metadata::{
	pallet_balances::BalancesCallIndexes, pallet_timestamp::TimestampCallIndexes, NodeMetadata,
};
use itp_stf_primitives::traits::IndirectExecutor;
use log::*;

/// Parses the extrinsics corresponding to the parentchain.
pub type ParentchainExtrinsicParser = ExtrinsicParser<ParentchainSignedExtra>;

/// The default indirect call (extrinsic-triggered) of the Target-A-Parachain.
#[derive(Debug, Clone, Encode, Decode, Eq, PartialEq)]
pub enum IndirectCall {
	TimestampSet(TimestampSetArgs),
}

impl<Executor: IndirectExecutor<TrustedCallSigned, Error>>
	IndirectDispatch<Executor, TrustedCallSigned> for IndirectCall
{
	fn dispatch(&self, executor: &Executor) -> Result<()> {
		trace!("[TargetA] dispatching indirect call {:?}", self);
		match self {
			IndirectCall::TimestampSet(timestamp_set_args) => timestamp_set_args.dispatch(executor),
		}
	}
}

pub struct ExtrinsicFilter {}

impl<NodeMetadata: TimestampCallIndexes> FilterIntoDataFrom<NodeMetadata> for ExtrinsicFilter {
	type Output = IndirectCall;
	type ParseParentchainMetadata = ParentchainExtrinsicParser;

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
				error!("ExtrinsicFilter: Could not parse parentchain extrinsic: {:?}", e);
				return None
			},
		};
		let index = xt.call_index;
		let call_args = &mut &xt.call_args[..];
		trace!("ExtrinsicFilter: attempting to execute indirect call with index {:?}", index);
		if index == metadata.timestamp_set_call_indexes().ok()? {
			debug!("ExtrinsicFilter: found timestamp set extrinsic");
			let args = decode_and_log_error::<TimestampSetArgs>(call_args)?;
			Some(IndirectCall::TimestampSet(args))
		} else {
			None
		}
	}
}
