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
	indirect_calls::{invoke::InvokeArgs, shield_funds::ShieldFundsArgs},
	integritee::extrinsic_parser::ParseExtrinsic,
};
use codec::{Decode, Encode};
use core::marker::PhantomData;
pub use event_handler::ParentchainEventHandler;
pub use extrinsic_parser::ParentchainExtrinsicParser;
use ita_stf::TrustedCallSigned;
use itc_parentchain_indirect_calls_executor::{
	error::Result, filter_metadata::FilterIntoDataFrom, IndirectDispatch, IndirectExecutor,
};
use itp_node_api::metadata::NodeMetadataTrait;
use log::trace;
/// The default indirect call (extrinsic-triggered) of the Integritee-Parachain.
#[derive(Debug, Clone, Encode, Decode, Eq, PartialEq)]
pub enum IndirectCall {
	ShieldFunds(ShieldFundsArgs),
	Invoke(InvokeArgs),
}

impl<Executor: IndirectExecutor<TrustedCallSigned>> IndirectDispatch<Executor, TrustedCallSigned>
	for IndirectCall
{
	fn dispatch(&self, executor: &Executor) -> Result<()> {
		trace!("dispatching indirect call {:?}", self);
		match self {
			IndirectCall::ShieldFunds(shieldfunds_args) => shieldfunds_args.dispatch(executor),
			IndirectCall::Invoke(invoke_args) => invoke_args.dispatch(executor),
		}
	}
}

/// Default filter we use for the Integritee-Parachain.
pub struct ShieldFundsAndInvokeFilter<ExtrinsicParser> {
	_phantom: PhantomData<ExtrinsicParser>,
}

impl<ExtrinsicParser, NodeMetadata: NodeMetadataTrait> FilterIntoDataFrom<NodeMetadata>
	for ShieldFundsAndInvokeFilter<ExtrinsicParser>
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
				log::error!(
					"[ShieldFundsAndInvokeFilter] Could not parse parentchain extrinsic: {:?}",
					e
				);
				return None
			},
		};
		let index = xt.call_index;
		let call_args = &mut &xt.call_args[..];
		log::trace!(
			"[ShieldFundsAndInvokeFilter] attempting to execute indirect call with index {:?}",
			index
		);
		if index == metadata.shield_funds_call_indexes().ok()? {
			log::debug!("executing shield funds call");
			let args = decode_and_log_error::<ShieldFundsArgs>(call_args)?;
			Some(IndirectCall::ShieldFunds(args))
		} else if index == metadata.invoke_call_indexes().ok()? {
			log::debug!("executing invoke call");
			let args = decode_and_log_error::<InvokeArgs>(call_args)?;
			Some(IndirectCall::Invoke(args))
		} else {
			None
		}
	}
}
