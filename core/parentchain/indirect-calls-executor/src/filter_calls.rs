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
	error::Result,
	indirect_calls::{CallWorkerArgs, ShiedFundsArgs},
	IndirectDispatch, IndirectExecutor,
};
use codec::{Decode, Encode};
use itp_node_api::{
	api_client::{ExtractCallIndexAndSignature, ParentchainUncheckedExtrinsic},
	metadata::{NodeMetadata, NodeMetadataTrait},
};

/// Trait to filter an indirect call and decode into it, where the decoding
/// is based on the metadata provided.
pub trait FilterCalls<NodeMetadata> {
	/// Call enum we try to decode into.
	type Call;

	/// Format of the parentchain extrinsics.
	///
	/// Needed to be able to find the call index in the encoded extrinsic.
	type ParentchainExtrinsic;

	/// Filters some bytes and returns `Some(Self::Call)` if the filter matches some criteria.
	fn filter_into_with_metadata(call: &mut &[u8], metadata: &NodeMetadata) -> Option<Self::Call>;
}

/// Indirect calls filter denying all indirect calls.
pub struct DenyAll;

impl FilterCalls<NodeMetadata> for DenyAll {
	type Call = ();
	type ParentchainExtrinsic = ();

	fn filter_into_with_metadata(_: &mut &[u8], _: &NodeMetadata) -> Option<Self::Call> {
		None
	}
}

/// Default filter we use for the Integritee-Parachain.
pub struct ShieldFundsAndCallWorkerFilter;

impl<NodeMetadata: NodeMetadataTrait> FilterCalls<NodeMetadata> for ShieldFundsAndCallWorkerFilter {
	type Call = IndirectCall;

	/// We only care about the signed extension type here for the decoding.
	///
	/// `()` is a trick to stop decoding after the call index. So the remaining
	/// bytes of `call` after decoding only contain the parentchain's dispatchable's
	/// arguments.
	type ParentchainExtrinsic = ParentchainUncheckedExtrinsic<([u8; 2], ())>;

	fn filter_into_with_metadata(call: &mut &[u8], metadata: &NodeMetadata) -> Option<Self::Call> {
		// Note: This mutates `call`. It will prune the `signature` and the `call_index` of the slice.
		let (_, index) = Self::ParentchainExtrinsic::extract_call_index_and_signature(call)?;

		if index == metadata.shield_funds_call_indexes().ok()? {
			let args = decode_and_log_error::<ShiedFundsArgs>(call)?;
			Some(IndirectCall::ShieldFunds(args))
		} else if index == metadata.call_worker_call_indexes().ok()? {
			let args = decode_and_log_error::<CallWorkerArgs>(call)?;
			Some(IndirectCall::CallWorker(args))
		} else {
			None
		}
	}
}

/// The default indirect call of the Integritee-Parachain.
///
/// Todo: Move or provide a template in app-libs such that users
/// can implemeent their own indirect call there.
#[derive(Debug, Clone, Encode, Decode, Eq, PartialEq)]
pub enum IndirectCall {
	ShieldFunds(ShiedFundsArgs),
	CallWorker(CallWorkerArgs),
}

impl<Executor: IndirectExecutor> IndirectDispatch<Executor> for IndirectCall {
	fn execute(&self, executor: &Executor) -> Result<()> {
		match self {
			IndirectCall::ShieldFunds(shieldfunds) => shieldfunds.execute(executor),
			IndirectCall::CallWorker(call_worker) => call_worker.execute(executor),
		}
	}
}

fn decode_and_log_error<V: Decode>(encoded: &mut &[u8]) -> Option<V> {
	match V::decode(encoded) {
		Ok(v) => Some(v),
		Err(e) => {
			log::warn!("Could not decode. {:?}", e);
			None
		},
	}
}
