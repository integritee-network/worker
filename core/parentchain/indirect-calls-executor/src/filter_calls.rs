use crate::{
	error::Result,
	indirect_calls::{CallWorkerArgs, ShiedFundsArgs},
	IndirectDispatch, IndirectExecutor,
};
use codec::{Decode, Encode};
use itp_node_api::{
	api_client::{ExtractCallIndex, ParentchainUncheckedExtrinsic},
	metadata::NodeMetadataTrait,
};

/// Trait to filter an indirect call and decode into it, where the decoding
/// is based on the metadata provided.
pub trait FilterCalls<NodeMetadata> {
	/// Call enum the we try to decode into.
	type Call: Decode + Encode;

	/// Format of the parentchain extrinsics.
	///
	/// Needed to be able to find the call index in the encoded extrinsic.
	type ParentchainExtrinsic: ExtractCallIndex;

	/// Filters some bytes and returns `Some(Self::Target)` if the filter matches some criteria.
	fn filter_into_with_metadata(call: &mut &[u8], metadata: &NodeMetadata) -> Option<Self::Call>;
}

pub struct ShieldFundsAndCallWorkerFilter;

impl<NodeMetadata: NodeMetadataTrait> FilterCalls<NodeMetadata> for ShieldFundsAndCallWorkerFilter {
	type Call = IndirectCall;

	/// We only care about the signed extension type here for the decoding.
	///
	/// `()` is a trick to stop decoding after the call index. So the remaining
	/// entries of the `call` after decoding contain the parentchain's dispatchable's
	/// arguments only.
	type ParentchainExtrinsic = ParentchainUncheckedExtrinsic<([u8; 2], ())>;

	fn filter_into_with_metadata(call: &mut &[u8], metadata: &NodeMetadata) -> Option<Self::Call> {
		// Note: This mutates `call`. It will prune the `signature` and the `call_index` of the slice.
		let index = Self::ParentchainExtrinsic::extract_call_index(call)?;

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

pub fn decode_and_log_error<V: Decode>(encoded: &mut &[u8]) -> Option<V> {
	match V::decode(encoded) {
		Ok(v) => Some(v),
		Err(e) => {
			log::warn!("Could not decode. {:?}", e);
			None
		},
	}
}
