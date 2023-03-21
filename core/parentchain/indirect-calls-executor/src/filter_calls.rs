use codec::{Decode, Encode};
use itp_node_api::metadata::{NodeMetadata, NodeMetadataTrait};
use itp_types::{CallWorkerFn, ShieldFundsFn};

/// Trait to filter an indirect call and decode into it, where the decoding
/// is based on the metadata provided.
pub trait FilterCalls<NodeMetadata> {
	type Call: Decode + Encode;
	/// Filters some bytes and returns `Some(Self::Target)` if the filter matches some criteria.
	fn filter_into_with_metadata(call: &mut &[u8], metadata: &NodeMetadata) -> Option<Self::Call>;
}

pub struct ShieldFundsAndCallWorkerFilter;

impl<NodeMetadata: NodeMetadataTrait> FilterCalls<NodeMetadata> for ShieldFundsAndCallWorkerFilter {
	type Call = IndirectCall;

	fn filter_into_with_metadata(call: &mut &[u8], metadata: &NodeMetadata) -> Option<Self::Call> {
		// this will just skip the rest of the bytes.
		let index = <[u8; 2]>::decode(call).ok()?;

		if index == metadata.shield_funds_call_indexes().ok()? {
			Some(IndirectCall::ShieldFunds(Decode::decode(call).ok()?))
		} else if index == metadata.call_worker_call_indexes().ok()? {
			Some(IndirectCall::CallWorker(Decode::decode(call).ok()?))
		} else {
			None
		}
	}
}

#[derive(Debug, Clone, Encode, Decode, Eq, PartialEq)]
pub enum IndirectCall {
	ShieldFunds(ShieldFundsFn),
	CallWorker(CallWorkerFn),
}
