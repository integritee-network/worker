use codec::{Decode, Encode};

/// Trait to filter an indirect call and decode into it, where the decoding
/// is based on the metadata provided.
pub trait FilterCalls<NodeMetadata> {
	type Call: Decode + Encode;
	/// Filters some bytes and returns `Some(Self::Target)` if the filter matches some criteria.
	fn filter_into_with_metadata(source: &mut [u8], metadata: &NodeMetadata) -> Option<Self::Call>;
}
