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

use codec::{Decode, Encode};
use core::marker::PhantomData;
use itp_api_client_types::Preamble;
use itp_node_api::api_client::{Address, CallIndex, PairSignature, UncheckedExtrinsic};

pub struct ExtrinsicParser<SignedExtra> {
	_phantom: PhantomData<SignedExtra>,
}

/// Partially interpreted extrinsic containing the `preamble` and the `call_index` whereas
/// the `call_args` remain in encoded form.
///
/// Intended for usage, where the actual `call_args` form is unknown.
pub struct SemiOpaqueExtrinsic<'a, TxExtension> {
	/// Signature of the Extrinsic.
	pub preamble: Preamble<TxExtension>,
	/// Call index of the dispatchable.
	pub call_index: CallIndex,
	/// Encoded arguments of the dispatchable corresponding to the `call_index`.
	pub call_args: &'a [u8],
}

/// Trait to extract signature and call indexes of an encoded [UncheckedExtrinsic].
pub trait ParseExtrinsic {
	/// Signed extra of the extrinsic.
	type SignedExtra;

	fn parse(encoded_call: &[u8]) -> Result<SemiOpaqueExtrinsic<Self::SignedExtra>, codec::Error>;
}

impl<SignedExtra> ParseExtrinsic for ExtrinsicParser<SignedExtra>
where
	SignedExtra: Decode + Encode,
{
	type SignedExtra = SignedExtra;

	/// Extract a call index of an encoded call.
	fn parse(encoded_call: &[u8]) -> Result<SemiOpaqueExtrinsic<Self::SignedExtra>, codec::Error> {
		let call_mut = &mut &encoded_call[..];

		// `()` is a trick to stop decoding after the call index. So the remaining bytes
		//  of `call` after decoding only contain the parentchain's dispatchable's arguments.
		let xt = UncheckedExtrinsic::<
            Address,
            (CallIndex, ()),
            PairSignature,
            Self::SignedExtra,
        >::decode(call_mut)?;

		Ok(SemiOpaqueExtrinsic {
			preamble: xt.preamble,
			call_index: xt.function.0,
			call_args: call_mut,
		})
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use itp_api_client_types::{ParentchainPlainTip, ParentchainSignature, ParentchainTxExtension};
	use itp_types::Nonce;
	use sp_core::crypto::AccountId32;
	use sp_runtime::{generic::Era, OpaqueExtrinsic};
	use substrate_api_client::ac_primitives::GenericTxExtension;

	#[test]
	#[allow(deprecated)]
	fn can_parse_v4_unsigned_extrinsic() {
		use substrate_api_client::ac_primitives::extrinsics::deprecated::UncheckedExtrinsicV4 as XTV4;

		let ex_v4: XTV4<Address, _, ParentchainSignature, ()> = XTV4::new_unsigned([1u8, 2u8]);

		let encoded = ex_v4.encode();

		let parsed = ExtrinsicParser::<ParentchainTxExtension>::parse(&encoded).unwrap();

		match parsed.preamble {
			Preamble::Bare(4) => (),
			other => panic!("unexpected preamble: {:?}", other),
		};

		assert_eq!(parsed.call_index, [1, 2]);
	}

	#[test]
	#[allow(deprecated)]
	fn can_parse_v4_signed_extrinsic() {
		use substrate_api_client::ac_primitives::extrinsics::deprecated::UncheckedExtrinsicV4 as XTV4;

		let (address, extension, signature) = get_default_signer_data();

		let ex_v4: XTV4<Address, _, ParentchainSignature, ParentchainTxExtension> =
			XTV4::new_signed([1u8, 2u8], address.clone(), signature.clone(), extension.clone());

		let encoded = ex_v4.encode();

		let parsed = ExtrinsicParser::<ParentchainTxExtension>::parse(&encoded).unwrap();

		match &parsed.preamble {
			Preamble::Signed(addr, sig, ext) => {
				assert_eq!(addr, &address);
				assert_eq!(sig, &signature);
				assert_eq!(ext, &extension);
			},
			other => panic!("unexpected preamble: {:?}", other),
		};

		assert_eq!(parsed.call_index, [1, 2]);
	}

	#[test]
	fn can_parse_v5_bare_extrinsic() {
		use substrate_api_client::ac_primitives::extrinsics::UncheckedExtrinsic as XTV5;

		let ex_v5: XTV5<Address, _, ParentchainSignature, ParentchainTxExtension> =
			XTV5::new_bare([1u8, 2u8, 0, 0, 0]);

		let encoded = ex_v5.encode();

		let parsed = ExtrinsicParser::<ParentchainTxExtension>::parse(&encoded).unwrap();

		match &parsed.preamble {
			Preamble::Bare(5) => {},
			other => panic!("unexpected preamble: {:?}", other),
		};

		assert_eq!(parsed.call_index, [1, 2]);
	}

	#[test]
	fn can_parse_v5_signed_extrinsic() {
		use substrate_api_client::ac_primitives::extrinsics::UncheckedExtrinsic as XTV5;

		let (address, extension, signature) = get_default_signer_data();

		let ex_v5: XTV5<Address, _, ParentchainSignature, ParentchainTxExtension> =
			XTV5::new_signed(
				[1u8, 2u8, 0, 0, 0],
				address.clone(),
				signature.clone(),
				extension.clone(),
			);

		let encoded = ex_v5.encode();

		let parsed = ExtrinsicParser::<ParentchainTxExtension>::parse(&encoded).unwrap();

		match &parsed.preamble {
			Preamble::Signed(addr, sig, ext) => {
				assert_eq!(addr, &address);
				assert_eq!(sig, &signature);
				assert_eq!(ext, &extension);
			},
			other => panic!("unexpected preamble: {:?}", other),
		};

		assert_eq!(parsed.call_index, [1, 2]);
	}

	#[test]
	fn can_parse_v5_general_transaction() {
		use substrate_api_client::ac_primitives::extrinsics::UncheckedExtrinsic as XTV5;

		let (_, extension, _) = get_default_signer_data();

		let ex_v5: XTV5<Address, _, ParentchainSignature, ParentchainTxExtension> =
			XTV5::new_transaction([1u8, 2u8, 0, 0, 0], extension.clone());

		let encoded = ex_v5.encode();

		let parsed = ExtrinsicParser::<ParentchainTxExtension>::parse(&encoded).unwrap();

		match &parsed.preamble {
			Preamble::General(extension_version, ext) => {
				assert_eq!(extension_version, &0);
				assert_eq!(ext, &extension);
			},
			other => panic!("unexpected preamble: {:?}", other),
		};

		assert_eq!(parsed.call_index, [1, 2]);
	}

	#[test]
	fn opaque_extrinsic_works() {
		use substrate_api_client::ac_primitives::extrinsics::UncheckedExtrinsic as XTV5;

		let (address, extension, signature) = get_default_signer_data();

		let ex_v5: XTV5<Address, _, ParentchainSignature, ParentchainTxExtension> =
			XTV5::new_signed(
				[1u8, 2u8, 0, 0, 0],
				address.clone(),
				signature.clone(),
				extension.clone(),
			);

		let encoded = ex_v5.encode();
		let opaque = OpaqueExtrinsic::from_bytes(&encoded).unwrap();

		assert_eq!(encoded, opaque.encode());

		let decoded: XTV5<Address, [u8; 5], ParentchainSignature, ParentchainTxExtension> =
			Decode::decode(&mut opaque.encode().as_slice()).unwrap();
		assert_eq!(ex_v5, decoded);
	}

	fn get_default_signer_data(
	) -> (Address, GenericTxExtension<ParentchainPlainTip, Nonce>, ParentchainSignature) {
		let address = Address::Id(AccountId32::new([0; 32]));
		let extension = ParentchainTxExtension::new(Era::Immortal, 1, Default::default());
		let signature =
			ParentchainSignature::Ed25519([0u8; 64].encode().as_slice().try_into().unwrap());

		(address, extension, signature)
	}
}
