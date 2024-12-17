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

#![cfg_attr(all(not(target_env = "sgx"), not(feature = "std")), no_std)]
#![cfg_attr(target_env = "sgx", feature(rustc_private))]

#[cfg(all(not(feature = "std"), feature = "sgx"))]
extern crate sgx_tstd as std;

use codec::{Decode, Encode};
use core::{fmt::Debug, marker::PhantomData};
use itp_types::parentchain::Hash;
use sp_core::{crypto::AccountId32, sr25519};
use sp_runtime::{MultiAddress, MultiSignature};
use substrate_api_client::ac_primitives::{
	BlakeTwo256, ExtrinsicSigner, SubstrateBlock, SubstrateHeader, SubstrateOpaqueExtrinsic,
};

use itp_api_client_types::{AssetTip, GenericSignedExtra, PlainTip};
pub use substrate_api_client::{
	ac_node_api::{
		metadata::{InvalidMetadataError, Metadata, MetadataError},
		EventDetails, Events, StaticEvent,
	},
	ac_primitives::{
		config::Config,
		extrinsics::{
			CallIndex, ExtrinsicParams, GenericAdditionalParams, GenericAdditionalSigned,
			GenericExtrinsicParams, UncheckedExtrinsicV4,
		},
		serde_impls::StorageKey,
		signer::{SignExtrinsic, StaticExtrinsicSigner},
	},
	rpc::Request,
	storage_key, Api,
};
#[cfg(feature = "std")]
pub mod event_subscriber;
pub mod extrinsic_parser;
pub mod indirect_calls;
pub mod integritee;
pub mod target_a;
pub mod target_b;

pub trait ParentchainInstance {}

#[derive(Debug, Clone, Encode, Decode, Eq, PartialEq)]
pub struct Integritee;
impl ParentchainInstance for Integritee {}

#[derive(Debug, Clone, Encode, Decode, Eq, PartialEq)]
pub struct TargetA;
impl ParentchainInstance for TargetA {}

#[derive(Debug, Clone, Encode, Decode, Eq, PartialEq)]
pub struct TargetB;
impl ParentchainInstance for TargetB {}

pub fn decode_and_log_error<V: Decode>(encoded: &mut &[u8]) -> Option<V> {
	match V::decode(encoded) {
		Ok(v) => Some(v),
		Err(e) => {
			log::warn!("Could not decode. {:?}: raw: {:?}", e, encoded);
			None
		},
	}
}

/// Config matching the specs of the typical polkadot chains.
/// We can define some more if we realize that we need more
/// granular control than the tip.
#[derive(Decode, Encode, Clone, Eq, PartialEq, Debug)]
pub struct ParentchainRuntimeConfig<Tip: Sized> {
	_phantom: PhantomData<Tip>,
}

impl<Tip> Config for ParentchainRuntimeConfig<Tip>
where
	u128: From<Tip>,
	Tip: Copy + Default + Encode + Debug,
{
	type Index = u32;
	type BlockNumber = u32;
	type Hash = Hash;
	type AccountId = AccountId32;
	type Address = MultiAddress<Self::AccountId, u32>;
	type Signature = MultiSignature;
	type Hasher = BlakeTwo256;
	type Header = SubstrateHeader<Self::BlockNumber, BlakeTwo256>;
	type AccountData = itp_types::AccountData;
	type ExtrinsicParams = GenericExtrinsicParams<Self, Tip>;
	type CryptoKey = sr25519::Pair;
	type ExtrinsicSigner = ExtrinsicSigner<Self>;
	type Block = SubstrateBlock<Self::Header, SubstrateOpaqueExtrinsic>;
	type Balance = itp_types::Balance;
	type ContractCurrency = u128;
	type StakingBalance = u128;
}
