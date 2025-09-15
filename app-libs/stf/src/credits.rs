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

// TrustedCalls and Getters for pallet-credits

use crate::{
	helpers::{shielding_target_genesis_hash, store_note},
	TrustedCall,
};
#[cfg(not(feature = "std"))]
use alloc::format;
use codec::{Decode, Encode};
use frame_support::dispatch::UnfilteredDispatchable;
use ita_parentchain_specs::MinimalChainSpec;
use ita_sgx_runtime::{CreditClassId, Credits, Runtime};
use itp_node_api::metadata::provider::AccessNodeMetadata;
use itp_node_api_metadata::NodeMetadataTrait;
use itp_sgx_runtime_primitives::types::{Balance, Moment, ShardIdentifier};
use itp_stf_interface::{ExecuteCall, ExecuteGetter};
use itp_stf_primitives::error::StfError;
use itp_types::{parentchain::ParentchainCall, AccountId, Hash};
use sp_std::{sync::Arc, vec, vec::Vec};

#[derive(Encode, Decode, Debug, Clone, PartialEq, Eq)]
pub struct CreditClassInfo {
	pub class_id: CreditClassId,
	pub admin: itp_stf_primitives::types::AccountId,
	pub total_minted: Balance,
	pub total_redeemed: Balance,
	pub total_deposit: Balance,
}

#[derive(Encode, Decode, Clone, Debug, PartialEq, Eq)]
#[allow(non_camel_case_types)]
#[repr(u8)]
#[allow(clippy::unnecessary_cast)]
pub enum CreditsTrustedCall {
	create_class(AccountId, CreditClassId) = 0,
	destroy_class(AccountId, CreditClassId) = 1,
	claim(AccountId, CreditClassId, Hash) = 2,
	mint(AccountId, CreditClassId, AccountId, Balance, Option<Moment>) = 3,
	redeem(AccountId, CreditClassId, AccountId, Balance) = 4,
}

impl CreditsTrustedCall {
	pub fn sender_account(&self) -> &AccountId {
		match self {
			Self::create_class(sender_account, ..) => sender_account,
			Self::destroy_class(sender_account, ..) => sender_account,
			Self::claim(sender_account, ..) => sender_account,
			Self::mint(sender_account, ..) => sender_account,
			Self::redeem(sender_account, ..) => sender_account,
		}
	}
}

impl<NodeMetadataRepository> ExecuteCall<NodeMetadataRepository> for CreditsTrustedCall
where
	NodeMetadataRepository: AccessNodeMetadata,
	NodeMetadataRepository::MetadataType: NodeMetadataTrait,
{
	type Error = StfError;

	fn execute(
		self,
		_calls: &mut Vec<ParentchainCall>,
		_shard: &ShardIdentifier,
		_node_metadata_repo: Arc<NodeMetadataRepository>,
	) -> Result<(), Self::Error> {
		match self.clone() {
			Self::create_class(who, class_id) => {
				let origin = ita_sgx_runtime::RuntimeOrigin::signed(who.clone());
				std::println!("⣿STF⣿ 🔄 credits_create_class by ⣿⣿⣿ class_id ⣿⣿⣿",);
				let deposit =
					MinimalChainSpec::one_unit(shielding_target_genesis_hash().unwrap_or_default())
						/ crate::STF_CREDITS_CLASS_DEPOSIT_DIVIDER;
				ita_sgx_runtime::CreditsCall::<Runtime>::create_class { id: class_id, deposit }
					.dispatch_bypass_filter(origin)
					.map_err(|e| {
						Self::Error::Dispatch(format!("Credits Create Class error: {:?}", e.error))
					})?;
				store_note(&who, TrustedCall::credits(self), vec![who.clone()])?;
				Ok(())
			},
			Self::destroy_class(who, class_id) => {
				let origin = ita_sgx_runtime::RuntimeOrigin::signed(who.clone());
				std::println!("⣿STF⣿ 🔄 credits_destroy_class by ⣿⣿⣿ class_id ⣿⣿⣿",);
				ita_sgx_runtime::CreditsCall::<Runtime>::destroy_class { id: class_id }
					.dispatch_bypass_filter(origin)
					.map_err(|e| {
						Self::Error::Dispatch(format!("Credits Destroy Class error: {:?}", e.error))
					})?;
				store_note(&who, TrustedCall::credits(self), vec![who.clone()])?;
				Ok(())
			},
			Self::claim(who, class_id, secret) => {
				let origin = ita_sgx_runtime::RuntimeOrigin::signed(who.clone());
				std::println!("⣿STF⣿ 🔄 credits_claim by ⣿⣿⣿ class_id ⣿⣿⣿ claim_hash ⣿⣿⣿",);
				let item_deposit =
					MinimalChainSpec::one_unit(shielding_target_genesis_hash().unwrap_or_default())
						/ crate::STF_CREDITS_ITEM_DEPOSIT_DIVIDER;
				ita_sgx_runtime::CreditsCall::<Runtime>::claim {
					id: class_id,
					secret,
					item_deposit,
				}
				.dispatch_bypass_filter(origin)
				.map_err(|e| {
					Self::Error::Dispatch(format!("Credits Claim error: {:?}", e.error))
				})?;
				store_note(&who, TrustedCall::credits(self), vec![who.clone()])?;
				Ok(())
			},
			Self::mint(who, class_id, owner, amount, maybe_expiry) => {
				let origin = ita_sgx_runtime::RuntimeOrigin::signed(who.clone());
				std::println!("⣿STF⣿ 🔄 credits_mint by ⣿⣿⣿ class_id ⣿⣿⣿ amount ⣿⣿⣿",);
				let item_deposit =
					MinimalChainSpec::one_unit(shielding_target_genesis_hash().unwrap_or_default())
						/ crate::STF_CREDITS_ITEM_DEPOSIT_DIVIDER;
				ita_sgx_runtime::CreditsCall::<Runtime>::mint {
					id: class_id,
					owner: owner.clone(),
					amount,
					maybe_expiry,
					item_deposit,
				}
				.dispatch_bypass_filter(origin)
				.map_err(|e| Self::Error::Dispatch(format!("Credits Mint error: {:?}", e.error)))?;
				store_note(&who, TrustedCall::credits(self), vec![who.clone(), owner])?;
				Ok(())
			},
			Self::redeem(who, class_id, owner, amount) => {
				let origin = ita_sgx_runtime::RuntimeOrigin::signed(who.clone());
				std::println!("⣿STF⣿ 🔄 credits_redeem by ⣿⣿⣿ class_id ⣿⣿⣿ amount ⣿⣿⣿",);
				let item_deposit =
					MinimalChainSpec::one_unit(shielding_target_genesis_hash().unwrap_or_default())
						/ crate::STF_CREDITS_ITEM_DEPOSIT_DIVIDER;
				ita_sgx_runtime::CreditsCall::<Runtime>::redeem {
					id: class_id,
					owner: owner.clone(),
					amount,
					item_deposit,
				}
				.dispatch_bypass_filter(origin)
				.map_err(|e| {
					Self::Error::Dispatch(format!("Credits Redeem error: {:?}", e.error))
				})?;
				store_note(&who, TrustedCall::credits(self), vec![who.clone(), owner])?;
				Ok(())
			},
		}?;
		Ok(())
	}
}

pub fn get_fee_for(_tc: &CreditsTrustedCall) -> Balance {
	let one = MinimalChainSpec::one_unit(shielding_target_genesis_hash().unwrap_or_default());
	one / crate::STF_TX_FEE_UNIT_DIVIDER
}

#[derive(Encode, Decode, Clone, Debug, PartialEq, Eq)]
#[allow(non_camel_case_types)]
pub enum CreditsPublicGetter {}

impl ExecuteGetter for CreditsPublicGetter {
	fn execute(self) -> Option<Vec<u8>> {
		None
	}
}

#[derive(Encode, Decode, Clone, Debug, PartialEq, Eq)]
#[allow(non_camel_case_types)]
pub enum CreditsTrustedGetter {
	credits { owner: AccountId, class_id: CreditClassId },
	credit_class_info { sender: AccountId, class_id: CreditClassId },
}

impl CreditsTrustedGetter {
	pub fn sender_account(&self) -> &AccountId {
		match self {
			Self::credits { owner, .. } => owner,
			Self::credit_class_info { sender, .. } => sender,
		}
	}
}

impl ExecuteGetter for CreditsTrustedGetter {
	fn execute(self) -> Option<Vec<u8>> {
		match self {
			Self::credits { owner, class_id } => Some(Credits::credits(class_id, &owner).encode()),
			Self::credit_class_info { sender, class_id } => {
				Credits::admin(class_id).filter(|admin| *admin == sender)?;
				let total_redeemed = Credits::total_redeemed_by(class_id, &sender);
				let total_minted = Credits::total_minted_by(class_id, &sender);
				let total_deposit = Credits::total_deposit(class_id);
				let info = CreditClassInfo {
					class_id,
					admin: sender,
					total_minted,
					total_redeemed,
					total_deposit,
				};
				Some(info.encode())
			},
		}
	}
}
