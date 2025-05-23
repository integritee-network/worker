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

#[cfg(feature = "evm")]
use sp_core::{H160, H256, U256};

#[cfg(feature = "evm")]
use std::vec::Vec;

#[cfg(feature = "evm")]
use crate::evm_helpers::{create_code_hash, evm_create2_address, evm_create_address};
use crate::{
	guess_the_number,
	guess_the_number::GuessTheNumberTrustedCall,
	helpers::{
		enclave_signer_account, ensure_enclave_signer_account, ensure_maintainer_account,
		get_mortality, shard_vault, shielding_target_genesis_hash, store_note, wrap_bytes,
	},
	Getter, STF_BYTE_FEE_UNIT_DIVIDER, STF_SESSION_PROXY_DEPOSIT_DIVIDER,
	STF_SHIELDING_FEE_AMOUNT_DIVIDER, STF_TX_FEE_UNIT_DIVIDER,
};
use codec::{Compact, Decode, Encode};
use frame_support::{
	ensure,
	traits::{fungibles::Inspect, UnfilteredDispatchable},
};
use ita_assets_map::{AssetId, AssetTranslation, FOREIGN_ASSETS, NATIVE_ASSETS};
use ita_parentchain_specs::MinimalChainSpec;
#[cfg(feature = "evm")]
use ita_sgx_runtime::{AddressMapping, HashedAddressMapping};
use ita_sgx_runtime::{
	Assets, ParentchainInstanceIntegritee, ParentchainInstanceTargetA, ParentchainInstanceTargetB,
	ParentchainIntegritee, Runtime, SessionProxyCredentials, SessionProxyRole, ShardManagement,
	System,
};
pub use ita_sgx_runtime::{Balance, Index};
use itp_node_api::metadata::{provider::AccessNodeMetadata, NodeMetadataTrait};
use itp_node_api_metadata::{
	frame_system::SystemCallIndexes,
	pallet_assets::{ForeignAssetsCallIndexes, NativeAssetsCallIndexes},
	pallet_balances::BalancesCallIndexes,
	pallet_enclave_bridge::EnclaveBridgeCallIndexes,
	pallet_proxy::ProxyCallIndexes,
};
use itp_stf_interface::ExecuteCall;
use itp_stf_primitives::{
	error::StfError,
	traits::{TrustedCallSigning, TrustedCallVerification},
	types::{AccountId, KeyPair, ShardIdentifier, Signature, TrustedOperation},
};
use itp_types::{
	parentchain::{GenericMortality, ParentchainCall, ParentchainId, ProxyType},
	Address, Moment, OpaqueCall,
};
use itp_utils::stringify::account_id_to_string;
use log::*;
use pallet_notes::{TimestampedTrustedNote, TrustedNote};
use sp_core::{
	blake2_256,
	crypto::{AccountId32, UncheckedFrom},
	ed25519,
};
use sp_runtime::{traits::Verify, MultiAddress, MultiSignature};
use std::{format, prelude::v1::*, sync::Arc, vec};

#[derive(Encode, Decode, Clone, Debug, PartialEq, Eq)]
#[allow(non_camel_case_types)]
#[repr(u8)]
#[allow(clippy::unnecessary_cast)]
pub enum TrustedCall {
	noop(AccountId) = 0,
	timestamp_set(AccountId, Moment, ParentchainId) = 1, // (Root, now)
	balance_transfer(AccountId, AccountId, Balance) = 2,
	balance_unshield(AccountId, AccountId, Balance, ShardIdentifier) = 3, // (AccountIncognito, BeneficiaryPublicAccount, Amount, Shard)
	balance_shield(AccountId, AccountId, Balance, ParentchainId) = 4, // (Root, AccountIncognito, Amount, origin parentchain)
	balance_transfer_with_note(AccountId, AccountId, Balance, Vec<u8>) = 5,
	balance_shield_through_enclave_bridge_pallet(AccountId, AccountId, Balance) = 6, // (Root, AccountIncognito, Amount)
	balance_unshield_through_enclave_bridge_pallet(AccountId, AccountId, Balance, ShardIdentifier) =
		7, // (AccountIncognito, BeneficiaryPublicAccount, Amount, Shard)
	note_bloat(AccountId, u32) = 10,
	waste_time(AccountId, u32) = 11,
	spam_extrinsics(AccountId, u32, ParentchainId) = 12,
	send_note(AccountId, AccountId, Vec<u8>) = 20,
	add_session_proxy(AccountId, AccountId, SessionProxyCredentials<Balance>) = 30,
	assets_transfer(AccountId, AccountId, AssetId, Balance) = 42,
	assets_unshield(AccountId, AccountId, AssetId, Balance, ShardIdentifier) = 43,
	assets_shield(AccountId, AccountId, AssetId, Balance, ParentchainId) = 44,
	assets_transfer_with_note(AccountId, AccountId, AssetId, Balance, Vec<u8>) = 45,
	force_unshield_all(AccountId, AccountId, Option<AssetId>) = 46, // (Root, Beneficiary, AssetId or native)
	guess_the_number(GuessTheNumberTrustedCall) = 50,
	#[cfg(feature = "evm")]
	evm_withdraw(AccountId, H160, Balance) = 90, // (Origin, Address EVM Account, Value)
	// (Origin, Source, Target, Input, Value, Gas limit, Max fee per gas, Max priority fee per gas, Nonce, Access list)
	#[cfg(feature = "evm")]
	evm_call(
		AccountId,
		H160,
		H160,
		Vec<u8>,
		U256,
		u64,
		U256,
		Option<U256>,
		Option<U256>,
		Vec<(H160, Vec<H256>)>,
	) = 91,
	// (Origin, Source, Init, Value, Gas limit, Max fee per gas, Max priority fee per gas, Nonce, Access list)
	#[cfg(feature = "evm")]
	evm_create(
		AccountId,
		H160,
		Vec<u8>,
		U256,
		u64,
		U256,
		Option<U256>,
		Option<U256>,
		Vec<(H160, Vec<H256>)>,
	) = 92,
	// (Origin, Source, Init, Salt, Value, Gas limit, Max fee per gas, Max priority fee per gas, Nonce, Access list)
	#[cfg(feature = "evm")]
	evm_create2(
		AccountId,
		H160,
		Vec<u8>,
		H256,
		U256,
		u64,
		U256,
		Option<U256>,
		Option<U256>,
		Vec<(H160, Vec<H256>)>,
	) = 93,
	#[cfg(any(feature = "test", test))]
	balance_set_balance(AccountId, AccountId, Balance, Balance) = 255,
}

impl TrustedCall {
	pub fn sender_account(&self) -> &AccountId {
		match self {
			Self::noop(sender_account) => sender_account,
			#[cfg(any(feature = "test", test))]
			Self::balance_set_balance(sender_account, ..) => sender_account,
			Self::balance_transfer(sender_account, ..) => sender_account,
			Self::balance_unshield(sender_account, ..) => sender_account,
			Self::balance_shield(sender_account, ..) => sender_account,
			Self::balance_transfer_with_note(sender_account, ..) => sender_account,
			Self::balance_shield_through_enclave_bridge_pallet(sender_account, ..) =>
				sender_account,
			Self::balance_unshield_through_enclave_bridge_pallet(sender_account, ..) =>
				sender_account,
			Self::timestamp_set(sender_account, ..) => sender_account,
			Self::send_note(sender_account, ..) => sender_account,
			Self::spam_extrinsics(sender_account, ..) => sender_account,
			Self::add_session_proxy(sender_account, ..) => sender_account,
			Self::note_bloat(sender_account, ..) => sender_account,
			Self::waste_time(sender_account, ..) => sender_account,
			Self::assets_transfer(sender_account, ..) => sender_account,
			Self::assets_unshield(sender_account, ..) => sender_account,
			Self::assets_shield(sender_account, ..) => sender_account,
			Self::assets_transfer_with_note(sender_account, ..) => sender_account,
			#[cfg(feature = "evm")]
			Self::evm_withdraw(sender_account, ..) => sender_account,
			#[cfg(feature = "evm")]
			Self::evm_call(sender_account, ..) => sender_account,
			#[cfg(feature = "evm")]
			Self::evm_create(sender_account, ..) => sender_account,
			#[cfg(feature = "evm")]
			Self::evm_create2(sender_account, ..) => sender_account,
			Self::guess_the_number(call) => call.sender_account(),
			Self::force_unshield_all(sender_account, ..) => sender_account,
		}
	}
}

impl TrustedCallSigning<TrustedCallSigned> for TrustedCall {
	fn sign(
		&self,
		pair: &KeyPair,
		nonce: Index,
		mrenclave: &[u8; 32],
		shard: &ShardIdentifier,
	) -> TrustedCallSigned {
		let delegate = if pair.account_id() == *self.sender_account() {
			None
		} else {
			Some(pair.account_id())
		};
		let mut payload = self.encode();
		payload.append(&mut nonce.encode());
		payload.append(&mut mrenclave.encode());
		payload.append(&mut shard.encode());

		TrustedCallSigned {
			call: self.clone(),
			nonce,
			delegate,
			signature: pair.sign(payload.as_slice()),
		}
	}
}

#[derive(Encode, Decode, Clone, Debug, PartialEq, Eq)]
pub struct TrustedCallSigned {
	pub call: TrustedCall,
	pub nonce: Index,
	pub delegate: Option<AccountId>,
	pub signature: Signature,
}

impl TrustedCallSigned {
	pub fn new(
		call: TrustedCall,
		nonce: Index,
		delegate: Option<AccountId>,
		signature: Signature,
	) -> Self {
		TrustedCallSigned { call, nonce, delegate, signature }
	}

	pub fn into_trusted_operation(
		self,
		direct: bool,
	) -> TrustedOperation<TrustedCallSigned, Getter> {
		match direct {
			true => TrustedOperation::direct_call(self),
			false => TrustedOperation::indirect_call(self),
		}
	}
}

impl Default for TrustedCallSigned {
	fn default() -> Self {
		Self {
			call: TrustedCall::noop(AccountId32::unchecked_from([0u8; 32].into())),
			nonce: 0,
			delegate: None,
			signature: MultiSignature::Ed25519(ed25519::Signature::unchecked_from([0u8; 64])),
		}
	}
}
impl TrustedCallVerification for TrustedCallSigned {
	fn sender_account(&self) -> &AccountId {
		self.call.sender_account()
	}

	fn nonce(&self) -> Index {
		self.nonce
	}

	fn verify_signature(&self, mrenclave: &[u8; 32], shard: &ShardIdentifier) -> bool {
		let mut payload = self.call.encode();
		payload.append(&mut self.nonce.encode());
		payload.append(&mut mrenclave.encode());
		payload.append(&mut shard.encode());

		let signer = self.delegate.as_ref().unwrap_or_else(|| self.call.sender_account());
		if self.signature.verify(payload.as_slice(), signer) {
			return true
		};

		// check if the signature is from an extension-dapp signer.
		self.signature.verify(wrap_bytes(&payload).as_slice(), signer)
	}
}

// TODO: #91 signed return value
/*
pub struct TrustedReturnValue<T> {
	pub value: T,
	pub signer: AccountId
}

impl TrustedReturnValue
*/

impl<NodeMetadataRepository> ExecuteCall<NodeMetadataRepository> for TrustedCallSigned
where
	NodeMetadataRepository: AccessNodeMetadata,
	NodeMetadataRepository::MetadataType: NodeMetadataTrait,
{
	type Error = StfError;

	fn execute(
		self,
		calls: &mut Vec<ParentchainCall>,
		shard: &ShardIdentifier,
		node_metadata_repo: Arc<NodeMetadataRepository>,
	) -> Result<(), Self::Error> {
		let _role = ensure_authorization(&self)?;
		// todo! spending limits according to role https://github.com/integritee-network/worker/issues/1656

		let sender = self.call.sender_account().clone();
		let call_hash = blake2_256(&self.call.encode());
		let system_nonce = System::account_nonce(&sender);
		ensure!(self.nonce == system_nonce, Self::Error::InvalidNonce(self.nonce, system_nonce));

		// try to charge fee first and fail early
		charge_fee_in_available_asset(&self)?;

		// increment the nonce, no matter if the call succeeds or fails.
		// The call must have entered the transaction pool already,
		// so it should be considered as valid
		System::inc_account_nonce(&sender);

		ensure!(may_execute(&self), Self::Error::Filtered);

		match self.call.clone() {
			TrustedCall::noop(who) => {
				debug!("noop called by {}", account_id_to_string(&who),);
				Ok::<(), Self::Error>(())
			},
			#[cfg(any(feature = "test", test))]
			TrustedCall::balance_set_balance(root, who, free_balance, reserved_balance) => {
				ensure!(is_root::<Runtime, AccountId>(&root), Self::Error::MissingPrivileges(root));
				debug!(
					"balance_set_balance({}, {}, {})",
					account_id_to_string(&who),
					free_balance,
					reserved_balance
				);
				ita_sgx_runtime::BalancesCall::<Runtime>::force_set_balance {
					who: MultiAddress::Id(who.clone()),
					new_free: free_balance,
				}
				.dispatch_bypass_filter(ita_sgx_runtime::RuntimeOrigin::root())
				.map_err(|e| {
					Self::Error::Dispatch(format!("Balance Set Balance error: {:?}", e.error))
				})?;
				store_note(&root, self.call, vec![who])?;
				// This explicit Error type is somehow still needed, otherwise the compiler complains
				// 	multiple `impl`s satisfying `StfError: std::convert::From<_>`
				// 		note: and another `impl` found in the `core` crate: `impl<T> std::convert::From<T> for T;`
				// the impl From<..> for StfError conflicts with the standard convert
				//
				// Alternatively, removing the customised "impl From<..> for StfError" and use map_err directly
				// would also work
				Ok::<(), Self::Error>(())
			},
			TrustedCall::balance_transfer(from, to, value) => {
				let origin = ita_sgx_runtime::RuntimeOrigin::signed(from.clone());
				std::println!("⣿STF⣿ 🔄 balance_transfer from ⣿⣿⣿ to ⣿⣿⣿ amount ⣿⣿⣿");
				ita_sgx_runtime::BalancesCall::<Runtime>::transfer {
					dest: MultiAddress::Id(to.clone()),
					value,
				}
				.dispatch_bypass_filter(origin)
				.map_err(|e| {
					Self::Error::Dispatch(format!("Balance Transfer error: {:?}", e.error))
				})?;
				store_note(&from, self.call, vec![from.clone(), to])?;
				Ok(())
			},
			TrustedCall::balance_transfer_with_note(from, to, value, _note) => {
				let origin = ita_sgx_runtime::RuntimeOrigin::signed(from.clone());
				std::println!("⣿STF⣿ 🔄 balance_transfer from ⣿⣿⣿ to ⣿⣿⣿ amount ⣿⣿⣿ with note ⣿⣿⣿");
				ita_sgx_runtime::BalancesCall::<Runtime>::transfer {
					dest: MultiAddress::Id(to.clone()),
					value,
				}
				.dispatch_bypass_filter(origin)
				.map_err(|e| {
					Self::Error::Dispatch(format!("Balance Transfer error: {:?}", e.error))
				})?;
				store_note(&from, self.call, vec![from.clone(), to])?;
				Ok(())
			},
			TrustedCall::balance_unshield(account_incognito, beneficiary, value, call_shard) => {
				if *shard != call_shard {
					return Err(StfError::Dispatch("wrong shard".to_string()))
				}
				let parentchain_call = parentchain_vault_proxy_call(
					unshield_native_from_vault_parentchain_call(
						&beneficiary,
						value,
						node_metadata_repo.clone(),
					)?,
					node_metadata_repo,
				)?;
				std::println!(
					"⣿STF⣿ 🛡👐 balance_unshield from ⣿⣿⣿ to {}, amount {}",
					account_id_to_string(&beneficiary),
					value
				);
				info!(
					"balance_unshield(from (L2): {}, to (L1): {}, amount {}, shard {})",
					account_id_to_string(&account_incognito),
					account_id_to_string(&beneficiary),
					value,
					shard
				);
				// now that the above hasn't failed, we can execute
				burn_funds(&account_incognito, value)?;
				let _ = store_note(
					&account_incognito,
					self.call,
					vec![account_incognito.clone(), beneficiary],
				);
				calls.push(parentchain_call);
				Ok(())
			},
			TrustedCall::balance_unshield_through_enclave_bridge_pallet(
				account_incognito,
				beneficiary,
				value,
				call_shard,
			) => {
				if shard_vault().is_some() {
					return Err(StfError::Dispatch(
						"shard vault key has been set. you may not use enclave bridge".to_string(),
					))
				};
				if *shard != call_shard {
					return Err(StfError::Dispatch("wrong shard".to_string()))
				}
				let call = OpaqueCall::from_tuple(&(
					node_metadata_repo
						.get_from_metadata(|m| m.unshield_funds_call_indexes())
						.map_err(|_| StfError::InvalidMetadata)?
						.map_err(|_| StfError::InvalidMetadata)?,
					shard,
					beneficiary.clone(),
					value,
					call_hash,
				));
				std::println!(
					"⣿STF⣿ 🛡👐 balance_unshield through enclave bridge pallet from ⣿⣿⣿ to {}, amount {}",
					account_id_to_string(&beneficiary),
					value
				);
				info!(
					"balance_unshield(from (L2): {}, to (L1): {}, amount {})",
					account_id_to_string(&account_incognito),
					account_id_to_string(&beneficiary),
					value,
				);
				// now that the above hasn't failed, we can execute
				burn_funds(&account_incognito, value)?;
				let _ = store_note(
					&account_incognito,
					self.call,
					vec![account_incognito.clone(), beneficiary],
				);
				let mortality = get_mortality(ParentchainId::Integritee, 32)
					.unwrap_or_else(GenericMortality::immortal);
				let parentchain_call = ParentchainCall::Integritee { call, mortality };
				calls.push(parentchain_call);
				Ok(())
			},
			TrustedCall::balance_shield(enclave_account, who, value, parentchain_id) => {
				ensure_enclave_signer_account(&enclave_account)?;
				debug!(
					"balance_shield({}, {}, {:?})",
					account_id_to_string(&who),
					value,
					parentchain_id
				);
				let (_vault_account, vault_parentchain_id) =
					shard_vault().ok_or(StfError::NoShardVaultAssigned)?;
				ensure!(
					parentchain_id == vault_parentchain_id,
					StfError::WrongParentchainIdForShardVault
				);
				std::println!("⣿STF⣿ 🛡 will shield to {}", account_id_to_string(&who));
				store_note(&enclave_account, self.call, vec![who.clone()])?;
				shield_funds(&who, value)?;
				Ok(())
			},
			TrustedCall::balance_shield_through_enclave_bridge_pallet(
				enclave_account,
				who,
				value,
			) => {
				ensure_enclave_signer_account(&enclave_account)?;
				debug!(
					"balance_shield_through_enclave_bridge_pallet({}, {})",
					account_id_to_string(&who),
					value,
				);
				ensure!(
					shard_vault().is_none(),
					StfError::EnclaveBridgeShieldingDisabledIfVaultAssigned
				);
				std::println!("⣿STF⣿ 🛡 will shield to {}", account_id_to_string(&who));
				shield_funds(&who, value)?;
				store_note(&enclave_account, self.call, vec![who])?;
				Ok(())
			},
			TrustedCall::timestamp_set(enclave_account, now, parentchain_id) => {
				ensure_enclave_signer_account(&enclave_account)?;
				debug!("timestamp_set({}, {:?})", now, parentchain_id);
				match parentchain_id {
					ParentchainId::Integritee => {
						if ParentchainIntegritee::creation_timestamp().is_none() {
							debug!(
								"initializing creation timestamp({}, {:?})",
								now, parentchain_id
							);
							ita_sgx_runtime::ParentchainPalletCall::<
								Runtime,
								ParentchainInstanceIntegritee,
							>::set_creation_timestamp {
								creation: now,
							}
							.dispatch_bypass_filter(ita_sgx_runtime::RuntimeOrigin::root())
							.map_err(|e| {
								Self::Error::Dispatch(format!("Timestamp Set error: {:?}", e.error))
							})?;
						};
						ita_sgx_runtime::ParentchainPalletCall::<
							Runtime,
							ParentchainInstanceIntegritee,
						>::set_now {
							now,
						}
						.dispatch_bypass_filter(ita_sgx_runtime::RuntimeOrigin::root())
						.map_err(|e| {
							Self::Error::Dispatch(format!("Timestamp Set error: {:?}", e.error))
						})?
					},
					ParentchainId::TargetA => ita_sgx_runtime::ParentchainPalletCall::<
						Runtime,
						ParentchainInstanceTargetA,
					>::set_now {
						now,
					}
					.dispatch_bypass_filter(ita_sgx_runtime::RuntimeOrigin::root())
					.map_err(|e| {
						Self::Error::Dispatch(format!("Timestamp Set error: {:?}", e.error))
					})?,
					ParentchainId::TargetB => ita_sgx_runtime::ParentchainPalletCall::<
						Runtime,
						ParentchainInstanceTargetB,
					>::set_now {
						now,
					}
					.dispatch_bypass_filter(ita_sgx_runtime::RuntimeOrigin::root())
					.map_err(|e| {
						Self::Error::Dispatch(format!("Timestamp Set error: {:?}", e.error))
					})?,
				};
				Ok(())
			},
			TrustedCall::note_bloat(sender, kilobytes) => {
				ensure_maintainer_account(&sender)?;
				if kilobytes >= 1_100 {
					return Err(StfError::Dispatch("bloat value must be below 1.1 MB".to_string()))
				}
				std::println!("⣿STF⣿ bloating notes by {}kB", kilobytes);
				// make sure we use exactly 512 bytes per note
				let dummy = TimestampedTrustedNote {
					timestamp: 0u64,
					version: 0u16,
					note: TrustedNote::String(vec![0u8; 400]),
				};
				let msg = vec![111u8; 512 - (dummy.encoded_size() - 400)];
				for _ in 0..kilobytes * 2 {
					ita_sgx_runtime::NotesCall::<Runtime>::note_string {
						link_to: vec![],
						payload: msg.clone(),
					}
					.dispatch_bypass_filter(ita_sgx_runtime::RuntimeOrigin::signed(sender.clone()))
					.map_err(|e| StfError::Dispatch(format!("Store note error: {:?}", e.error)))?;
				}
				Ok(())
			},
			TrustedCall::waste_time(sender, milliseconds) => {
				ensure_maintainer_account(&sender)?;
				if milliseconds > 10_000 {
					return Err(StfError::Dispatch("waste time value must be below 10s".to_string()))
				}
				std::println!("⣿STF⣿ waste time: {}ms", milliseconds);
				std::thread::sleep(std::time::Duration::from_millis(milliseconds as u64));
				std::println!("⣿STF⣿ finished wasting time");
				Ok(())
			},
			TrustedCall::spam_extrinsics(sender, number_of_extrinsics, parentchain_id) => {
				ensure_maintainer_account(&sender)?;
				std::println!(
					"⣿STF⣿ spam {} extrinsics to {:?}",
					number_of_extrinsics,
					parentchain_id
				);
				let mortality =
					get_mortality(parentchain_id, 32).unwrap_or_else(GenericMortality::immortal);
				for i in 0..number_of_extrinsics {
					debug!("preparing spam extrnisic {}", i);
					let call = OpaqueCall::from_tuple(&(
						node_metadata_repo
							.get_from_metadata(|m| m.remark_call_indexes())
							.map_err(|_| StfError::InvalidMetadata)?
							.map_err(|_| StfError::InvalidMetadata)?,
						b"This is some dummy remark to spam extrinsics which should cause each extrinsic to be of size 512 kB ASDFGH1234567890123456789012345678901234567890".to_vec(),
					));
					let pcall = match parentchain_id {
						ParentchainId::Integritee =>
							ParentchainCall::Integritee { call, mortality: mortality.clone() },
						ParentchainId::TargetA =>
							ParentchainCall::TargetA { call, mortality: mortality.clone() },
						ParentchainId::TargetB =>
							ParentchainCall::TargetB { call, mortality: mortality.clone() },
					};
					calls.push(pcall);
				}
				Ok(())
			},
			TrustedCall::send_note(from, to, _note) => {
				let _origin = ita_sgx_runtime::RuntimeOrigin::signed(from.clone());
				std::println!("⣿STF⣿ 🔄 send_note from ⣿⣿⣿ to ⣿⣿⣿ with note ⣿⣿⣿");
				store_note(&from, self.call, vec![from.clone(), to])?;
				Ok(())
			},
			TrustedCall::add_session_proxy(delegator, delegate, credentials) => {
				let origin = ita_sgx_runtime::RuntimeOrigin::signed(delegator.clone());
				std::println!("⣿STF⣿ 🔄 add_proxy delegator ⣿⣿⣿ delegate ⣿⣿⣿");
				let deposit =
					MinimalChainSpec::one_unit(shielding_target_genesis_hash().unwrap_or_default())
						/ STF_SESSION_PROXY_DEPOSIT_DIVIDER;
				ita_sgx_runtime::SessionProxyCall::<Runtime>::add_proxy {
					delegate,
					credentials,
					deposit,
				}
				.dispatch_bypass_filter(origin)
				.map_err(|e| {
					Self::Error::Dispatch(format!("SessionProxy add error: {:?}", e.error))
				})?;
				store_note(&delegator, self.call, vec![delegator.clone()])?;
				Ok(())
			},
			TrustedCall::assets_transfer(from, to, id, amount) => {
				let origin = ita_sgx_runtime::RuntimeOrigin::signed(from.clone());
				std::println!("⣿STF⣿ 🔄 assets_transfer from ⣿⣿⣿ to ⣿⣿⣿ amount ⣿⣿⣿ {:?}", id);
				ita_sgx_runtime::AssetsCall::<Runtime>::transfer {
					id,
					target: MultiAddress::Id(to.clone()),
					amount,
				}
				.dispatch_bypass_filter(origin)
				.map_err(|e| {
					Self::Error::Dispatch(format!("assets_transfer error: {:?}", e.error))
				})?;
				store_note(&from, self.call, vec![from.clone(), to])?;
				Ok(())
			},
			TrustedCall::assets_transfer_with_note(from, to, id, amount, _note) => {
				let origin = ita_sgx_runtime::RuntimeOrigin::signed(from.clone());
				std::println!(
					"⣿STF⣿ 🔄 assets_transfer from ⣿⣿⣿ to ⣿⣿⣿ amount ⣿⣿⣿ with note ⣿⣿⣿ {:?}",
					id
				);
				ita_sgx_runtime::AssetsCall::<Runtime>::transfer {
					id,
					target: MultiAddress::Id(to.clone()),
					amount,
				}
				.dispatch_bypass_filter(origin)
				.map_err(|e| {
					Self::Error::Dispatch(format!("assets_transfer error: {:?}", e.error))
				})?;
				store_note(&from, self.call, vec![from.clone(), to])?;
				Ok(())
			},
			TrustedCall::assets_unshield(
				account_incognito,
				beneficiary,
				asset_id,
				value,
				call_shard,
			) => {
				if !asset_id.is_shieldable(shielding_target_genesis_hash().unwrap_or_default()) {
					error!("preventing to unshield unsupported asset: {:?}", asset_id);
					return Err(StfError::Dispatch("unsuppoted asset for un/shielding".into()))
				}
				if *shard != call_shard {
					return Err(StfError::Dispatch("wrong shard".to_string()))
				}
				std::println!(
					"⣿STF⣿ 🛡👐 assets_unshield, from ⣿⣿⣿ to {}, amount {} {:?}",
					account_id_to_string(&beneficiary),
					value,
					asset_id
				);
				info!(
					"assets_unshield(from (L2): {}, to (L1): {}, amount {})",
					account_id_to_string(&account_incognito),
					account_id_to_string(&beneficiary),
					value
				);
				let parentchain_call = parentchain_vault_proxy_call(
					unshield_assets_parentchain_call(
						&beneficiary,
						value,
						asset_id,
						node_metadata_repo.clone(),
					)?,
					node_metadata_repo,
				)?;
				// now that all the above hasn't failed, we can execute
				burn_assets(&account_incognito, value, asset_id)?;
				store_note(
					&account_incognito,
					self.call,
					vec![account_incognito.clone(), beneficiary],
				)?;
				calls.push(parentchain_call);
				Ok(())
			},
			TrustedCall::assets_shield(enclave_account, who, asset_id, value, parentchain_id) => {
				ensure_enclave_signer_account(&enclave_account)?;
				if !asset_id.is_shieldable(shielding_target_genesis_hash().unwrap_or_default()) {
					error!("preventing to shield unsupported asset: {:?}", asset_id);
					return Err(StfError::Dispatch("unsuppoted asset for shielding".into()))
				}
				debug!(
					"assets_shield({}, {}, {:?}, {:?})",
					account_id_to_string(&who),
					value,
					asset_id,
					parentchain_id
				);
				let (_vault_account, vault_parentchain_id) =
					shard_vault().ok_or(StfError::NoShardVaultAssigned)?;
				ensure!(
					parentchain_id == vault_parentchain_id,
					StfError::WrongParentchainIdForShardVault
				);
				std::println!("⣿STF⣿ 🛡 will shield assets to {}", account_id_to_string(&who));
				store_note(&enclave_account, self.call, vec![who.clone()])?;
				shield_assets(&who, value, asset_id)?;
				Ok(())
			},
			#[cfg(feature = "evm")]
			TrustedCall::evm_withdraw(from, address, value) => {
				debug!("evm_withdraw({}, {}, {})", account_id_to_string(&from), address, value);
				ita_sgx_runtime::EvmCall::<Runtime>::withdraw { address, value }
					.dispatch_bypass_filter(ita_sgx_runtime::RuntimeOrigin::signed(from))
					.map_err(|e| {
						Self::Error::Dispatch(format!("Evm Withdraw error: {:?}", e.error))
					})?;
				Ok(())
			},
			#[cfg(feature = "evm")]
			TrustedCall::evm_call(
				from,
				source,
				target,
				input,
				value,
				gas_limit,
				max_fee_per_gas,
				max_priority_fee_per_gas,
				nonce,
				access_list,
			) => {
				debug!(
					"evm_call(from: {}, source: {}, target: {})",
					account_id_to_string(&from),
					source,
					target
				);
				ita_sgx_runtime::EvmCall::<Runtime>::call {
					source,
					target,
					input,
					value,
					gas_limit,
					max_fee_per_gas,
					max_priority_fee_per_gas,
					nonce,
					access_list,
				}
				.dispatch_bypass_filter(ita_sgx_runtime::RuntimeOrigin::signed(from))
				.map_err(|e| Self::Error::Dispatch(format!("Evm Call error: {:?}", e.error)))?;
				Ok(())
			},
			#[cfg(feature = "evm")]
			TrustedCall::evm_create(
				from,
				source,
				init,
				value,
				gas_limit,
				max_fee_per_gas,
				max_priority_fee_per_gas,
				nonce,
				access_list,
			) => {
				debug!(
					"evm_create(from: {}, source: {}, value: {})",
					account_id_to_string(&from),
					source,
					value
				);
				let nonce_evm_account =
					System::account_nonce(&HashedAddressMapping::into_account_id(source));
				ita_sgx_runtime::EvmCall::<Runtime>::create {
					source,
					init,
					value,
					gas_limit,
					max_fee_per_gas,
					max_priority_fee_per_gas,
					nonce,
					access_list,
				}
				.dispatch_bypass_filter(ita_sgx_runtime::RuntimeOrigin::signed(from))
				.map_err(|e| Self::Error::Dispatch(format!("Evm Create error: {:?}", e.error)))?;
				let contract_address = evm_create_address(source, nonce_evm_account);
				info!("Trying to create evm contract with address {:?}", contract_address);
				Ok(())
			},
			#[cfg(feature = "evm")]
			TrustedCall::evm_create2(
				from,
				source,
				init,
				salt,
				value,
				gas_limit,
				max_fee_per_gas,
				max_priority_fee_per_gas,
				nonce,
				access_list,
			) => {
				debug!(
					"evm_create2(from: {}, source: {}, value: {})",
					account_id_to_string(&from),
					source,
					value
				);
				let code_hash = create_code_hash(&init);
				ita_sgx_runtime::EvmCall::<Runtime>::create2 {
					source,
					init,
					salt,
					value,
					gas_limit,
					max_fee_per_gas,
					max_priority_fee_per_gas,
					nonce,
					access_list,
				}
				.dispatch_bypass_filter(ita_sgx_runtime::RuntimeOrigin::signed(from))
				.map_err(|e| Self::Error::Dispatch(format!("Evm Create2 error: {:?}", e.error)))?;
				let contract_address = evm_create2_address(source, salt, code_hash);
				info!("Trying to create evm contract with address {:?}", contract_address);
				Ok(())
			},
			TrustedCall::guess_the_number(call) => call.execute(calls, shard, node_metadata_repo),
			TrustedCall::force_unshield_all(enclave_account, who, maybe_asset_id) => {
				ensure_enclave_signer_account(&enclave_account)?;
				if let Some(asset_id) = maybe_asset_id {
					let balance = Assets::balance(asset_id, &who);
					let unshield_amount =
						balance.saturating_sub(asset_id.one_unit() / STF_TX_FEE_UNIT_DIVIDER * 3);
					let parentchain_call = parentchain_vault_proxy_call(
						unshield_assets_parentchain_call(
							&who,
							unshield_amount,
							asset_id,
							node_metadata_repo.clone(),
						)?,
						node_metadata_repo,
					)?;
					std::println!(
						"⣿STF⣿ 🛡👐 force unshield all from (L2): {}, to (L1), value {} {:?} ",
						account_id_to_string(&who),
						unshield_amount,
						asset_id
					);
					// now that all the above hasn't failed, we can execute
					store_note(&who, self.call, vec![who.clone()])?;
					burn_assets(&who, balance, asset_id)?;
					if unshield_amount > 0 {
						calls.push(parentchain_call);
					}
				} else {
					let info = System::account(&who);
					if info.consumers > 0 {
						// we can't unshield if there are still consumers. Try to remove them first
						// remove session proxies and free deposit
						pallet_session_proxy::SessionProxies::<Runtime>::iter_key_prefix(&who)
							.for_each(|delegate| {
								ita_sgx_runtime::SessionProxyCall::<Runtime>::remove_proxy {
									delegate,
								}
								.dispatch_bypass_filter(ita_sgx_runtime::RuntimeOrigin::signed(
									who.clone(),
								))
								.map_err(|e| {
									Self::Error::Dispatch(format!(
										"removing session proxy failed: {:?}",
										e.error
									))
								})
								.ok(); // ignore error and continue
							})
					}
					let balance = info.data.free;
					let unshield_amount = balance.saturating_sub(
						MinimalChainSpec::one_unit(
							shielding_target_genesis_hash().unwrap_or_default(),
						) / STF_TX_FEE_UNIT_DIVIDER * 3,
					);
					let parentchain_call = parentchain_vault_proxy_call(
						unshield_native_from_vault_parentchain_call(
							&who,
							unshield_amount,
							node_metadata_repo.clone(),
						)?,
						node_metadata_repo,
					)?;
					std::println!(
						"⣿STF⣿ 🛡👐 force unshield all for {}, value {} native",
						account_id_to_string(&who),
						unshield_amount,
					);
					// now that all the above hasn't failed, we can execute
					store_note(&who, self.call, vec![who.clone()])?;
					ita_sgx_runtime::BalancesCall::<Runtime>::force_set_balance {
						who: MultiAddress::Id(who),
						new_free: 0,
					}
					.dispatch_bypass_filter(ita_sgx_runtime::RuntimeOrigin::root())
					.map_err(|e| {
						Self::Error::Dispatch(format!("Balance burn balance error: {:?}", e.error))
					})?;
					if unshield_amount > 0 {
						calls.push(parentchain_call);
					}
				}
				Ok(())
			},
		}?;
		Ok(())
	}
}

#[derive(Debug, Copy, Clone)]
enum Fee {
	Free,
	Native(Balance),
	Asset(Balance, AssetId),
}
fn get_fee_for(tc: &TrustedCallSigned, fee_asset: Option<AssetId>) -> Fee {
	let one = match fee_asset {
		None => MinimalChainSpec::one_unit(shielding_target_genesis_hash().unwrap_or_default()),
		Some(asset_id) => asset_id.one_unit(),
	};
	let fee_amount = match &tc.call {
		TrustedCall::balance_transfer(..) => one / STF_TX_FEE_UNIT_DIVIDER,
		TrustedCall::balance_transfer_with_note(_, _, _, note) =>
			one / STF_TX_FEE_UNIT_DIVIDER
				+ (one.saturating_mul(Balance::from(note.len() as u32))) / STF_BYTE_FEE_UNIT_DIVIDER,
		TrustedCall::balance_unshield(..) => one / STF_TX_FEE_UNIT_DIVIDER * 3,
		TrustedCall::guess_the_number(call) => guess_the_number::get_fee_for(call), // asset fees not supported here
		TrustedCall::note_bloat(..) => 0,
		TrustedCall::waste_time(..) => 0,
		TrustedCall::spam_extrinsics(..) => 0,
		TrustedCall::timestamp_set(..) => 0,
		TrustedCall::balance_shield(..) => 0, //will be charged on recipient, elsewhere
		TrustedCall::balance_shield_through_enclave_bridge_pallet(..) => 0, //will be charged on recipient, elsewhere
		TrustedCall::assets_shield(..) => 0, //will be charged on recipient, elsewhere,
		TrustedCall::assets_unshield(..) => one / STF_TX_FEE_UNIT_DIVIDER * 3,
		TrustedCall::balance_unshield_through_enclave_bridge_pallet(..) =>
			one / STF_TX_FEE_UNIT_DIVIDER * 3,
		TrustedCall::assets_transfer_with_note(_, _, _asset_id, _, note) =>
			one / STF_TX_FEE_UNIT_DIVIDER
				+ (one.saturating_mul(Balance::from(note.len() as u32))) / STF_BYTE_FEE_UNIT_DIVIDER,
		TrustedCall::assets_transfer(_, _, _asset_id, ..) => one / STF_TX_FEE_UNIT_DIVIDER,
		TrustedCall::force_unshield_all(..) => 0, // root call, will be charged on affected account
		TrustedCall::add_session_proxy(..) => one / STF_TX_FEE_UNIT_DIVIDER,
		TrustedCall::send_note(..) => one / STF_TX_FEE_UNIT_DIVIDER,
		#[cfg(feature = "evm")]
		TrustedCall::evm_call(..) => one / STF_TX_FEE_UNIT_DIVIDER,
		#[cfg(feature = "evm")]
		TrustedCall::evm_create(..) => one / STF_TX_FEE_UNIT_DIVIDER,
		#[cfg(feature = "evm")]
		TrustedCall::evm_create2(..) => one / STF_TX_FEE_UNIT_DIVIDER,
		#[cfg(feature = "evm")]
		TrustedCall::evm_withdraw(..) => one / STF_TX_FEE_UNIT_DIVIDER,
		#[cfg(any(feature = "test", test))]
		TrustedCall::balance_set_balance(..) => 0,
		// can be called by anyone so can't be free!
		TrustedCall::noop(..) => one / STF_TX_FEE_UNIT_DIVIDER,
	};
	if fee_amount == 0 {
		return Fee::Free
	}
	match fee_asset {
		None => Fee::Native(fee_amount),
		Some(asset_id) => match asset_id {
			AssetId::USDC | AssetId::USDT | AssetId::USDC_E | AssetId::EURC_E | AssetId::USDT_E =>
				Fee::Asset(fee_amount, asset_id),
			// TODO: use TEEracle info from L1 for exchange rates. the hardcoded exchange rates are
			// just to get started in the right order of magnitude
			AssetId::ETH | AssetId::WETH => Fee::Asset(fee_amount / 2_000, asset_id),
			AssetId::BTC | AssetId::WBTC_E => Fee::Asset(fee_amount / 70_000, asset_id),
			AssetId::PEPE_E => Fee::Asset(fee_amount * 111_000, asset_id),
		},
	}
}

fn charge_fee(fee: Fee, payer: &AccountId) -> Result<(), StfError> {
	if let Fee::Free = fee {
		return Ok(())
	}
	debug!("attempting to charge fee for TrustedCall: {:?}", fee);
	let fee_recipient: AccountId = enclave_signer_account();
	let origin = ita_sgx_runtime::RuntimeOrigin::signed(payer.clone());
	match fee {
		Fee::Native(native_fee) => ita_sgx_runtime::BalancesCall::<Runtime>::transfer {
			dest: MultiAddress::Id(fee_recipient),
			value: native_fee,
		}
		.dispatch_bypass_filter(origin)
		.map_err(|e| StfError::Dispatch(format!("Fee Payment Error: {:?}", e.error)))
		.map(|_| ()),
		Fee::Asset(asset_fee, asset_id) => ita_sgx_runtime::AssetsCall::<Runtime>::transfer {
			id: asset_id,
			target: MultiAddress::Id(fee_recipient),
			amount: asset_fee,
		}
		.dispatch_bypass_filter(origin)
		.map_err(|e| StfError::Dispatch(format!("Fee Payment Error: {:?}", e.error)))
		.map(|_| ()),
		_ => Ok(()),
	}
}

fn charge_fee_in_available_asset(tc: &TrustedCallSigned) -> Result<(), StfError> {
	let sender = tc.call.sender_account().clone();
	// default to charging native
	let fee = get_fee_for(tc, None);
	if charge_fee(fee, &sender).is_ok() {
		return Ok(())
	}
	// if no native available, try to charge fee in asset
	for asset_id in AssetId::all_shieldable(shielding_target_genesis_hash().unwrap_or_default()) {
		let fee = get_fee_for(tc, Some(asset_id));
		if charge_fee(fee, &sender).is_ok() {
			return Ok(())
		}
	}
	Err(StfError::MissingFunds)
}

fn burn_funds(account: &AccountId, amount: u128) -> Result<(), StfError> {
	let account_info = System::account(&account);
	if account_info.data.free < amount {
		return Err(StfError::MissingFunds)
	}

	ita_sgx_runtime::BalancesCall::<Runtime>::force_set_balance {
		who: MultiAddress::Id(account.clone()),
		new_free: account_info.data.free - amount,
	}
	.dispatch_bypass_filter(ita_sgx_runtime::RuntimeOrigin::root())
	.map_err(|e| StfError::Dispatch(format!("Burn funds error: {:?}", e.error)))?;
	Ok(())
}

fn burn_assets(account: &AccountId, amount: u128, id: AssetId) -> Result<(), StfError> {
	ita_sgx_runtime::AssetsCall::<Runtime>::burn {
		id,
		who: MultiAddress::Id(account.clone()),
		amount,
	}
	.dispatch_bypass_filter(ita_sgx_runtime::RuntimeOrigin::signed(enclave_signer_account()))
	.map_err(|e| StfError::Dispatch(format!("Burn assets error: {:?}", e.error)))?;
	Ok(())
}

fn shield_funds(account: &AccountId, amount: u128) -> Result<(), StfError> {
	//fixme: make fee configurable and send fee to vault account on L2
	let fee = amount / STF_SHIELDING_FEE_AMOUNT_DIVIDER;

	// endow fee to enclave (self)
	let fee_recipient: AccountId = enclave_signer_account();

	let account_info = System::account(&fee_recipient);
	ita_sgx_runtime::BalancesCall::<Runtime>::force_set_balance {
		who: MultiAddress::Id(fee_recipient),
		new_free: account_info.data.free + fee,
	}
	.dispatch_bypass_filter(ita_sgx_runtime::RuntimeOrigin::root())
	.map_err(|e| StfError::Dispatch(format!("Shield funds error: {:?}", e.error)))?;

	// endow shieding amount - fee to beneficiary
	let account_info = System::account(&account);
	ita_sgx_runtime::BalancesCall::<Runtime>::force_set_balance {
		who: MultiAddress::Id(account.clone()),
		new_free: account_info.data.free + amount - fee,
	}
	.dispatch_bypass_filter(ita_sgx_runtime::RuntimeOrigin::root())
	.map_err(|e| StfError::Dispatch(format!("Shield funds error: {:?}", e.error)))?;

	Ok(())
}

fn shield_assets(account: &AccountId, amount: u128, asset_id: AssetId) -> Result<(), StfError> {
	//fixme: make fee configurable and send fee to vault account on L2
	let fee = amount / STF_SHIELDING_FEE_AMOUNT_DIVIDER;
	let sudo_account: AccountId = enclave_signer_account();

	// auto-create asset_id
	if !Assets::asset_exists(asset_id) {
		debug!("will create new asset with id {:?}", asset_id);
		ita_sgx_runtime::AssetsCall::<Runtime>::force_create {
			id: asset_id,
			owner: MultiAddress::Id(sudo_account.clone()),
			is_sufficient: true,
			min_balance: 1,
		}
		.dispatch_bypass_filter(ita_sgx_runtime::RuntimeOrigin::root())
		.map_err(|e| StfError::Dispatch(format!("Shield (create asset) error: {:?}", e.error)))?;
	};
	// endow fee to enclave (self)
	ita_sgx_runtime::AssetsCall::<Runtime>::mint {
		id: asset_id,
		beneficiary: MultiAddress::Id(sudo_account.clone()),
		amount: fee,
	}
	.dispatch_bypass_filter(ita_sgx_runtime::RuntimeOrigin::signed(sudo_account.clone()))
	.map_err(|e| StfError::Dispatch(format!("Shield assets error: {:?}", e.error)))?;
	// endow shieding (amount - fee) to beneficiary
	ita_sgx_runtime::AssetsCall::<Runtime>::mint {
		id: asset_id,
		beneficiary: MultiAddress::Id(account.clone()),
		amount: amount - fee,
	}
	.dispatch_bypass_filter(ita_sgx_runtime::RuntimeOrigin::signed(sudo_account))
	.map_err(|e| StfError::Dispatch(format!("Shield assets (mint) error: {:?}", e.error)))?;

	Ok(())
}

fn unshield_native_from_vault_parentchain_call<NodeMetadataRepository>(
	beneficiary: &AccountId,
	value: Balance,
	node_metadata_repo: Arc<NodeMetadataRepository>,
) -> Result<OpaqueCall, StfError>
where
	NodeMetadataRepository: AccessNodeMetadata,
	NodeMetadataRepository::MetadataType: NodeMetadataTrait,
{
	Ok(OpaqueCall::from_tuple(&(
		node_metadata_repo
			.get_from_metadata(|m| m.transfer_keep_alive_call_indexes())
			.map_err(|_| StfError::InvalidMetadata)?
			.map_err(|_| StfError::InvalidMetadata)?,
		Address::from(beneficiary.clone()),
		Compact(value),
	)))
}
fn unshield_assets_parentchain_call<NodeMetadataRepository>(
	beneficiary: &AccountId,
	value: Balance,
	asset_id: AssetId,
	node_metadata_repo: Arc<NodeMetadataRepository>,
) -> Result<OpaqueCall, StfError>
where
	NodeMetadataRepository: AccessNodeMetadata,
	NodeMetadataRepository::MetadataType: NodeMetadataTrait,
{
	match asset_id.reserve_instance() {
		Some(FOREIGN_ASSETS) => {
			let location = asset_id
				.into_location(shielding_target_genesis_hash().unwrap_or_default())
				.ok_or(StfError::Dispatch("unknown asset id location".into()))?;
			Ok(OpaqueCall::from_tuple(&(
				node_metadata_repo
					.get_from_metadata(|m| m.foreign_assets_transfer_keep_alive_call_indexes())
					.map_err(|_| StfError::InvalidMetadata)?
					.map_err(|_| StfError::InvalidMetadata)?,
				location,
				Address::Id(beneficiary.clone()),
				Compact(value),
			)))
		},
		Some(NATIVE_ASSETS) => {
			let native_asset_id = asset_id
				.into_asset_hub_index(shielding_target_genesis_hash().unwrap_or_default())
				.ok_or(StfError::Dispatch("unknown asset index".into()))?;
			Ok(OpaqueCall::from_tuple(&(
				node_metadata_repo
					.get_from_metadata(|m| m.native_assets_transfer_keep_alive_call_indexes())
					.map_err(|_| StfError::InvalidMetadata)?
					.map_err(|_| StfError::InvalidMetadata)?,
				Compact(native_asset_id),
				Address::Id(beneficiary.clone()),
				Compact(value),
			)))
		},
		_ => Err(StfError::Dispatch("unknown asset id reserve".into())),
	}
}

fn parentchain_vault_proxy_call<NodeMetadataRepository>(
	call: OpaqueCall,
	node_metadata_repo: Arc<NodeMetadataRepository>,
) -> Result<ParentchainCall, StfError>
where
	NodeMetadataRepository: AccessNodeMetadata,
	NodeMetadataRepository::MetadataType: NodeMetadataTrait,
{
	let (vault, parentchain_id) = shard_vault()
		.ok_or_else(|| StfError::Dispatch("shard vault key hasn't been set".to_string()))?;
	let vault_address = Address::from(vault);
	let call = OpaqueCall::from_tuple(&(
		node_metadata_repo
			.get_from_metadata(|m| m.proxy_call_indexes())
			.map_err(|_| StfError::InvalidMetadata)?
			.map_err(|_| StfError::InvalidMetadata)?,
		vault_address,
		None::<ProxyType>,
		call,
	));
	let mortality = get_mortality(parentchain_id, 32).unwrap_or_else(GenericMortality::immortal);

	Ok(match parentchain_id {
		ParentchainId::Integritee => ParentchainCall::Integritee { call, mortality },
		ParentchainId::TargetA => ParentchainCall::TargetA { call, mortality },
		ParentchainId::TargetB => ParentchainCall::TargetB { call, mortality },
	})
}

/// depending on the current shard status and shielding target we may want to filter specific calls
fn may_execute(tcs: &TrustedCallSigned) -> bool {
	if let Some((config, _)) = ShardManagement::upgradable_shard_config() {
		// TODO: we could check for a pending upgrade too, but as the shard will be touched frequently,
		// this should work fine as L1 takes care of turning pending into active
		if config.active_config.maintenance_mode {
			info!("We're in maintenance mode. Checking call filter rules");
			return match tcs.call {
				// we want to allow shielding calls as we can't prevent them and can't catch up later
				TrustedCall::balance_shield(..) => true,
				TrustedCall::balance_shield_through_enclave_bridge_pallet(..) => true,
				TrustedCall::assets_shield(..) => true,
				// permissioned calls are ok
				TrustedCall::timestamp_set(..) => true,
				TrustedCall::force_unshield_all(..) => true,
				// everything else is disabled during maintenance mode
				_ => false,
			}
		}
	}
	if MinimalChainSpec::is_known_production_chain(
		shielding_target_genesis_hash().unwrap_or_default(),
	) && matches!(
		tcs.call,
		TrustedCall::waste_time(..)
			| TrustedCall::note_bloat(..)
			| TrustedCall::spam_extrinsics(..)
	) {
		warn!("preventing execution of call {:?} on production chain", tcs.call);
		return false
	}
	true
}

fn ensure_authorization(tcs: &TrustedCallSigned) -> Result<SessionProxyRole<Balance>, StfError> {
	let delegator = tcs.sender_account();
	if let Some(delegate) = tcs.delegate.clone() {
		let (credentials, _) =
			pallet_session_proxy::Pallet::<Runtime>::session_proxies(&delegator, &delegate)
				.ok_or_else(|| StfError::MissingPrivileges(delegate.clone()))?;
		//todo! verify expiry
		match credentials.role {
			SessionProxyRole::Any => Ok(credentials.role),
			SessionProxyRole::NonTransfer => match tcs.call {
				TrustedCall::noop(..) => Ok(credentials.role),
				TrustedCall::guess_the_number(..) => Ok(credentials.role),
				TrustedCall::send_note(..) => Ok(credentials.role),
				_ => Err(StfError::MissingPrivileges(delegate)),
			},
			_ => Err(StfError::MissingPrivileges(delegate)),
		}
	} else {
		// signed by account owner
		Ok(SessionProxyRole::Any)
	}
}

#[cfg(any(feature = "test", test))]
fn is_root<Runtime, AccountId>(account: &AccountId) -> bool
where
	Runtime: frame_system::Config<AccountId = AccountId> + pallet_sudo::Config,
	AccountId: PartialEq,
{
	pallet_sudo::Pallet::<Runtime>::key().map_or(false, |k| account == &k)
}

#[cfg(test)]
mod tests {
	use super::*;
	use itp_stf_primitives::types::KeyPair;
	use sp_keyring::AccountKeyring;

	use base58::FromBase58;

	pub(crate) fn shard_from_base58(src: &str) -> ShardIdentifier {
		ShardIdentifier::decode(
			&mut src.from_base58().expect("shard has to be base58 encoded").as_slice(),
		)
		.unwrap()
	}

	pub(crate) fn mrenclave_from_base58(src: &str) -> [u8; 32] {
		let mut mrenclave = [0u8; 32];
		mrenclave.copy_from_slice(&src.from_base58().expect("mrenclave has to be base58 encoded"));
		mrenclave
	}

	#[test]
	fn verify_signature_works() {
		let nonce = 21;
		let mrenclave = [0u8; 32];
		let shard = ShardIdentifier::default();

		let call = TrustedCall::balance_set_balance(
			AccountKeyring::Alice.public().into(),
			AccountKeyring::Alice.public().into(),
			42,
			42,
		);
		let signed_call = call.sign(
			&KeyPair::Sr25519(Box::new(AccountKeyring::Alice.pair())),
			nonce,
			&mrenclave,
			&shard,
		);

		assert!(signed_call.verify_signature(&mrenclave, &shard));
	}

	#[test]
	fn extension_dapp_verify_signature_works() {
		// This is a getter, which has been signed in the browser with the `signRaw` interface,
		// which wraps the data in `<Bytes>...</Bytes>`
		//
		// see: https://github.com/polkadot-js/extension/pull/743
		let dapp_extension_signed_call: Vec<u8> = vec![
			3, 6, 72, 250, 19, 15, 144, 30, 85, 114, 224, 117, 219, 65, 218, 30, 241, 136, 74, 157,
			10, 202, 233, 233, 100, 255, 63, 64, 102, 81, 215, 65, 60, 0, 0, 0, 0, 0, 0, 0, 0, 0,
			0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 10, 0, 0, 0, 0, 0,
			0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 73, 110, 99, 111, 103, 110, 105, 116, 101, 101, 84, 101,
			115, 116, 110, 101, 116, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 51, 1,
			0, 0, 0, 0, 1, 54, 194, 196, 95, 0, 150, 174, 244, 180, 4, 197, 64, 98, 123, 229, 37,
			222, 44, 232, 93, 170, 211, 231, 95, 157, 7, 88, 164, 204, 179, 171, 14, 68, 138, 43,
			37, 155, 15, 245, 130, 224, 239, 138, 44, 83, 46, 63, 200, 86, 5, 182, 47, 195, 144,
			170, 1, 108, 60, 4, 72, 201, 22, 212, 143,
		];
		let call = TrustedCallSigned::decode(&mut dapp_extension_signed_call.as_slice()).unwrap();

		let mrenclave = mrenclave_from_base58("8weGnjvG3nh6UzoYjqaTjpWjX1ouNPioA1K5134DJc5j");
		let shard = shard_from_base58("5wePd1LYa5M49ghwgZXs55cepKbJKhj5xfzQGfPeMS7c");
		assert!(call.verify_signature(&mrenclave, &shard))
	}
}
