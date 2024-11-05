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
	guess_the_number::GuessTheNumberTrustedCall,
	helpers::{
		enclave_signer_account, ensure_enclave_signer_account, shard_vault,
		shielding_target_genesis_hash, wrap_bytes,
	},
	Getter, STF_SHIELDING_FEE_AMOUNT_DIVIDER,
};
use codec::{Compact, Decode, Encode};
use frame_support::{ensure, traits::UnfilteredDispatchable};
use ita_parentchain_specs::MinimalChainSpec;
#[cfg(feature = "evm")]
use ita_sgx_runtime::{AddressMapping, HashedAddressMapping};
pub use ita_sgx_runtime::{Balance, Index};
use ita_sgx_runtime::{
	ParentchainInstanceIntegritee, ParentchainInstanceTargetA, ParentchainInstanceTargetB,
	ParentchainIntegritee, Runtime, System,
};
use itp_node_api::metadata::{provider::AccessNodeMetadata, NodeMetadataTrait};
use itp_node_api_metadata::{
	pallet_balances::BalancesCallIndexes, pallet_enclave_bridge::EnclaveBridgeCallIndexes,
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
use sp_core::{
	crypto::{AccountId32, UncheckedFrom},
	ed25519,
};
use sp_io::hashing::blake2_256;
use sp_runtime::{traits::Verify, MultiAddress, MultiSignature};
use std::{format, prelude::v1::*, sync::Arc};

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
			Self::timestamp_set(sender_account, ..) => sender_account,
			#[cfg(feature = "evm")]
			Self::evm_withdraw(sender_account, ..) => sender_account,
			#[cfg(feature = "evm")]
			Self::evm_call(sender_account, ..) => sender_account,
			#[cfg(feature = "evm")]
			Self::evm_create(sender_account, ..) => sender_account,
			#[cfg(feature = "evm")]
			Self::evm_create2(sender_account, ..) => sender_account,
			Self::guess_the_number(call) => call.sender_account(),
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
		let mut payload = self.encode();
		payload.append(&mut nonce.encode());
		payload.append(&mut mrenclave.encode());
		payload.append(&mut shard.encode());

		TrustedCallSigned { call: self.clone(), nonce, signature: pair.sign(payload.as_slice()) }
	}
}

#[derive(Encode, Decode, Clone, Debug, PartialEq, Eq)]
pub struct TrustedCallSigned {
	pub call: TrustedCall,
	pub nonce: Index,
	pub signature: Signature,
}

impl TrustedCallSigned {
	pub fn new(call: TrustedCall, nonce: Index, signature: Signature) -> Self {
		TrustedCallSigned { call, nonce, signature }
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

		if self.signature.verify(payload.as_slice(), self.call.sender_account()) {
			return true
		};

		// check if the signature is from an extension-dapp signer.
		self.signature
			.verify(wrap_bytes(&payload).as_slice(), self.call.sender_account())
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
		node_metadata_repo: Arc<NodeMetadataRepository>,
	) -> Result<(), Self::Error> {
		let sender = self.call.sender_account().clone();
		let call_hash = blake2_256(&self.call.encode());
		let system_nonce = System::account_nonce(&sender);
		ensure!(self.nonce == system_nonce, Self::Error::InvalidNonce(self.nonce, system_nonce));

		// try to charge fee first and fail early
		let fee = get_fee_for(&self);
		charge_fee(fee, &sender)?;

		// increment the nonce, no matter if the call succeeds or fails.
		// The call must have entered the transaction pool already,
		// so it should be considered as valid
		System::inc_account_nonce(&sender);

		match self.call {
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
					who: MultiAddress::Id(who),
					new_free: free_balance,
				}
				.dispatch_bypass_filter(ita_sgx_runtime::RuntimeOrigin::root())
				.map_err(|e| {
					Self::Error::Dispatch(format!("Balance Set Balance error: {:?}", e.error))
				})?;
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
				let origin = ita_sgx_runtime::RuntimeOrigin::signed(from);
				std::println!("⣿STF⣿ 🔄 balance_transfer from ⣿⣿⣿ to ⣿⣿⣿ amount ⣿⣿⣿");
				ita_sgx_runtime::BalancesCall::<Runtime>::transfer {
					dest: MultiAddress::Id(to),
					value,
				}
				.dispatch_bypass_filter(origin)
				.map_err(|e| {
					Self::Error::Dispatch(format!("Balance Transfer error: {:?}", e.error))
				})?;
				Ok(())
			},
			TrustedCall::balance_unshield(account_incognito, beneficiary, value, shard) => {
				std::println!(
					"⣿STF⣿ 🛡👐 balance_unshield from ⣿⣿⣿ to {}, amount {}",
					account_id_to_string(&beneficiary),
					value
				);
				info!(
					"balance_unshield(from (L2): {}, to (L1): {}, amount {} (+fee: {}), shard {})",
					account_id_to_string(&account_incognito),
					account_id_to_string(&beneficiary),
					value,
					fee,
					shard
				);

				burn_funds(account_incognito, value)?;

				let (vault, parentchain_id) = shard_vault().ok_or_else(|| {
					StfError::Dispatch("shard vault key hasn't been set".to_string())
				})?;
				let vault_address = Address::from(vault);
				let vault_transfer_call = OpaqueCall::from_tuple(&(
					node_metadata_repo
						.get_from_metadata(|m| m.transfer_keep_alive_call_indexes())
						.map_err(|_| StfError::InvalidMetadata)?
						.map_err(|_| StfError::InvalidMetadata)?,
					Address::from(beneficiary),
					Compact(value),
				));
				let proxy_call = OpaqueCall::from_tuple(&(
					node_metadata_repo
						.get_from_metadata(|m| m.proxy_call_indexes())
						.map_err(|_| StfError::InvalidMetadata)?
						.map_err(|_| StfError::InvalidMetadata)?,
					vault_address,
					None::<ProxyType>,
					vault_transfer_call,
				));
				let parentchain_call = match parentchain_id {
					ParentchainId::Integritee => ParentchainCall::Integritee {
						call: proxy_call,
						mortality: GenericMortality::immortal(),
					},
					ParentchainId::TargetA => ParentchainCall::TargetA {
						call: proxy_call,
						mortality: GenericMortality::immortal(),
					},
					ParentchainId::TargetB => ParentchainCall::TargetB {
						call: proxy_call,
						mortality: GenericMortality::immortal(),
					},
				};
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
				shield_funds(who, value)?;

				// Send proof of execution on chain.
				calls.push(ParentchainCall::Integritee {
					call: OpaqueCall::from_tuple(&(
						node_metadata_repo
							.get_from_metadata(|m| m.publish_hash_call_indexes())
							.map_err(|_| StfError::InvalidMetadata)?
							.map_err(|_| StfError::InvalidMetadata)?,
						call_hash,
						Vec::<itp_types::H256>::new(),
						b"shielded some funds!".to_vec(),
					)),
					mortality: GenericMortality::immortal(),
				});
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
			TrustedCall::guess_the_number(call) => call.execute(calls, node_metadata_repo),
		}?;
		Ok(())
	}

	fn get_storage_hashes_to_update(self) -> Vec<Vec<u8>> {
		let mut key_hashes = Vec::new();
		match self.call {
			TrustedCall::noop(..) => debug!("No storage updates needed..."),
			TrustedCall::guess_the_number(call) =>
				key_hashes.append(&mut <GuessTheNumberTrustedCall as ExecuteCall<
					NodeMetadataRepository,
				>>::get_storage_hashes_to_update(call)),
			_ => debug!("No storage updates needed..."),
		};
		key_hashes
	}
}

fn get_fee_for(tc: &TrustedCallSigned) -> Balance {
	let one = MinimalChainSpec::one_unit(shielding_target_genesis_hash().unwrap_or_default());
	match &tc.call {
		TrustedCall::balance_transfer(..) => one / crate::STF_TX_FEE_UNIT_DIVIDER,
		TrustedCall::balance_unshield(..) => one / crate::STF_TX_FEE_UNIT_DIVIDER * 3,
		TrustedCall::guess_the_number(call) => crate::guess_the_number::get_fee_for(call),
		_ => Balance::from(0u32),
	}
}

fn charge_fee(fee: Balance, payer: &AccountId) -> Result<(), StfError> {
	debug!("attempting to charge fee for TrustedCall");
	let fee_recipient: AccountId = enclave_signer_account();
	let origin = ita_sgx_runtime::RuntimeOrigin::signed(payer.clone());
	ita_sgx_runtime::BalancesCall::<Runtime>::transfer {
		dest: MultiAddress::Id(fee_recipient),
		value: fee,
	}
	.dispatch_bypass_filter(origin)
	.map_err(|e| StfError::Dispatch(format!("Fee Payment Error: {:?}", e.error)))?;
	Ok(())
}

fn burn_funds(account: AccountId, amount: u128) -> Result<(), StfError> {
	let account_info = System::account(&account);
	if account_info.data.free < amount {
		return Err(StfError::MissingFunds)
	}

	ita_sgx_runtime::BalancesCall::<Runtime>::force_set_balance {
		who: MultiAddress::Id(account),
		new_free: account_info.data.free - amount,
	}
	.dispatch_bypass_filter(ita_sgx_runtime::RuntimeOrigin::root())
	.map_err(|e| StfError::Dispatch(format!("Burn funds error: {:?}", e.error)))?;
	Ok(())
}

fn shield_funds(account: AccountId, amount: u128) -> Result<(), StfError> {
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
		who: MultiAddress::Id(account),
		new_free: account_info.data.free + amount - fee,
	}
	.dispatch_bypass_filter(ita_sgx_runtime::RuntimeOrigin::root())
	.map_err(|e| StfError::Dispatch(format!("Shield funds error: {:?}", e.error)))?;

	Ok(())
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
			0, 0, 0, 1, 54, 194, 196, 95, 0, 150, 174, 244, 180, 4, 197, 64, 98, 123, 229, 37, 222,
			44, 232, 93, 170, 211, 231, 95, 157, 7, 88, 164, 204, 179, 171, 14, 68, 138, 43, 37,
			155, 15, 245, 130, 224, 239, 138, 44, 83, 46, 63, 200, 86, 5, 182, 47, 195, 144, 170,
			1, 108, 60, 4, 72, 201, 22, 212, 143,
		];
		let call = TrustedCallSigned::decode(&mut dapp_extension_signed_call.as_slice()).unwrap();

		let mrenclave = mrenclave_from_base58("8weGnjvG3nh6UzoYjqaTjpWjX1ouNPioA1K5134DJc5j");
		let shard = shard_from_base58("5wePd1LYa5M49ghwgZXs55cepKbJKhj5xfzQGfPeMS7c");
		assert!(call.verify_signature(&mrenclave, &shard))
	}
}
