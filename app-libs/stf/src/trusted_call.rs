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
	helpers::{enclave_signer_account, ensure_enclave_signer_account, shard_vault},
	Getter,
};
use codec::{Compact, Decode, Encode};
use frame_support::{ensure, traits::UnfilteredDispatchable};
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
	parentchain::{ParentchainCall, ParentchainId, ProxyType},
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

// raflle stuff
pub use ita_raffle_stf::{RaffleCount, RaffleIndex, RaffleTrustedCall, WinnerCount};

#[derive(Encode, Decode, Clone, Debug, PartialEq, Eq)]
#[allow(non_camel_case_types)]
pub enum TrustedCall {
	noop(AccountId),
	balance_set_balance(AccountId, AccountId, Balance, Balance),
	balance_transfer(AccountId, AccountId, Balance),
	balance_unshield(AccountId, AccountId, Balance, ShardIdentifier), // (AccountIncognito, BeneficiaryPublicAccount, Amount, Shard)
	balance_shield(AccountId, AccountId, Balance, ParentchainId), // (Root, AccountIncognito, Amount, origin parentchain)
	timestamp_set(AccountId, Moment, ParentchainId),              // (Root, now)
	raffle(RaffleTrustedCall),
	#[cfg(feature = "evm")]
	evm_withdraw(AccountId, H160, Balance), // (Origin, Address EVM Account, Value)
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
	),
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
	),
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
	),
}

impl TrustedCall {
	pub fn sender_account(&self) -> &AccountId {
		match self {
			Self::noop(sender_account) => sender_account,
			Self::balance_set_balance(sender_account, ..) => sender_account,
			Self::balance_transfer(sender_account, ..) => sender_account,
			Self::balance_unshield(sender_account, ..) => sender_account,
			Self::balance_shield(sender_account, ..) => sender_account,
			Self::timestamp_set(sender_account, ..) => sender_account,
			Self::raffle(call) => call.sender_account(),
			#[cfg(feature = "evm")]
			Self::evm_withdraw(sender_account, ..) => sender_account,
			#[cfg(feature = "evm")]
			Self::evm_call(sender_account, ..) => sender_account,
			#[cfg(feature = "evm")]
			Self::evm_create(sender_account, ..) => sender_account,
			#[cfg(feature = "evm")]
			Self::evm_create2(sender_account, ..) => sender_account,
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
		self.signature.verify(payload.as_slice(), self.call.sender_account())
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

		// increment the nonce, no matter if the call succeeds or fails.
		// The call must have entered the transaction pool already,
		// so it should be considered as valid
		System::inc_account_nonce(&sender);

		match self.call {
			TrustedCall::noop(who) => {
				debug!("noop called by {}", account_id_to_string(&who),);
				Ok::<(), Self::Error>(())
			},
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
				let origin = ita_sgx_runtime::RuntimeOrigin::signed(from.clone());
				std::println!("⣿STF⣿ 🔄 balance_transfer from ⣿⣿⣿ to ⣿⣿⣿ amount ⣿⣿⣿");
				// endow fee to enclave (self)
				let fee_recipient: AccountId = enclave_signer_account();
				// fixme: apply fees through standard frame process and tune it
				let fee = crate::STF_TX_FEE;
				info!(
					"from {}, to {}, amount {}, fee {}",
					account_id_to_string(&from),
					account_id_to_string(&to),
					value,
					fee
				);
				ita_sgx_runtime::BalancesCall::<Runtime>::transfer {
					dest: MultiAddress::Id(fee_recipient),
					value: fee,
				}
				.dispatch_bypass_filter(origin.clone())
				.map_err(|e| {
					Self::Error::Dispatch(format!("Balance Transfer error: {:?}", e.error))
				})?;
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
				// endow fee to enclave (self)
				let fee_recipient: AccountId = enclave_signer_account();
				// fixme: apply fees through standard frame process and tune it. has to be at least two L1 transfer's fees
				let fee = crate::STF_TX_FEE * 3;

				info!(
					"balance_unshield(from (L2): {}, to (L1): {}, amount {} (+fee: {}), shard {})",
					account_id_to_string(&account_incognito),
					account_id_to_string(&beneficiary),
					value,
					fee,
					shard
				);

				let origin = ita_sgx_runtime::RuntimeOrigin::signed(account_incognito.clone());
				ita_sgx_runtime::BalancesCall::<Runtime>::transfer {
					dest: MultiAddress::Id(fee_recipient),
					value: fee,
				}
				.dispatch_bypass_filter(origin)
				.map_err(|e| {
					Self::Error::Dispatch(format!("Balance Unshielding error: {:?}", e.error))
				})?;
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
					ParentchainId::Integritee => ParentchainCall::Integritee(proxy_call),
					ParentchainId::TargetA => ParentchainCall::TargetA(proxy_call),
					ParentchainId::TargetB => ParentchainCall::TargetB(proxy_call),
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
				calls.push(ParentchainCall::Integritee(OpaqueCall::from_tuple(&(
					node_metadata_repo
						.get_from_metadata(|m| m.publish_hash_call_indexes())
						.map_err(|_| StfError::InvalidMetadata)?
						.map_err(|_| StfError::InvalidMetadata)?,
					call_hash,
					Vec::<itp_types::H256>::new(),
					b"shielded some funds!".to_vec(),
				))));
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
			TrustedCall::raffle(call) => call.execute(calls, node_metadata_repo),
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
		}?;
		Ok(())
	}

	fn get_storage_hashes_to_update(self) -> Vec<Vec<u8>> {
		let key_hashes = Vec::new();
		match self.call {
			TrustedCall::noop(..) => debug!("No storage updates needed..."),
			TrustedCall::balance_set_balance(..) => debug!("No storage updates needed..."),
			TrustedCall::balance_transfer(..) => debug!("No storage updates needed..."),
			TrustedCall::balance_unshield(..) => debug!("No storage updates needed..."),
			TrustedCall::balance_shield(..) => debug!("No storage updates needed..."),
			TrustedCall::timestamp_set(..) => debug!("No storage updates needed..."),
			_ => debug!("No storage updates needed..."),
		};
		key_hashes
	}
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
	let fee = amount / 571; // approx 0.175%

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
}
