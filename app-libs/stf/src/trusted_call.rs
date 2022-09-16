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

#[cfg(feature = "sgx")]
pub use ita_sgx_runtime::{Balance, Index};
#[cfg(feature = "std")]
pub use my_node_runtime::{Balance, Index};

#[cfg(feature = "evm")]
use sp_core::{H160, H256, U256};

#[cfg(feature = "evm")]
use std::vec::Vec;

use crate::{AccountId, KeyPair, ShardIdentifier, Signature, StfError, TrustedOperation};
use codec::{Decode, Encode};
use itp_stf_interface::ExecuteCall;
use itp_types::OpaqueCall;
use log::*;
use sp_runtime::traits::Verify;

#[derive(Encode, Decode, Clone, Debug, PartialEq, Eq)]
#[allow(non_camel_case_types)]
pub enum TrustedCall {
	balance_set_balance(AccountId, AccountId, Balance, Balance),
	balance_transfer(AccountId, AccountId, Balance),
	balance_unshield(AccountId, AccountId, Balance, ShardIdentifier), // (AccountIncognito, BeneficiaryPublicAccount, Amount, Shard)
	balance_shield(AccountId, AccountId, Balance), // (Root, AccountIncognito, Amount)
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
			TrustedCall::balance_set_balance(sender_account, ..) => sender_account,
			TrustedCall::balance_transfer(sender_account, ..) => sender_account,
			TrustedCall::balance_unshield(sender_account, ..) => sender_account,
			TrustedCall::balance_shield(sender_account, ..) => sender_account,
			#[cfg(feature = "evm")]
			TrustedCall::evm_withdraw(sender_account, ..) => sender_account,
			#[cfg(feature = "evm")]
			TrustedCall::evm_call(sender_account, ..) => sender_account,
			#[cfg(feature = "evm")]
			TrustedCall::evm_create(sender_account, ..) => sender_account,
			#[cfg(feature = "evm")]
			TrustedCall::evm_create2(sender_account, ..) => sender_account,
		}
	}

	pub fn sign(
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

	pub fn verify_signature(&self, mrenclave: &[u8; 32], shard: &ShardIdentifier) -> bool {
		let mut payload = self.call.encode();
		payload.append(&mut self.nonce.encode());
		payload.append(&mut mrenclave.encode());
		payload.append(&mut shard.encode());
		self.signature.verify(payload.as_slice(), self.call.sender_account())
	}

	pub fn into_trusted_operation(self, direct: bool) -> TrustedOperation {
		match direct {
			true => TrustedOperation::direct_call(self),
			false => TrustedOperation::indirect_call(self),
		}
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

#[cfg(feature = "sgx")]
pub mod sgx {
	use super::*;
	use crate::helpers::ensure_enclave_signer_account;
	use ita_sgx_runtime::{Runtime, System};
	use itp_utils::stringify::account_id_to_string;
	use sp_io::hashing::blake2_256;
	use sp_runtime::MultiAddress;
	use std::{format, prelude::v1::*};
	use support::{ensure, traits::UnfilteredDispatchable};

	#[cfg(feature = "evm")]
	use ita_sgx_runtime::{AddressMapping, HashedAddressMapping};

	#[cfg(feature = "evm")]
	use crate::evm_helpers::{create_code_hash, evm_create2_address, evm_create_address};

	impl ExecuteCall for TrustedCallSigned {
		type Error = StfError;

		fn execute(
			self,
			calls: &mut Vec<OpaqueCall>,
			unshield_funds_fn: [u8; 2],
		) -> Result<(), Self::Error> {
			let sender = self.call.sender_account().clone();
			let call_hash = blake2_256(&self.call.encode());
			ensure!(
				self.nonce == System::account_nonce(&sender),
				Self::Error::InvalidNonce(self.nonce)
			);
			match self.call {
				TrustedCall::balance_set_balance(root, who, free_balance, reserved_balance) => {
					ensure!(
						crate::stf_sgx::is_root(&root),
						Self::Error::MissingPrivileges(root.clone())
					);
					debug!(
						"balance_set_balance({}, {}, {})",
						account_id_to_string(&who),
						free_balance,
						reserved_balance
					);
					ita_sgx_runtime::BalancesCall::<Runtime>::set_balance {
						who: MultiAddress::Id(who.clone()),
						new_free: free_balance,
						new_reserved: reserved_balance,
					}
					.dispatch_bypass_filter(ita_sgx_runtime::Origin::root())
					.map_err(|e| {
						Self::Error::Dispatch(format!("Balance Set Balance error: {:?}", e.error))
					})?;
					Ok(())
				},
				TrustedCall::balance_transfer(from, to, value) => {
					let origin = ita_sgx_runtime::Origin::signed(from.clone());
					debug!(
						"balance_transfer({}, {}, {})",
						account_id_to_string(&from),
						account_id_to_string(&to),
						value
					);
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
					debug!(
						"balance_unshield({}, {}, {}, {})",
						account_id_to_string(&account_incognito),
						account_id_to_string(&beneficiary),
						value,
						shard
					);
					unshield_funds(account_incognito, value)?;
					calls.push(OpaqueCall::from_tuple(&(
						unshield_funds_fn,
						beneficiary,
						value,
						shard,
						call_hash,
					)));
					Ok(())
				},
				TrustedCall::balance_shield(enclave_account, who, value) => {
					ensure_enclave_signer_account(&enclave_account)?;
					debug!("balance_shield({}, {})", account_id_to_string(&who), value);
					shield_funds(who, value)?;
					Ok(())
				},
				#[cfg(feature = "evm")]
				TrustedCall::evm_withdraw(from, address, value) => {
					debug!("evm_withdraw({}, {}, {})", account_id_to_string(&from), address, value);
					ita_sgx_runtime::EvmCall::<Runtime>::withdraw { address, value }
						.dispatch_bypass_filter(ita_sgx_runtime::Origin::signed(from))
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
					.dispatch_bypass_filter(ita_sgx_runtime::Origin::signed(from))
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
					.dispatch_bypass_filter(ita_sgx_runtime::Origin::signed(from))
					.map_err(|e| {
						Self::Error::Dispatch(format!("Evm Create error: {:?}", e.error))
					})?;
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
					.dispatch_bypass_filter(ita_sgx_runtime::Origin::signed(from))
					.map_err(|e| {
						Self::Error::Dispatch(format!("Evm Create2 error: {:?}", e.error))
					})?;
					let contract_address = evm_create2_address(source, salt, code_hash);
					info!("Trying to create evm contract with address {:?}", contract_address);
					Ok(())
				},
			}?;
			System::inc_account_nonce(&sender);
			Ok(())
		}

		fn get_storage_hashes_to_update(self) -> Vec<Vec<u8>> {
			let key_hashes = Vec::new();
			match self.call {
				TrustedCall::balance_set_balance(_, _, _, _) =>
					debug!("No storage updates needed..."),
				TrustedCall::balance_transfer(_, _, _) => debug!("No storage updates needed..."),
				TrustedCall::balance_unshield(_, _, _, _) => debug!("No storage updates needed..."),
				TrustedCall::balance_shield(_, _, _) => debug!("No storage updates needed..."),
				#[cfg(feature = "evm")]
				_ => debug!("No storage updates needed..."),
			};
			key_hashes
		}
	}

	fn unshield_funds(account: AccountId, amount: u128) -> Result<(), StfError> {
		let account_info = System::account(&account);
		if account_info.data.free < amount {
			return Err(StfError::MissingFunds)
		}

		ita_sgx_runtime::BalancesCall::<Runtime>::set_balance {
			who: MultiAddress::Id(account),
			new_free: account_info.data.free - amount,
			new_reserved: account_info.data.reserved,
		}
		.dispatch_bypass_filter(ita_sgx_runtime::Origin::root())
		.map_err(|e| StfError::Dispatch(format!("Unshield funds error: {:?}", e.error)))?;
		Ok(())
	}

	fn shield_funds(account: AccountId, amount: u128) -> Result<(), StfError> {
		let account_info = System::account(&account);
		ita_sgx_runtime::BalancesCall::<Runtime>::set_balance {
			who: MultiAddress::Id(account),
			new_free: account_info.data.free + amount,
			new_reserved: account_info.data.reserved,
		}
		.dispatch_bypass_filter(ita_sgx_runtime::Origin::root())
		.map_err(|e| StfError::Dispatch(format!("Shield funds error: {:?}", e.error)))?;

		Ok(())
	}
}

#[cfg(not(feature = "sgx"))]
impl ExecuteCall for TrustedCallSigned {
	type Error = StfError;

	fn execute(
		self,
		_calls: &mut Vec<OpaqueCall>,
		_unshield_funds_fn: [u8; 2],
	) -> Result<(), Self::Error> {
		warn!("Call execution currently only available in sgx mode");
		unimplemented!()
	}

	fn get_storage_hashes_to_update(self) -> Vec<Vec<u8>> {
		warn!("Call get_storage_hashes_to_update currently only available in sgx mode");
		unimplemented!()
	}
}

#[cfg(test)]
mod tests {
	use super::*;
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
		let signed_call =
			call.sign(&KeyPair::Sr25519(AccountKeyring::Alice.pair()), nonce, &mrenclave, &shard);

		assert!(signed_call.verify_signature(&mrenclave, &shard));
	}
}
