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
use crate::{
	evm_helpers::{create_code_hash, evm_create2_address, evm_create_address},
	getter::TrustedGetterTrait,
	helpers::{get_storage_double_map, get_storage_map},
	types::{AccountId, KeyPair},
	Getter, Index, TrustedGetterSigned, TrustedOperation,
};
use codec::{Decode, Encode};
use ita_sgx_runtime::{AddressMapping, HashedAddressMapping, System};
use itp_stf_interface::ExecuteGetter;
use itp_storage::StorageHasher;
use log::*;
use sha3::{Digest, Keccak256};
use sp_core::{H160, H256, U256};
use std::{prelude::v1::*, vec::Vec};

pub fn get_evm_account_codes(evm_account: &H160) -> Option<Vec<u8>> {
	get_storage_map("Evm", "AccountCodes", evm_account, &StorageHasher::Blake2_128Concat)
}

pub fn get_evm_account_storages(evm_account: &H160, index: &H256) -> Option<H256> {
	get_storage_double_map(
		"Evm",
		"AccountStorages",
		evm_account,
		&StorageHasher::Blake2_128Concat,
		index,
		&StorageHasher::Blake2_128Concat,
	)
}

// FIXME: Once events are available, these addresses should be read from events.
pub fn evm_create_address(caller: H160, nonce: Index) -> H160 {
	let mut stream = rlp::RlpStream::new_list(2);
	stream.append(&caller);
	stream.append(&nonce);
	H256::from_slice(Keccak256::digest(&stream.out()).as_slice()).into()
}

// FIXME: Once events are available, these addresses should be read from events.
pub fn evm_create2_address(caller: H160, salt: H256, code_hash: H256) -> H160 {
	let mut hasher = Keccak256::new();
	hasher.update([0xff]);
	hasher.update(&caller[..]);
	hasher.update(&salt[..]);
	hasher.update(&code_hash[..]);
	H256::from_slice(hasher.finalize().as_slice()).into()
}

pub fn create_code_hash(code: &[u8]) -> H256 {
	H256::from_slice(Keccak256::digest(code).as_slice())
}

pub fn get_evm_account(account: &AccountId) -> H160 {
	let mut evm_acc_slice: [u8; 20] = [0; 20];
	evm_acc_slice.copy_from_slice((<[u8; 32]>::from(account.clone())).get(0..20).unwrap());
	evm_acc_slice.into()
}

#[derive(Encode, Decode, Clone, Debug, PartialEq, Eq)]
#[allow(non_camel_case_types)]
pub enum TrustedGetterEvm {
	evm_nonce(AccountId),
	evm_account_codes(AccountId, H160),
	evm_account_storages(AccountId, H160, H256),
}

impl TrustedGetterEvm {
	pub fn sign(&self, pair: &KeyPair) -> TrustedGetterSigned<TrustedGetterEvm> {
		let signature = pair.sign(self.encode().as_slice());
		TrustedGetterSigned::<TrustedGetterEvm>::new(self.clone(), signature)
	}
}

impl TrustedGetterTrait for TrustedGetterEvm {
	fn sender_account(&self) -> &AccountId {
		match self {
			TrustedGetterEvm::evm_nonce(sender_account) => sender_account,
			TrustedGetterEvm::evm_account_codes(sender_account, _) => sender_account,
			TrustedGetterEvm::evm_account_storages(sender_account, ..) => sender_account,
		}
	}
}
impl ExecuteGetter for TrustedGetterEvm {
	fn execute(self) -> Option<Vec<u8>> {
		match self {
			TrustedGetterEvm::evm_nonce(who) => {
				let evm_account = get_evm_account(&who);
				let evm_account = HashedAddressMapping::into_account_id(evm_account);
				let nonce = System::account_nonce(&evm_account);
				debug!("TrustedGetter evm_nonce");
				debug!("Account nonce is {}", nonce);
				Some(nonce.encode())
			},
			#[cfg(feature = "evm")]
			TrustedGetterEvm::evm_account_codes(_who, evm_account) =>
			// TODO: This probably needs some security check if who == evm_account (or assosciated)
				if let Some(info) = get_evm_account_codes(&evm_account) {
					debug!("TrustedGetter Evm Account Codes");
					debug!("AccountCodes for {} is {:?}", evm_account, info);
					Some(info) // TOOD: encoded?
				} else {
					None
				},
			#[cfg(feature = "evm")]
			TrustedGetterEvm::evm_account_storages(_who, evm_account, index) =>
			// TODO: This probably needs some security check if who == evm_account (or assosciated)
				if let Some(value) = get_evm_account_storages(&evm_account, &index) {
					debug!("TrustedGetter Evm Account Storages");
					debug!("AccountStorages for {} is {:?}", evm_account, value);
					Some(value.encode())
				} else {
					None
				},
		}
	}
	fn get_storage_hashes_to_update(self) -> Vec<Vec<u8>> {
		Vec::new()
	}
}
impl From<TrustedGetterSigned<TrustedGetterEvm>> for Getter<TrustedGetterEvm> {
	fn from(item: TrustedGetterSigned<TrustedGetterEvm>) -> Self {
		Getter::<TrustedGetterEvm>::trusted(item)
	}
}
impl From<TrustedGetterSigned<TrustedGetterEvm>> for TrustedOperation<TrustedGetterEvm> {
	fn from(item: TrustedGetterSigned<TrustedGetterEvm>) -> Self {
		TrustedOperation::<TrustedGetterEvm>::get(item.into())
	}
}
// Bookmark

pub enum TrustedCallEvm {
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

impl TrustedCallTrait for TrustedCallEvm {
	fn sender_account(&self) -> &AccountId {
		match self {
			TrustedCallEvm::evm_withdraw(sender_account, ..) => sender_account,
			TrustedCallEvm::evm_call(sender_account, ..) => sender_account,
			TrustedCallEvm::evm_create(sender_account, ..) => sender_account,
			TrustedCallEvm::evm_create2(sender_account, ..) => sender_account,
		}
	}
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

impl ExecuteCall for TrustedCallEvm {
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
			#[cfg(feature = "evm")]
			TrustedCallEvm::evm_withdraw(from, address, value) => {
				debug!("evm_withdraw({}, {}, {})", account_id_to_string(&from), address, value);
				ita_sgx_runtime::EvmCall::<Runtime>::withdraw { address, value }
					.dispatch_bypass_filter(ita_sgx_runtime::Origin::signed(from))
					.map_err(|e| {
						Self::Error::Dispatch(format!("Evm Withdraw error: {:?}", e.error))
					})?;
				Ok(())
			},
			#[cfg(feature = "evm")]
			TrustedCallEvm::evm_call(
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
			TrustedCallEvm::evm_create(
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
				.map_err(|e| Self::Error::Dispatch(format!("Evm Create error: {:?}", e.error)))?;
				let contract_address = evm_create_address(source, nonce_evm_account);
				info!("Trying to create evm contract with address {:?}", contract_address);
				Ok(())
			},
			#[cfg(feature = "evm")]
			TrustedCallEvm::evm_create2(
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
				.map_err(|e| Self::Error::Dispatch(format!("Evm Create2 error: {:?}", e.error)))?;
				let contract_address = evm_create2_address(source, salt, code_hash);
				info!("Trying to create evm contract with address {:?}", contract_address);
				Ok(())
			},
		}
	}

	fn get_storage_hashes_to_update(self) -> Vec<Vec<u8>> {
		let key_hashes = Vec::new();
		debug!("No storage updates needed...");
		key_hashes
	}
}
