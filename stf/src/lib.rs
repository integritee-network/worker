/*
	Copyright 2019 Supercomputing Systems AG

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

/////////////////////////////////////////////////////////////////////////////
#![feature(structural_match)]
#![feature(rustc_attrs)]
#![feature(core_intrinsics)]
#![feature(derive_eq)]

#![cfg_attr(not(target_env = "sgx"), no_std)]
#![cfg_attr(target_env = "sgx", feature(rustc_private))]

extern crate balances;
extern crate srml_support;
extern crate version;
extern crate sr_io;
extern crate alloc;

#[cfg(feature = "sgx")]
#[macro_use]
extern crate log;
#[cfg(feature = "sgx")]
extern crate env_logger;

#[cfg(feature = "sgx")]
mod runtime_wrapper;

pub mod tests;

#[cfg(feature = "sgx")]
#[macro_use]
extern crate sgx_tstd as std;

#[cfg(feature = "sgx")]
use std::prelude::v1::*;

#[cfg(feature = "sgx")]
use runtime_wrapper::Runtime;

#[cfg(feature = "sgx")]
use sr_io::SgxExternalities;

#[cfg(feature = "sgx")]
use std::backtrace::{self, PrintFormat};
#[cfg(feature = "sgx")]
use std::panic;

use codec::{Compact, Decode, Encode};
use primitives::hashing::{blake2_256, twox_128};

use runtime_primitives::traits::Dispatchable;
use runtime_primitives::{AnySignature, traits::Verify};
pub type Signature = AnySignature;
pub type AuthorityId = <Signature as Verify>::Signer;
pub type AccountId = <Signature as Verify>::Signer;
pub type Hash = primitives::H256;
pub type Balance = u128;

#[cfg(feature = "sgx")]
pub type State = SgxExternalities;

#[derive(Encode, Decode)]
pub enum TrustedCall {
    balance_set_balance(AccountId, Balance, Balance),
    balance_transfer(AccountId, AccountId, Balance),
}

#[cfg(feature = "sgx")]
pub struct Stf {
}

#[cfg(feature = "sgx")]
impl Stf {
    pub fn init_state() -> State {
        debug!("initializing stf state");
        let mut ext = State::new();	
        sr_io::with_externalities(&mut ext, || {
            // write Genesis 
            info!("Prepare some Genesis values");
            sr_io::set_storage(&storage_key_bytes("Balances", "TotalIssuance", None), &11u128.encode());
            sr_io::set_storage(&storage_key_bytes("Balances", "CreationFee", None), &1u128.encode());
            sr_io::set_storage(&storage_key_bytes("Balances", "TransferFee", None), &1u128.encode());
            sr_io::set_storage(&storage_key_bytes("Balances", "TransactionBaseFee", None), &1u128.encode());
            sr_io::set_storage(&storage_key_bytes("Balances", "TransfactionByteFee", None), &1u128.encode());
            sr_io::set_storage(&storage_key_bytes("Balances", "ExistentialDeposit", None), &1u128.encode());
        });
        ext
    }
    pub fn execute(mut ext: &mut State, call: TrustedCall) {
        sr_io::with_externalities(&mut ext, || {
            let result = match call {
                TrustedCall::balance_set_balance(who, free_balance, reserved_balance ) =>
                    runtime_wrapper::balancesCall::<Runtime>::set_balance(indices::Address::<Runtime>::Id(who.clone()), free_balance, reserved_balance).dispatch(runtime_wrapper::Origin::ROOT),
                TrustedCall::balance_transfer(from, to, value) =>
                    runtime_wrapper::balancesCall::<Runtime>::transfer(indices::Address::<Runtime>::Id(to.clone()), value).dispatch(runtime_wrapper::Origin::ROOT),
                _ => {
					Err("Call not recognized")}
            };
        });
    }
}

#[cfg(feature = "sgx")]
pub fn storage_key_bytes(module: &str, storage_key_name: &str, param: Option<Vec<u8>>) -> Vec<u8> {
	use primitives::twox_128;
    let mut key = [module, storage_key_name].join(" ").as_bytes().to_vec();
    let mut keyhash;
	debug!("storage_key_hash for: module: {} key: {} (and params?) ", module, storage_key_name);
    match param {
        Some(par) => {
            key.append(&mut par.clone());
            keyhash = blake2_256(&key).to_vec();
        },
        _ => {
            keyhash = twox_128(&key).to_vec();
        },
    }
	//debug!("   is 0x{}", hex::encode_hex(&keyhash));
    keyhash
}

/*
pub fn init_runtime() {
	info!("[??] asking runtime out");

	let mut ext = SgxExternalities::new();	

	let tina = AccountId::default();
	let origin_tina = runtime_wrapper::Origin::signed(tina.clone());
	//let origin = runtime_wrapper::Origin::ROOT;
	
	let address = indices::Address::<Runtime>::default();

	sr_io::with_externalities(&mut ext, || {
		// write Genesis 
		info!("Prepare some Genesis values");
		sr_io::set_storage(&storage_key_bytes("Balances", "TotalIssuance", None), &11u128.encode());
		sr_io::set_storage(&storage_key_bytes("Balances", "CreationFee", None), &1u128.encode());
		sr_io::set_storage(&storage_key_bytes("Balances", "TransferFee", None), &1u128.encode());
		sr_io::set_storage(&storage_key_bytes("Balances", "TransactionBaseFee", None), &1u128.encode());
		sr_io::set_storage(&storage_key_bytes("Balances", "TransfactionByteFee", None), &1u128.encode());
		sr_io::set_storage(&storage_key_bytes("Balances", "ExistentialDeposit", None), &1u128.encode());
		// prefund Tina
		sr_io::set_storage(&storage_key_bytes("Balances", "FreeBalance", Some(tina.clone().encode())), & 13u128.encode());

		// read storage
		let _creation_fee = sr_io::storage(&storage_key_bytes("Balances", "ExistentialDeposit", None));
		debug!("reading genesis storage ExistentialDeposit = {:?}", _creation_fee);

		const MILLICENTS: u128 = 1_000_000_000;
		const CENTS: u128 = 1_000 * MILLICENTS;    // assume this is worth about a cent.

		info!("re-funding tina: call set_balance");
		let res = runtime_wrapper::balancesCall::<Runtime>::set_balance(indices::Address::<Runtime>::Id(tina.clone()), 42, 43).dispatch(runtime_wrapper::Origin::ROOT);
		info!("reading Tina's FreeBalance");
		let tina_balance = sr_io::storage(&storage_key_bytes("Balances", "FreeBalance", Some(tina.clone().encode())));
		info!("Tina's FreeBalance is {:?}", tina_balance);
	});
	info!("[++] finished playing with runtime");
}
*/