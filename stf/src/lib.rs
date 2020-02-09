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

extern crate alloc;

use codec::{Decode, Encode};
use primitives::{sr25519, Pair};
use runtime_primitives::{traits::Verify, AnySignature};

#[cfg(feature = "sgx")]
pub mod sgx;

pub type Signature = AnySignature;
pub type AuthorityId = <Signature as Verify>::Signer;
pub type AccountId = <Signature as Verify>::Signer;
pub type Hash = primitives::H256;
pub type Balance = u128;

#[cfg(feature = "sgx")]
pub type State = sr_io::SgxExternalities;

#[derive(Encode, Decode, Clone)]
#[allow(non_camel_case_types)]
pub enum TrustedCall {
    balance_set_balance(AccountId, Balance, Balance),
    balance_transfer(AccountId, AccountId, Balance),
}

impl TrustedCall {
    fn account(&self) -> &AccountId {
        match self {
            TrustedCall::balance_set_balance(account, _, _) => account,
            TrustedCall::balance_transfer(account, _, _) => account,
        }
    }

    pub fn sign(&self, pair: &sr25519::Pair, nonce: u32, mrenclave: [u8;32], shard: [u8; 32]) -> AnySignature {
        pair.sign(
            self.encode()
            .append(vec![self.nonce])
            .append(mrenclave.encode()) 
            .append(shard.encode()).as_slice(),
            .as_slice()).into()
    }
}

#[derive(Encode, Decode, Clone)]
#[allow(non_camel_case_types)]
pub enum TrustedGetter {
    free_balance(AccountId),
    reserved_balance(AccountId),
}

impl TrustedGetter {
    pub fn account(&self) -> &AccountId {
        match self {
            TrustedGetter::free_balance(account) => account,
            TrustedGetter::reserved_balance(account) => account,
        }
    }

    pub fn sign(&self, pair: &sr25519::Pair) -> AnySignature {
        pair.sign(self.encode().as_slice()).into()
    }
}

#[derive(Encode, Decode)]
pub struct TrustedGetterSigned {
    pub getter: TrustedGetter,
    pub signature: AnySignature,
}

impl TrustedGetterSigned {
    pub fn new(getter: TrustedGetter, signature: AnySignature) -> Self {
        TrustedGetterSigned { getter, signature }
    }

    pub fn verify_signature(&self) -> bool {
        self.signature
            .verify(self.getter.encode().as_slice(), self.getter.account())
    }
}

#[derive(Encode, Decode)]
pub struct TrustedCallSigned {
    pub call: TrustedCall,
    pub nonce: u32,
    pub signature: AnySignature,
}

impl TrustedCallSigned {
    pub fn new(call: TrustedCall, signature: AnySignature) -> Self {
        TrustedCallSigned { call, signature }
    }

    pub fn verify_signature(&self, mrenclave: [u8; 32], shard: [u8; 32]]) -> bool {
        self.signature
            .verify(
                self.call.encode()
                .append(vec![self.nonce])
                .append(mrenclave.encode()) 
                .append(shard.encode()).as_slice(),
                self.call.account())
    }
}

#[cfg(feature = "sgx")]
pub struct Stf {}
