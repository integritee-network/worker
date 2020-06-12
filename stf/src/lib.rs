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
#![cfg_attr(all(not(target_env = "sgx"), not(feature = "std")), no_std)]
#![cfg_attr(target_env = "sgx", feature(rustc_private))]

extern crate alloc;

#[cfg(feature = "std")]
extern crate clap;

use codec::{Compact, Decode, Encode};
use sp_core::{sr25519, Pair, H256};
use sp_runtime::{traits::Verify, AnySignature, MultiSignature, AccountId32};
pub type ShardIdentifier = H256;
pub use encointer_currencies::CurrencyIdentifier;
pub use encointer_ceremonies::ProofOfAttendance;
pub use encointer_ceremonies::Attestation;

#[cfg(feature = "sgx")]
pub mod sgx;

#[cfg(feature = "sgx")]
use sgx_tstd as std;
use std::vec::Vec;

#[cfg(feature = "std")]
pub mod cli;

pub type Signature = AnySignature;
pub type AuthorityId = <Signature as Verify>::Signer;
pub type AccountId = <Signature as Verify>::Signer;
pub type Hash = sp_core::H256;
pub use encointer_balances::BalanceType;
pub type BalanceTransferFn = ([u8; 2], AccountId, Compact<u128>);
pub static BALANCE_MODULE: u8 = 4u8;
pub static BALANCE_TRANSFER: u8 = 0u8;
pub static SUBSRATEE_REGISTRY_MODULE: u8 = 6u8;
pub static UNSHIELD: u8 = 5u8;
pub static CALL_CONFIRMED: u8 = 3u8;

#[cfg(feature = "sgx")]
pub type State = sp_io::SgxExternalities;

#[derive(Encode, Decode, Clone)]
#[allow(non_camel_case_types)]
pub enum TrustedOperationSigned {
    call(TrustedCallSigned),
    get(TrustedGetterSigned),
}

#[derive(Encode, Decode, Clone, Debug)]
#[allow(non_camel_case_types)]
pub enum TrustedCall {
    balance_transfer(AccountId, AccountId, CurrencyIdentifier, BalanceType),
    ceremonies_register_participant(AccountId, CurrencyIdentifier, Option<ProofOfAttendance<MultiSignature, AccountId32>>),
    ceremonies_register_attestations(AccountId, Vec<Attestation<MultiSignature, AccountId32, u64>>),
    ceremonies_grant_reputation(AccountId, CurrencyIdentifier, AccountId32)
}

impl TrustedCall {
    fn account(&self) -> &AccountId {
        match self {
            TrustedCall::balance_transfer(account, _, _, _) => account,
            TrustedCall::ceremonies_register_participant(account, _, _) => account,
            TrustedCall::ceremonies_register_attestations(account, _) => account,
            TrustedCall::ceremonies_grant_reputation(account, _, _) => account,
        }
    }

    pub fn sign(
        &self,
        pair: &sr25519::Pair,
        nonce: u32,
        mrenclave: &[u8; 32],
        shard: &ShardIdentifier,
    ) -> TrustedCallSigned {
        let mut payload = self.encode();
        payload.append(&mut nonce.encode());
        payload.append(&mut mrenclave.encode());
        payload.append(&mut shard.encode());

        TrustedCallSigned {
            call: self.clone(),
            nonce,
            signature: pair.sign(payload.as_slice()).into(),
        }
    }
}

#[derive(Encode, Decode, Clone, Debug)]
#[allow(non_camel_case_types)]
pub enum TrustedGetter {
    balance(AccountId, CurrencyIdentifier),
    registration(AccountId, CurrencyIdentifier),
    meetup_index_time_and_location(AccountId, CurrencyIdentifier),
    attestations(AccountId, CurrencyIdentifier)
}

impl TrustedGetter {
    pub fn account(&self) -> &AccountId {
        match self {
            TrustedGetter::balance(account, _) => account,
            TrustedGetter::registration(account, _) => account,
            TrustedGetter::meetup_index_time_and_location(account, _) => account,
            TrustedGetter::attestations(account, _) => account,
        }
    }

    pub fn sign(&self, pair: &sr25519::Pair) -> TrustedGetterSigned {
        let signature = pair.sign(self.encode().as_slice()).into();
        TrustedGetterSigned {
            getter: self.clone(),
            signature,
        }
    }
}

#[derive(Encode, Decode, Clone)]
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

#[derive(Encode, Decode, Clone)]
pub struct TrustedCallSigned {
    pub call: TrustedCall,
    pub nonce: u32,
    pub signature: AnySignature,
}

impl TrustedCallSigned {
    pub fn new(call: TrustedCall, nonce: u32, signature: AnySignature) -> Self {
        TrustedCallSigned {
            call,
            nonce,
            signature,
        }
    }

    pub fn verify_signature(&self, mrenclave: &[u8; 32], shard: &ShardIdentifier) -> bool {
        let mut payload = self.call.encode();
        payload.append(&mut self.nonce.encode());
        payload.append(&mut mrenclave.encode());
        payload.append(&mut shard.encode());
        self.signature
            .verify(payload.as_slice(), self.call.account())
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
pub struct Stf {}

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
            AccountKeyring::Alice.public(),
            AccountKeyring::Alice.public(),
            42,
            42,
        );
        let signed_call = call.sign(&AccountKeyring::Alice.pair(), nonce, &mrenclave, &shard);

        assert!(signed_call.verify_signature(&mrenclave, &shard));
    }
}
