use sgx_tstd as std;
use std::collections::HashMap;
use std::prelude::v1::*;

use codec::{Decode, Encode};
use derive_more::Display;
use log_sgx::*;
use metadata::StorageHasher;
use sgx_runtime::{Balance, Runtime};
use sp_core::crypto::AccountId32;
use sp_io::SgxExternalitiesTrait;
use sp_runtime::traits::Dispatchable;

use crate::{
    AccountId, State, Stf, TrustedCall, TrustedCallSigned, TrustedGetter, TrustedGetterSigned,
    ShardIdentifier, SUBSRATEE_REGISTRY_MODULE, UNSHIELD,
};
use sp_core::blake2_256;

/// Simple blob that holds a call in encoded format
#[derive(Clone, Debug)]
pub struct OpaqueCall(pub Vec<u8>);

impl Encode for OpaqueCall {
    fn encode(&self) -> Vec<u8> {
        self.0.clone()
    }
}

type Index = u32;
type AccountData = balances::AccountData<Balance>;
type AccountInfo = system::AccountInfo<Index, AccountData>;
const ALICE_ENCODED: [u8; 32] = [
    212, 53, 147, 199, 21, 253, 211, 28, 97, 20, 26, 189, 4, 169, 159, 214, 130, 44, 133, 88, 133,
    76, 205, 227, 154, 86, 132, 231, 165, 109, 162, 125,
];

impl Stf {
    pub fn init_state() -> State {
        debug!("initializing stf state");
        let mut ext = State::new();
        ext.execute_with(|| {
            sp_io::storage::set(
                &storage_value_key("Balances", "TotalIssuance"),
                &11u128.encode(),
            );
            sp_io::storage::set(
                &storage_value_key("Balances", "CreationFee"),
                &1u128.encode(),
            );
            sp_io::storage::set(
                &storage_value_key("Balances", "TransferFee"),
                &1u128.encode(),
            );
            sp_io::storage::set(
                &storage_value_key("Balances", "TransactionBaseFee"),
                &1u128.encode(),
            );
            sp_io::storage::set(
                &storage_value_key("Balances", "TransfactionByteFee"),
                &1u128.encode(),
            );
            sp_io::storage::set(
                &storage_value_key("Balances", "ExistentialDeposit"),
                &1u128.encode(),
            );
            sp_io::storage::set(&storage_value_key("Sudo", "Key"), &ALICE_ENCODED);
        });
        ext
    }

    pub fn update_storage(ext: &mut State, map_update: &HashMap<Vec<u8>, Option<Vec<u8>>>) {
        ext.execute_with(|| {
            map_update
                .iter()
                .for_each(|(k, v)| {
                    match v {
                        Some(value) => sp_io::storage::set(k, value),
                        None => sp_io::storage::clear(k)
                    };
                });
        });
    }

    pub fn execute(
        ext: &mut State,
        call: TrustedCallSigned,
        calls: &mut Vec<OpaqueCall>,
    ) -> Result<(), StfError> {
        ext.execute_with(|| match call.call {
            TrustedCall::balance_set_balance(root, who, free_balance, reserved_balance) => {
                Self::ensure_root(root)?;
                sgx_runtime::BalancesCall::<Runtime>::set_balance(
                    AccountId32::from(who),
                    free_balance,
                    reserved_balance,
                )
                .dispatch(sgx_runtime::Origin::ROOT)
                .map_err(|_| StfError::Dispatch)?;
                Ok(())
            }
            TrustedCall::balance_transfer(from, to, value) => {
                let origin = sgx_runtime::Origin::signed(AccountId32::from(from));
                sgx_runtime::BalancesCall::<Runtime>::transfer(AccountId32::from(to), value)
                    .dispatch(origin)
                    .map_err(|_| StfError::Dispatch)?;
                Ok(())
            }
            TrustedCall::balance_unshield(account_incognito, beneficiary, value, shard) => {
                Self::unshield_funds(account_incognito, value)?;
                calls.push(OpaqueCall(
                    (
                        [SUBSRATEE_REGISTRY_MODULE, UNSHIELD],
                        beneficiary,
                        value,
                        shard,
                        blake2_256(&call.encode()),
                    )
                        .encode(),
                ));
                Ok(())
            }
            TrustedCall::balance_shield(who, value) => {
                Self::shield_funds(who, value)?;
                Ok(())
            }
        })
    }

    pub fn get_state(ext: &mut State, getter: TrustedGetter) -> Option<Vec<u8>> {
        ext.execute_with(|| match getter {
            TrustedGetter::free_balance(who) => {
                if let Some(info) = get_account_info(&who) {
                    debug!("AccountInfo for {:?} is {:?}", who, info);
                    Some(info.data.free.encode())
                } else {
                    None
                }
            }
            TrustedGetter::reserved_balance(who) => {
                if let Some(info) = get_account_info(&who) {
                    debug!("AccountInfo for {:?} is {:?}", who, info);
                    Some(info.data.reserved.encode())
                } else {
                    None
                }
            }
        })
    }

    fn ensure_root(account: AccountId) -> Result<(), StfError> {
        if sp_io::storage::get(&storage_value_key("Sudo", "Key")).unwrap() == account.encode() {
            Ok(())
        } else {
            Err(StfError::MissingPrivileges(account))
        }
    }

    fn shield_funds(account: AccountId, amount: u128) -> Result<(), StfError> {
        match get_account_info(&account) {
            Some(account_info) => sgx_runtime::BalancesCall::<Runtime>::set_balance(
                account.into(),
                account_info.data.free + amount,
                account_info.data.reserved,
            )
            .dispatch(sgx_runtime::Origin::ROOT)
            .map_err(|_| StfError::Dispatch)?,
            None => sgx_runtime::BalancesCall::<Runtime>::set_balance(account.into(), amount, 0)
                .dispatch(sgx_runtime::Origin::ROOT)
                .map_err(|_| StfError::Dispatch)?,
        };
        Ok(())
    }

    fn unshield_funds(account: AccountId, amount: u128) -> Result<(), StfError> {
        match get_account_info(&account) {
            Some(account_info) => {
                if account_info.data.free < amount {
                    return Err(StfError::MissingFunds);
                }

                sgx_runtime::BalancesCall::<Runtime>::set_balance(
                    account.into(),
                    account_info.data.free - amount,
                    account_info.data.reserved,
                )
                .dispatch(sgx_runtime::Origin::ROOT)
                .map_err(|_| StfError::Dispatch)?;
                Ok(())
            }
            None => Err(StfError::InexistentAccount(account)),
        }
    }

    pub fn get_storage_hashes_to_update(call: &TrustedCallSigned) -> Vec<Vec<u8>> {
        let mut key_hashes = Vec::new();
        match call.call {
            TrustedCall::balance_set_balance(account, _, _, _) => {
                key_hashes.push(nonce_key_hash(&account)) // dummy, actually not necessary
            }
            TrustedCall::balance_transfer(account, _, _) => {
                key_hashes.push(nonce_key_hash(&account)) // dummy, actually not necessary
            }
            TrustedCall::balance_unshield(account, _, _, _) => {
                key_hashes.push(nonce_key_hash(&account))
            }
            TrustedCall::balance_shield(_, _) => debug!("No storage updates needed..."),
        };
        key_hashes
    }

    pub fn get_storage_hashes_to_update_for_getter(getter: &TrustedGetterSigned) -> Vec<Vec<u8>> {
        info!("No specific storage updates needed for getter. Returning those for on block: {:?}", getter.getter);
        Self::storage_hashes_to_update_on_block()
    }

    pub fn storage_hashes_to_update_on_block() -> Vec<Vec<u8>> {
        let mut key_hashes = Vec::new();

        // get all shards that are currently registered
        key_hashes.push(shards_key_hash());

        key_hashes
    }
}

pub fn storage_hashes_to_update_per_shard(_shard: &ShardIdentifier) -> Vec<Vec<u8>> {
    Vec::new()
}

pub fn shards_key_hash() -> Vec<u8> {
    storage_value_key("EncointerCurrencies", "CurrencyIdentifiers")
}

// get the AccountInfo key where the nonce is stored
pub fn nonce_key_hash(account: &AccountId) -> Vec<u8> {
    storage_map_key(
        "System",
        "Account",
        account,
        &StorageHasher::Blake2_128Concat,
    )
}

fn get_account_info(who: &AccountId) -> Option<AccountInfo> {
    if let Some(infovec) = sp_io::storage::get(&storage_map_key(
        "System",
        "Account",
        who,
        &StorageHasher::Blake2_128Concat,
    )) {
        if let Ok(info) = AccountInfo::decode(&mut infovec.as_slice()) {
            Some(info)
        } else {
            None
        }
    } else {
        None
    }
}

pub fn storage_value_key(module_prefix: &str, storage_prefix: &str) -> Vec<u8> {
    let mut bytes = sp_core::twox_128(module_prefix.as_bytes()).to_vec();
    bytes.extend(&sp_core::twox_128(storage_prefix.as_bytes())[..]);
    bytes
}

pub fn storage_map_key<K: Encode>(
    module_prefix: &str,
    storage_prefix: &str,
    mapkey1: &K,
    hasher1: &StorageHasher,
) -> Vec<u8> {
    let mut bytes = sp_core::twox_128(module_prefix.as_bytes()).to_vec();
    bytes.extend(&sp_core::twox_128(storage_prefix.as_bytes())[..]);
    bytes.extend(key_hash(mapkey1, hasher1));
    bytes
}

pub fn storage_double_map_key<K: Encode, Q: Encode>(
    module_prefix: &str,
    storage_prefix: &str,
    mapkey1: &K,
    hasher1: &StorageHasher,
    mapkey2: &Q,
    hasher2: &StorageHasher,
) -> Vec<u8> {
    let mut bytes = sp_core::twox_128(module_prefix.as_bytes()).to_vec();
    bytes.extend(&sp_core::twox_128(storage_prefix.as_bytes())[..]);
    bytes.extend(key_hash(mapkey1, hasher1));
    bytes.extend(key_hash(mapkey2, hasher2));
    bytes
}

/// generates the key's hash depending on the StorageHasher selected
fn key_hash<K: Encode>(key: &K, hasher: &StorageHasher) -> Vec<u8> {
    let encoded_key = key.encode();
    match hasher {
        StorageHasher::Identity => encoded_key.to_vec(),
        StorageHasher::Blake2_128 => sp_core::blake2_128(&encoded_key).to_vec(),
        StorageHasher::Blake2_128Concat => {
            // copied from substrate Blake2_128Concat::hash since StorageHasher is not public
            let x: &[u8] = encoded_key.as_slice();
            sp_core::blake2_128(x)
                .iter()
                .chain(x.iter())
                .cloned()
                .collect::<Vec<_>>()
        }
        StorageHasher::Blake2_256 => sp_core::blake2_256(&encoded_key).to_vec(),
        StorageHasher::Twox128 => sp_core::twox_128(&encoded_key).to_vec(),
        StorageHasher::Twox256 => sp_core::twox_256(&encoded_key).to_vec(),
        StorageHasher::Twox64Concat => sp_core::twox_64(&encoded_key).to_vec(),
    }
}

#[derive(Debug, Display)]
pub enum StfError {
    #[display(fmt = "Insufficient privileges {:?}, are you sure you are root?", _0)]
    MissingPrivileges(AccountId),
    #[display(fmt = "Error dispatching runtime call")]
    Dispatch,
    #[display(fmt = "Not enough funds to perform operation")]
    MissingFunds,
    #[display(fmt = "Account does not exist {:?}", _0)]
    InexistentAccount(AccountId),
}
