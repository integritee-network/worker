use sgx_tstd as std;
use std::collections::HashMap;
use std::prelude::v1::*;

use codec::{Decode, Encode};
use derive_more::Display;
use log_sgx::*;
use metadata::StorageHasher;
use sgx_runtime::{Balance, Runtime};
use sp_core::crypto::{AccountId32, Ss58Codec};
use sp_io::SgxExternalitiesTrait;
use sp_runtime::traits::Dispatchable;
use encointer_scheduler::{CeremonyIndexType, CeremonyPhaseType};
use encointer_balances::BalanceType;
use encointer_currencies::CurrencyIdentifier;
use encointer_ceremonies::{ParticipantIndexType, MeetupIndexType};
use sgx_runtime::Moment;

use crate::{
    AccountId, State, Stf, TrustedCall, TrustedCallSigned, TrustedGetter, TrustedGetterSigned,
    SUBSRATEE_REGISTRY_MODULE, UNSHIELD,
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
type AccountData = ();//balances::AccountData<Balance>;
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
            // do not set genesis for pallets that are meant to be on-chain
            // use get_storage_hashes_to_update instead
            sp_io::storage::set(
                &storage_value_key("EncointerCeremonies", "CeremonyReward"),
                &BalanceType::from_num(1).encode(),
            );
            sp_io::storage::set(
                &storage_value_key("EncointerCeremonies", "TimeTolerance"),
                &Moment::from(600_000u32).encode(), // +-10min
            );
            sp_io::storage::set(
                &storage_value_key("EncointerCeremonies", "LocationTolerance"),
                &1_000u32.encode(),// [m]
            );
            sp_io::storage::set(&storage_value_key("Sudo", "Key"), &ALICE_ENCODED);
        });
        ext
    }

    pub fn update_storage(ext: &mut State, map_update: &HashMap<Vec<u8>, Vec<u8>>) {
        ext.execute_with(|| {
            map_update
                .iter()
                .for_each(|(k, v)| sp_io::storage::set(k, v))
        });
    }

    pub fn execute(
        ext: &mut State,
        call: TrustedCallSigned,
        calls: &mut Vec<OpaqueCall>,
    ) -> Result<(), StfError> {
        ext.execute_with(|| match call.call {
                TrustedCall::balance_transfer(from, to, cid, value) => {
                    let origin = sgx_runtime::Origin::signed(AccountId32::from(from));
                    sgx_runtime::EncointerBalancesCall::<Runtime>::transfer(AccountId32::from(to), cid, value)
                        .dispatch(origin)
                        .map_err(|_| StfError::Dispatch)?;
                    Ok(())
                }
                TrustedCall::ceremonies_register_participant(from, cid, proof) => {
                    let origin = sgx_runtime::Origin::signed(AccountId32::from(from));
                    sgx_runtime::EncointerCeremoniesCall::<Runtime>::register_participant(cid, proof)
                        .dispatch(origin)
                        .map_err(|_| StfError::Dispatch)?;
                    Ok(())
                }
            }
        })
    }

    pub fn get_state(ext: &mut State, getter: TrustedGetter) -> Option<Vec<u8>> {
        ext.execute_with(|| match getter {
            TrustedGetter::balance(who, cid) => {
                Some(get_encointer_balance(&who, &cid).encode())
            },
            TrustedGetter::ceremony_registration(who, cid) => {
                Some(get_ceremony_registration(&who, &cid).encode())
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

    pub fn get_storage_hashes_to_update(call: &TrustedCallSigned) -> Vec<Vec<u8>> {
        let mut key_hashes = Vec::new();
        match call.call {
            TrustedCall::balance_transfer(account, _, _, _) => {
                key_hashes.push(nonce_key_hash(account))
            },
            TrustedCall::ceremonies_register_participant(account, _, _) => {
                key_hashes.push(storage_value_key("EncointerScheduler", "CurrentPhase"));
                key_hashes.push(storage_value_key("EncointerScheduler", "CurrentCeremonyIndex"));
                key_hashes.push(storage_value_key("EncointerCurrencies", "CurrencyIdentifiers"));
            }
        };
        key_hashes
    }

    pub fn get_storage_hashes_to_update_for_getter(getter: &TrustedGetterSigned) -> Vec<Vec<u8>> {
        let key_hashes = Vec::new();
        info!("No storage updates needed for getter: {:?}", getter.getter); // dummy. Is currently not needed
        key_hashes
    }

    pub fn storage_hashes_to_update_on_block() -> Vec<Vec<u8>> {
        // let key_hashes = Vec::new();
        // key_hashes.push(storage_value_key("dummy", "dummy"));
        // key_hashes
        Vec::new()
    }
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

fn get_ceremony_registration(who: &AccountId, cid: &CurrencyIdentifier) -> ParticipantIndexType {
    let cindex = match sp_io::storage::get(&storage_value_key(
        "EncointerScheduler",
        "CurrentCeremonyIndex")) {
            Some(val) => if let Ok(v) = CeremonyIndexType::decode(&mut val.as_slice()) { v } else { 0 },
            None => 0
    };
    info!("cindex = {}", cindex);
    if let Some(res) = sp_io::storage::get(&storage_double_map_key(
        "EncointerCeremonies",
        "ParticipantIndex",
        &(cid,cindex), 
        &StorageHasher::Blake2_128Concat,
        who,
        &StorageHasher::Blake2_128Concat,
    )) {
        if let Ok(pindex) = ParticipantIndexType::decode(&mut res.as_slice()) {
            pindex
        } else {
            debug!("can't decode ParticipantIndexType for {:x?}", res);
            0
        }
    } else {
        debug!("no registration for caller");
        0
    }
}

fn get_encointer_balance(who: &AccountId, cid: &CurrencyIdentifier) -> BalanceType {
    if let Some(balvec) = sp_io::storage::get(&storage_double_map_key(
        "EncointerBalances",
        "Balance",
        cid,
        &StorageHasher::Blake2_128Concat,
        who,
        &StorageHasher::Blake2_128Concat,
    )) {
        if let Ok(bal) = BalanceType::decode(&mut balvec.as_slice()) {
            bal
        } else {
            BalanceType::from_num(0)
        }
    } else {
        BalanceType::from_num(0)
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
