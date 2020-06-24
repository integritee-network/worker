use sgx_tstd as std;
use std::collections::HashMap;
use std::prelude::v1::*;

use codec::{Decode, Encode};
use derive_more::Display;
use log_sgx::*;
use metadata::StorageHasher;
use sgx_runtime::{Runtime, BlockNumber};
use sp_core::crypto::AccountId32;
use sp_io::SgxExternalitiesTrait;
use sp_runtime::traits::Dispatchable;
use encointer_scheduler::{CeremonyPhaseType, OnCeremonyPhaseChange};
use encointer_balances::{BalanceType, BalanceEntry};
use encointer_currencies::{CurrencyIdentifier, Location};
use encointer_ceremonies::{ParticipantIndexType, MeetupIndexType};
use sgx_runtime::Moment;

use crate::{AccountId, State, Stf, TrustedCall, TrustedCallSigned, Getter, PublicGetter, TrustedGetter, ShardIdentifier};

/// Simple blob that holds a call in encoded format
#[derive(Clone, Debug)]
pub struct OpaqueCall(pub Vec<u8>);

impl Encode for OpaqueCall {
    fn encode(&self) -> Vec<u8> {
        self.0.clone()
    }
}

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

    pub fn update_storage(ext: &mut State, map_update: &HashMap<Vec<u8>, Option<Vec<u8>>>) {
        ext.execute_with(|| {
            let key = storage_value_key("EncointerScheduler", "CurrentPhase");

            let next_phase = match map_update.get(&key) {
                Some(maybe_phase) => maybe_phase.to_owned(),
                None => None,
            };
            let curr_phase = sp_io::storage::get(&key);

            map_update
                .iter()
                .for_each(|(k, v)| {
                    match v {
                        Some(value) => sp_io::storage::set(k, value),
                        None => sp_io::storage::clear(k)
                    };
                });

            if next_phase.is_some() && next_phase != curr_phase {
                if let Ok(next_phase) = CeremonyPhaseType::decode(&mut &next_phase.unwrap()[..])
                {
                    info!("Updated phase. Phase is now: {:?}", next_phase);
                    encointer_ceremonies::Module::<sgx_runtime::Runtime>::on_ceremony_phase_change(next_phase);
                }
            }
        });
    }

    pub fn update_block_number(ext: &mut State, number: BlockNumber) {
        ext.execute_with(|| {
            let key = storage_value_key("System", "Number");
            sp_io::storage::set(&key, &number.encode());
        });
    }


    pub fn execute(
        ext: &mut State,
        call: TrustedCallSigned,
        _calls: &mut Vec<OpaqueCall>,
    ) -> Result<(), StfError> {
        ext.execute_with(|| match call.call {
            TrustedCall::balance_transfer(from, to, cid, value) => {
                let origin = sgx_runtime::Origin::signed(AccountId32::from(from));
                sgx_runtime::EncointerBalancesCall::<Runtime>::transfer(AccountId32::from(to), cid, value)
                    .dispatch(origin)
                    .map_err(|_| StfError::Dispatch("balance_transfer".to_string()))?;
                Ok(())
            }
            TrustedCall::ceremonies_register_participant(from, cid, proof) => {
                let origin = sgx_runtime::Origin::signed(AccountId32::from(from));

                if encointer_scheduler::Module::<sgx_runtime::Runtime>::current_phase() != CeremonyPhaseType::REGISTERING {
                    return Err(StfError::Dispatch("registering participants can only be done during REGISTERING phase".to_string()))
                }

                sgx_runtime::EncointerCeremoniesCall::<Runtime>::register_participant(cid, proof)
                    .dispatch(origin)
                    .map_err(|_| StfError::Dispatch("ceremonies_register_participant".to_string()))?;
                Ok(())
            }
            TrustedCall::ceremonies_register_attestations(from, attestations) => {
                let origin = sgx_runtime::Origin::signed(AccountId32::from(from));
                sgx_runtime::EncointerCeremoniesCall::<Runtime>::register_attestations(attestations)
                    .dispatch(origin)
                    .map_err(|_| StfError::Dispatch("ceremonies_register_attestations".to_string()))?;
                Ok(())
            }
            TrustedCall::ceremonies_grant_reputation(ceremony_master, cid, reputable) => {
                Self::ensure_ceremony_master(ceremony_master)?;
                let origin = sgx_runtime::Origin::signed(AccountId32::from(ceremony_master));
                sgx_runtime::EncointerCeremoniesCall::<Runtime>::grant_reputation(cid, reputable)
                    .dispatch(origin)
                    .map_err(|_| StfError::Dispatch("ceremonies_grant_reputation".to_string()))?;
                Ok(())
            }
        })
    }

    pub fn get_state(ext: &mut State, getter: Getter) -> Option<Vec<u8>> {
        ext.execute_with(|| 
            match getter {
                Getter::trusted(g) => match g.getter {
                    TrustedGetter::balance(who, cid) => {
                        let balance: BalanceEntry<BlockNumber> = encointer_balances::Module::<sgx_runtime::Runtime>::balance_entry(cid, AccountId32::from(who));
                        Some(balance.encode())
                    },
                    TrustedGetter::registration(who, cid) => {
                        let c_index = encointer_scheduler::Module::<sgx_runtime::Runtime>::current_ceremony_index();
                        let part: ParticipantIndexType = encointer_ceremonies::Module::<sgx_runtime::Runtime>::participant_index((cid, c_index), AccountId32::from(who));
                        Some(part.encode())
                    }
                    TrustedGetter::meetup_index_time_and_location(who, cid) => {
                        let c_index = encointer_scheduler::Module::<sgx_runtime::Runtime>::current_ceremony_index();
                        let meetup_index: MeetupIndexType = encointer_ceremonies::Module::<sgx_runtime::Runtime>::meetup_index((cid, c_index), AccountId32::from(who));
                        let time: Option<Moment> =  encointer_ceremonies::Module::<sgx_runtime::Runtime>::get_meetup_time(&cid, meetup_index);
                        let location: Option<Location> = encointer_ceremonies::Module::<sgx_runtime::Runtime>::get_meetup_location(&cid, meetup_index);
                        let enc = (meetup_index, location, time).encode();
                        Some(enc)
                    }
                    TrustedGetter::attestations(who, cid) => {
                        let c_index = encointer_scheduler::Module::<sgx_runtime::Runtime>::current_ceremony_index();
                        let attestation_index = encointer_ceremonies::Module::<sgx_runtime::Runtime>::attestation_index((cid, c_index), AccountId32::from(who));
                        let attestations = encointer_ceremonies::Module::<sgx_runtime::Runtime>::attestation_registry((cid, c_index), attestation_index);
                        Some(attestations.encode())
                    }
                },
                Getter::public(g) => match g {
                    PublicGetter::total_issuance(cid) => {
                        let c_index = encointer_scheduler::Module::<sgx_runtime::Runtime>::current_ceremony_index();
                        let balance: BalanceEntry<BlockNumber> = encointer_balances::Module::<sgx_runtime::Runtime>::total_issuance_entry(cid);
                        Some(balance.encode())
                    },
                    PublicGetter::participant_count(cid) => {
                        let c_index = encointer_scheduler::Module::<sgx_runtime::Runtime>::current_ceremony_index();
                        match encointer_scheduler::Module::<sgx_runtime::Runtime>::current_phase() {
                            CeremonyPhaseType::REGISTERING => {
                                warn!("querying participant count during registering phase not allowed for privacy reasons");
                                None
                            },
                            _ => { 
                                let count = encointer_ceremonies::Module::<sgx_runtime::Runtime>::participant_count((cid, c_index));
                                Some(count.encode())
                            }
                        }
                    },
                    PublicGetter::meetup_count(cid) => {
                        let c_index = encointer_scheduler::Module::<sgx_runtime::Runtime>::current_ceremony_index();
                        let count = encointer_ceremonies::Module::<sgx_runtime::Runtime>::meetup_count((cid, c_index));
                        Some(count.encode())
                    },
                    PublicGetter::ceremony_reward(cid) => {
                        let reward = encointer_ceremonies::Module::<sgx_runtime::Runtime>::ceremony_reward();
                        Some(reward.encode())
                    },
                    PublicGetter::location_tolerance(cid) => {
                        let tol = encointer_ceremonies::Module::<sgx_runtime::Runtime>::location_tolerance();
                        Some(tol.encode())
                    },
                    PublicGetter::time_tolerance(cid)   => {
                        let tol = encointer_ceremonies::Module::<sgx_runtime::Runtime>::time_tolerance();
                        Some(tol.encode())
                    }              
                }
            }
        )
    }

    fn ensure_ceremony_master(account: AccountId) -> Result<(), StfError> {
        if sp_io::storage::get(&storage_value_key("EncointerScheduler", "CeremonyMaster")).unwrap() == account.encode() {
            Ok(())
        } else {
            Err(StfError::MissingPrivileges(account))
        }
    }

    pub fn get_storage_hashes_to_update(call: &TrustedCallSigned) -> Vec<Vec<u8>> {
        let mut key_hashes = Vec::new();
        match call.call {
            TrustedCall::balance_transfer(account, _, _, _) => {
                key_hashes.push(nonce_key_hash(&account))
            }
            TrustedCall::ceremonies_register_participant(_, _, _) => {
                key_hashes.push(storage_value_key("EncointerScheduler", "CurrentPhase"));
                key_hashes.push(storage_value_key("EncointerScheduler", "CurrentCeremonyIndex"));
                key_hashes.push(storage_value_key("EncointerCurrencies", "CurrencyIdentifiers"));
            }
            TrustedCall::ceremonies_register_attestations(_, _) => {
                key_hashes.push(storage_value_key("EncointerScheduler", "CurrentPhase"));
                key_hashes.push(storage_value_key("EncointerScheduler", "CurrentCeremonyIndex"));
                key_hashes.push(storage_value_key("EncointerCurrencies", "CurrencyIdentifiers"));
            }
            TrustedCall::ceremonies_grant_reputation(_, _, _) => {
                key_hashes.push(storage_value_key("EncointerScheduler", "CurrentCeremonyIndex"));
                key_hashes.push(storage_value_key("EncointerScheduler", "CeremonyMaster"));
            }
        };
        key_hashes
    }

    pub fn get_storage_hashes_to_update_for_getter(getter: &Getter) -> Vec<Vec<u8>> {
        info!("No specific storage updates needed for getter. Returning those for on block: {:?}", getter);
        Self::storage_hashes_to_update_on_block()
    }

    pub fn storage_hashes_to_update_on_block() -> Vec<Vec<u8>> {
        let mut key_hashes = Vec::new();

        // get all shards that are currently registered
        key_hashes.push(shards_key_hash());

        key_hashes.push(storage_value_key("EncointerScheduler", "CurrentPhase"));
        key_hashes.push(storage_value_key("EncointerScheduler", "CurrentCeremonyIndex"));
        key_hashes.push(storage_value_key("EncointerScheduler", "NextPhaseTimestamp"));
        key_hashes.push(storage_value_key("EncointerScheduler", "PhaseDurations"));

        key_hashes
    }
}

pub fn storage_hashes_to_update_per_shard(shard: &ShardIdentifier) -> Vec<Vec<u8>> {
    let mut key_hashes = Vec::new();

    // for encointer CID == ShardIdentifier
    key_hashes.push(bootstrapper_key_hash(shard));
    key_hashes.push(location_key_hash(shard));

    key_hashes
}

pub fn bootstrapper_key_hash(cid: &CurrencyIdentifier) -> Vec<u8> {
    storage_map_key("EncointerCurrencies", "Bootstrappers", cid, &StorageHasher::Blake2_128Concat)
}
pub fn location_key_hash(cid: &CurrencyIdentifier) -> Vec<u8> {
    storage_map_key("EncointerCurrencies", "Locations", cid, &StorageHasher::Blake2_128Concat)
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
    Dispatch(String),
    #[display(fmt = "Not enough funds to perform operation")]
    MissingFunds,
    #[display(fmt = "Account does not exist {:?}", _0)]
    InexistentAccount(AccountId),
}
