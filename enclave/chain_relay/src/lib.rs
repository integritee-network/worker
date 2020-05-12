// Copyright 2017-2019 Parity Technologies (UK) Ltd.
// This file is part of Substrate.

// Substrate is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

// Substrate is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.

// You should have received a copy of the GNU General Public License
// along with Substrate.  If not, see <http://www.gnu.org/licenses/>.

#![cfg_attr(not(target_env = "sgx"), no_std)]
#![cfg_attr(target_env = "sgx", feature(rustc_private))]

#[cfg(not(target_env = "sgx"))]
#[macro_use]
extern crate sgx_tstd as std;

pub mod error;
pub mod justification;
pub mod state;
pub mod storage_proof;

use crate::std::collections::BTreeMap;
use crate::std::fmt;
use crate::std::vec::Vec;
use core::iter::Iterator;

use error::Error;
use justification::GrandpaJustification;
use state::RelayState;
use storage_proof::StorageProof;

use codec::{Decode, Encode};
use core::iter::FromIterator;
use finality_grandpa::voter_set::VoterSet;
use log::info;
use sp_finality_grandpa::{AuthorityId, AuthorityList, SetId};
use sp_runtime::generic::{Block as BlockG, Header as HeaderG};
use sp_runtime::traits::{
    BlakeTwo256, Block as BlockT, Hash as HashT, Header as HeaderT, NumberFor,
};
use sp_runtime::{Justification, OpaqueExtrinsic};

type RelayId = u64;
pub type Header = HeaderG<u32, BlakeTwo256>;
pub type Block = BlockG<Header, OpaqueExtrinsic>;

#[derive(Encode, Decode, Clone, Default)]
pub struct LightValidation {
    pub num_relays: RelayId,
    pub tracked_relays: BTreeMap<RelayId, RelayState<Block>>,
}

impl LightValidation {
    pub fn new() -> Self {
        LightValidation::default()
    }

    pub fn initialize_relay(
        &mut self,
        block_header: Header,
        validator_set: AuthorityList,
        _validator_set_proof: StorageProof,
    ) -> Result<RelayId, Error> {
        // Todo: Enable when we get proofs
        // let state_root = block_header.state_root();
        // Self::check_validator_set_proof::<<Header as HeaderT>::Hashing>(
        //     state_root,
        //     validator_set_proof,
        //     &validator_set,
        // )?;

        let relay_info = RelayState::new(block_header, validator_set);

        let new_relay_id = self.num_relays + 1;
        self.tracked_relays.insert(new_relay_id, relay_info);

        self.num_relays = new_relay_id;

        Ok(new_relay_id)
    }

    pub fn submit_finalized_headers(
        &mut self,
        relay_id: RelayId,
        header: Header,
        ancestry_proof: Vec<Header>,
        validator_set: AuthorityList,
        validator_set_id: SetId,
        grandpa_proof: Justification,
    ) -> Result<(), Error> {
        let relay = self
            .tracked_relays
            .get(&relay_id)
            .ok_or(Error::NoSuchRelayExists)?;

        // Check that the new header is a decendent of the old header
        let last_header = &relay.last_finalized_block_header;
        Self::verify_ancestry(ancestry_proof, last_header.hash(), &header)?;

        let block_hash = header.hash();
        let block_num = *header.number();

        // Check that the header has been finalized
        let voter_set = VoterSet::from_iter(validator_set.clone());
        Self::verify_grandpa_proof::<Block>(
            grandpa_proof,
            block_hash,
            block_num,
            validator_set_id,
            &voter_set,
        )?;

        match self.tracked_relays.get_mut(&relay_id) {
            Some(relay_info) => {
                relay_info.last_finalized_block_header = header.clone();
                relay_info.headers.push(header);
                if validator_set_id > relay_info.current_validator_set_id {
                    relay_info.current_validator_set = validator_set;
                    relay_info.current_validator_set_id = validator_set_id;
                }
            }
            _ => panic!("We succesfully got this relay earlier, therefore it exists; qed"),
        };

        Ok(())
    }

    pub fn submit_simple_header(
        &mut self,
        relay_id: RelayId,
        header: Header,
        grandpa_proof: Justification,
    ) -> Result<(), Error> {
        let relay = self
            .tracked_relays
            .get(&relay_id)
            .ok_or(Error::NoSuchRelayExists)?;
        if relay.last_finalized_block_header.hash() != *header.parent_hash() {
            return Err(Error::HeaderAncestryMismatch);
        }
        let ancestry_proof = vec![];
        let validator_set = relay.current_validator_set.clone();
        let validator_set_id = relay.current_validator_set_id;
        self.submit_finalized_headers(
            relay_id,
            header,
            ancestry_proof,
            validator_set,
            validator_set_id,
            grandpa_proof,
        )
    }

    pub fn submit_xt_to_be_included(
        &mut self,
        relay_id: RelayId,
        extrinsic: OpaqueExtrinsic,
    ) -> Result<(), Error> {
        let relay = self
            .tracked_relays
            .get_mut(&relay_id)
            .ok_or(Error::NoSuchRelayExists)?;
        relay.verify_tx_inclusion.push(extrinsic);
        Ok(())
    }

    pub fn check_xt_inclusion(&mut self, block: &Block) -> Result<(), Error> {
        let relay = self
            .tracked_relays
            .get_mut(&self.num_relays)
            .ok_or(Error::NoSuchRelayExists)?;

        if !Self::_has_xt_to_be_included(relay) {
            return Ok(());
        }

        let mut found_xts = vec![];
        block.extrinsics.iter().for_each(|xt| {
            if let Some(index) = relay.verify_tx_inclusion.iter().position(|xt_opaque| {
                <<Header as HeaderT>::Hashing>::hash_of(xt)
                    == <<Header as HeaderT>::Hashing>::hash_of(xt_opaque)
            }) {
                found_xts.push(index);
            }
        });

        let rm: Vec<OpaqueExtrinsic> = found_xts
            .into_iter()
            .map(|i| relay.verify_tx_inclusion.remove(i))
            .collect();

        if !rm.is_empty() {
            info!("Verified that {} extrinsics have been included.", rm.len());
        }

        Ok(())
    }

    pub fn has_xt_to_be_included(&mut self, relay_id: RelayId) -> Result<bool, Error> {
        let relay = self
            .tracked_relays
            .get(&relay_id)
            .ok_or(Error::NoSuchRelayExists)?;
        Ok(Self::_has_xt_to_be_included(relay))
    }

    fn _has_xt_to_be_included(relay: &RelayState<Block>) -> bool {
        match relay.verify_tx_inclusion.len() {
            0 => false,
            _amount => true,
        }
    }

    //
    // fn check_validator_set_proof<Hash: HashT>(
    //     state_root: &Hash::Out,
    //     proof: StorageProof,
    //     validator_set: &Vec<(AuthorityId, AuthorityWeight)>,
    // ) -> Result<(), Error> {
    //     let checker = StorageProofChecker::<Hash>::new(*state_root, proof.clone())?;
    //
    //     // By encoding the given set we should have an easy way to compare
    //     // with the stuff we get out of storage via `read_value`
    //     let mut encoded_validator_set = validator_set.encode();
    //     encoded_validator_set.insert(0, 1); // Add AUTHORITIES_VERISON == 1
    //     let actual_validator_set = checker
    //         .read_value(b":grandpa_authorities")?
    //         .ok_or(Error::StorageValueUnavailable)?;
    //
    //     if encoded_validator_set == actual_validator_set {
    //         Ok(())
    //     } else {
    //         Err(Error::ValidatorSetMismatch)
    //     }
    // }

    fn verify_grandpa_proof<Block>(
        justification: Justification,
        hash: Block::Hash,
        number: NumberFor<Block>,
        set_id: u64,
        voters: &VoterSet<AuthorityId>,
    ) -> Result<(), Error>
    where
        Block: BlockT,
        NumberFor<Block>: finality_grandpa::BlockNumberOps,
    {
        // We don't really care about the justification, as long as it's valid
        let _ = GrandpaJustification::<Block>::decode_and_verify_finalizes(
            &justification,
            (hash, number),
            set_id,
            voters,
        )?;

        Ok(())
    }

    // A naive way to check whether a `child` header is a decendent
    // of an `ancestor` header. For this it requires a proof which
    // is a chain of headers between (but not including) the `child`
    // and `ancestor`. This could be updated to use something like
    // Log2 Ancestors (#2053) in the future.
    fn verify_ancestry<Header>(
        proof: Vec<Header>,
        ancestor_hash: Header::Hash,
        child: &Header,
    ) -> Result<(), Error>
    where
        Header: HeaderT,
    {
        let mut parent_hash = child.parent_hash();
        if *parent_hash == ancestor_hash {
            return Ok(());
        }

        // If we find that the header's parent hash matches our ancestor's hash we're done
        for header in proof.iter() {
            // Need to check that blocks are actually related
            if header.hash() != *parent_hash {
                break;
            }

            parent_hash = header.parent_hash();
            if *parent_hash == ancestor_hash {
                return Ok(());
            }
        }

        Err(Error::InvalidAncestryProof)
    }
}

impl fmt::Debug for LightValidation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "LightValidationTest {{ num_relays: {}, tracked_relays: {:?} }}",
            self.num_relays, self.tracked_relays
        )
    }
}
