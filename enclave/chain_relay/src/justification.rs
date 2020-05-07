// Copyright 2018-2019 Parity Technologies (UK) Ltd.
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

use crate::std::collections::{HashMap, HashSet};
use crate::std::string::ToString;
use crate::std::vec::Vec;

#[cfg(test)]
use sc_client::Client;
#[cfg(test)]
use sc_client_api::{backend::Backend, CallExecutor};

use super::error::JustificationError as ClientError;
use codec::{Decode, Encode};
use finality_grandpa::voter_set::VoterSet;
use finality_grandpa::Error as GrandpaError;
use sp_finality_grandpa::{AuthorityId, AuthoritySignature};
use sp_runtime::traits::{Block as BlockT, Header as HeaderT, NumberFor};

/// A GRANDPA justification for block finality, it includes a commit message and
/// an ancestry proof including all headers routing all precommit target blocks
/// to the commit target block. Due to the current voting strategy the precommit
/// targets should be the same as the commit target, since honest voters don't
/// vote past authority set change blocks.
///
/// This is meant to be stored in the db and passed around the network to other
/// nodes, and are used by syncing nodes to prove authority set handoffs.
#[derive(Encode, Decode)]
pub struct GrandpaJustification<Block: BlockT> {
    round: u64,
    pub(crate) commit: Commit<Block>,
    votes_ancestries: Vec<Block::Header>,
}

impl<Block: BlockT> GrandpaJustification<Block> {
    /// Create a GRANDPA justification from the given commit. This method
    /// assumes the commit is valid and well-formed.
    #[cfg(test)]
    pub(crate) fn from_commit<C>(
        client: &Arc<C>,
        round: u64,
        commit: Commit<Block>,
    ) -> Result<GrandpaJustification<Block>, Error>
    where
        C: HeaderBackend<Block>,
    {
        let mut votes_ancestries_hashes = HashSet::new();
        let mut votes_ancestries = Vec::new();

        let error = || {
            let msg = "invalid precommits for target commit".to_string();
            Err(Error::Client(ClientError::BadJustification(msg)))
        };

        for signed in commit.precommits.iter() {
            let mut current_hash = signed.precommit.target_hash.clone();
            loop {
                if current_hash == commit.target_hash {
                    break;
                }

                match client.header(&BlockId::Hash(current_hash))? {
                    Some(current_header) => {
                        if *current_header.number() <= commit.target_number {
                            return error();
                        }

                        let parent_hash = current_header.parent_hash().clone();
                        if votes_ancestries_hashes.insert(current_hash) {
                            votes_ancestries.push(current_header);
                        }
                        current_hash = parent_hash;
                    }
                    _ => return error(),
                }
            }
        }

        Ok(GrandpaJustification {
            round,
            commit,
            votes_ancestries,
        })
    }

    /// Decode a GRANDPA justification and validate the commit and the votes'
    /// ancestry proofs finalize the given block.
    pub(crate) fn decode_and_verify_finalizes(
        encoded: &[u8],
        finalized_target: (Block::Hash, NumberFor<Block>),
        set_id: u64,
        voters: &VoterSet<AuthorityId>,
    ) -> Result<GrandpaJustification<Block>, ClientError>
    where
        NumberFor<Block>: finality_grandpa::BlockNumberOps,
    {
        let justification = GrandpaJustification::<Block>::decode(&mut &*encoded)
            .map_err(|_| ClientError::JustificationDecode)?;

        if (
            justification.commit.target_hash,
            justification.commit.target_number,
        ) != finalized_target
        {
            let msg = "invalid commit target in grandpa justification".to_string();
            Err(ClientError::BadJustification(msg))
        } else {
            justification.verify(set_id, voters).map(|_| justification)
        }
    }

    /// Validate the commit and the votes' ancestry proofs.
    pub(crate) fn verify(
        &self,
        set_id: u64,
        voters: &VoterSet<AuthorityId>,
    ) -> Result<(), ClientError>
    where
        NumberFor<Block>: finality_grandpa::BlockNumberOps,
    {
        use finality_grandpa::Chain;

        let ancestry_chain = AncestryChain::<Block>::new(&self.votes_ancestries);

        match finality_grandpa::validate_commit(&self.commit, voters, &ancestry_chain) {
            Ok(ref result) if result.ghost().is_some() => {}
            _ => {
                let msg = "invalid commit in grandpa justification".to_string();
                return Err(ClientError::BadJustification(msg));
            }
        }

        let mut buf = Vec::new();
        let mut visited_hashes = HashSet::new();
        for signed in self.commit.precommits.iter() {
            if communication::check_message_sig_with_buffer::<Block>(
                &finality_grandpa::Message::Precommit(signed.precommit.clone()),
                &signed.id,
                &signed.signature,
                self.round,
                set_id,
                &mut buf,
            )
            .is_err()
            {
                return Err(ClientError::BadJustification(
                    "invalid signature for precommit in grandpa justification".to_string(),
                ));
            }

            if self.commit.target_hash == signed.precommit.target_hash {
                continue;
            }

            match ancestry_chain.ancestry(self.commit.target_hash, signed.precommit.target_hash) {
                Ok(route) => {
                    // ancestry starts from parent hash but the precommit target hash has been visited
                    visited_hashes.insert(signed.precommit.target_hash);
                    for hash in route {
                        visited_hashes.insert(hash);
                    }
                }
                _ => {
                    return Err(ClientError::BadJustification(
                        "invalid precommit ancestry proof in grandpa justification".to_string(),
                    ));
                }
            }
        }

        let ancestry_hashes = self
            .votes_ancestries
            .iter()
            .map(|h: &Block::Header| h.hash())
            .collect();

        if visited_hashes != ancestry_hashes {
            return Err(ClientError::BadJustification(
                "invalid precommit ancestries in grandpa justification with unused headers"
                    .to_string(),
            ));
        }

        Ok(())
    }
}

/// A utility trait implementing `finality_grandpa::Chain` using a given set of headers.
/// This is useful when validating commits, using the given set of headers to
/// verify a valid ancestry route to the target commit block.
struct AncestryChain<Block: BlockT> {
    ancestry: HashMap<Block::Hash, Block::Header>,
}

impl<Block: BlockT> AncestryChain<Block> {
    fn new(ancestry: &[Block::Header]) -> AncestryChain<Block> {
        let ancestry: HashMap<_, _> = ancestry
            .iter()
            .cloned()
            .map(|h: Block::Header| (h.hash(), h))
            .collect();

        AncestryChain { ancestry }
    }
}

impl<Block: BlockT> finality_grandpa::Chain<Block::Hash, NumberFor<Block>> for AncestryChain<Block>
where
    NumberFor<Block>: finality_grandpa::BlockNumberOps,
{
    fn ancestry(
        &self,
        base: Block::Hash,
        block: Block::Hash,
    ) -> Result<Vec<Block::Hash>, GrandpaError> {
        let mut route = Vec::new();
        let mut current_hash = block;
        loop {
            if current_hash == base {
                break;
            }
            match self.ancestry.get(&current_hash) {
                Some(current_header) => {
                    current_hash = *current_header.parent_hash();
                    route.push(current_hash);
                }
                _ => return Err(GrandpaError::NotDescendent),
            }
        }
        route.pop(); // remove the base

        Ok(route)
    }

    fn best_chain_containing(
        &self,
        _block: Block::Hash,
    ) -> Option<(Block::Hash, NumberFor<Block>)> {
        None
    }
}

// copied

/// A commit message for this chain's block type.
pub type Commit<Block> = finality_grandpa::Commit<
    <Block as BlockT>::Hash,
    NumberFor<Block>,
    AuthoritySignature,
    AuthorityId,
>;

mod communication {
    use crate::std::vec::Vec;
    use codec::Encode;
    use log::debug;
    use sp_core::Pair;
    use sp_finality_grandpa::{
        AuthorityId, AuthorityPair, AuthoritySignature, RoundNumber, SetId as SetIdNumber,
    };
    use sp_runtime::traits::{Block as BlockT, NumberFor};

    pub type Message<Block> = finality_grandpa::Message<<Block as BlockT>::Hash, NumberFor<Block>>;

    // Check the signature of a Grandpa message.
    // This was originally taken from `communication/mod.rs`

    /// Check a message signature by encoding the message as a localized payload and
    /// verifying the provided signature using the expected authority id.
    /// The encoding necessary to verify the signature will be done using the given
    /// buffer, the original content of the buffer will be cleared.
    pub(crate) fn check_message_sig_with_buffer<Block: BlockT>(
        message: &Message<Block>,
        id: &AuthorityId,
        signature: &AuthoritySignature,
        round: RoundNumber,
        set_id: SetIdNumber,
        buf: &mut Vec<u8>,
    ) -> Result<(), ()> {
        let as_public = id.clone();
        localized_payload_with_buffer(round, set_id, message, buf);

        if AuthorityPair::verify(signature, buf, &as_public) {
            Ok(())
        } else {
            debug!(target: "afg", "Bad signature on message from {:?}", id);
            Err(())
        }
    }

    /// Encode round message localized to a given round and set id using the given
    /// buffer. The given buffer will be cleared and the resulting encoded payload
    /// will always be written to the start of the buffer.
    pub(crate) fn localized_payload_with_buffer<E: Encode>(
        round: RoundNumber,
        set_id: SetIdNumber,
        message: &E,
        buf: &mut Vec<u8>,
    ) {
        buf.clear();
        (message, round, set_id).encode_to(buf)
    }
}
