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

use std::{
	collections::{HashMap, HashSet},
	string::ToString,
	vec::Vec,
};

use super::error::JustificationError as ClientError;
use codec::{Decode, Encode};
use finality_grandpa::{voter_set::VoterSet, Error as GrandpaError};
use log::*;
use sp_finality_grandpa::{AuthorityId, AuthorityList, AuthoritySignature};
use sp_runtime::traits::{Block as BlockT, Header as HeaderT, NumberFor};

/// A commit message for this chain's block type.
pub type Commit<Block> = finality_grandpa::Commit<
	<Block as BlockT>::Hash,
	NumberFor<Block>,
	AuthoritySignature,
	AuthorityId,
>;

/// A GRANDPA justification for block finality, it includes a commit message and
/// an ancestry proof including all headers routing all precommit target blocks
/// to the commit target block. Due to the current voting strategy the precommit
/// targets should be the same as the commit target, since honest voters don't
/// vote past authority set change blocks.
///
/// This is meant to be stored in the db and passed around the network to other
/// nodes, and are used by syncing nodes to prove authority set handoffs.
#[derive(Clone, Encode, Decode, PartialEq, Eq)]
pub struct GrandpaJustification<Block: BlockT> {
	round: u64,
	pub(crate) commit: Commit<Block>,
	votes_ancestries: Vec<Block::Header>,
}

impl<Block: BlockT> GrandpaJustification<Block> {
	/// Decode a GRANDPA justification and validate the commit and the votes'
	/// ancestry proofs finalize the given block.
	pub fn decode_and_verify_finalizes(
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

		let justificated_commit =
			(justification.commit.target_hash, justification.commit.target_number);

		if justificated_commit != finalized_target {
			Err(ClientError::BadJustification(
				"invalid commit target in grandpa justification".to_string(),
			))
		} else {
			justification.verify_with_voter_set(set_id, voters).map(|_| justification)
		}
	}

	/// Validate the commit and the votes' ancestry proofs.
	pub fn verify(&self, set_id: u64, authorities: AuthorityList) -> Result<(), ClientError>
	where
		NumberFor<Block>: finality_grandpa::BlockNumberOps,
	{
		let voters =
			VoterSet::new(authorities.into_iter()).ok_or(ClientError::InvalidAuthoritiesSet)?;

		self.verify_with_voter_set(set_id, &voters)
	}

	fn validate_commit(
		&self,
		voters: &VoterSet<AuthorityId>,
		ancestry_chain: &AncestryChain<Block>,
	) -> Result<(), ClientError>
	where
		NumberFor<Block>: finality_grandpa::BlockNumberOps,
	{
		match finality_grandpa::validate_commit(&self.commit, voters, ancestry_chain) {
			Ok(ref result) if result.is_valid() => Ok(()),
			_ => Err(ClientError::BadJustification(
				"invalid commit in grandpa justification".to_string(),
			)),
		}
	}

	fn fill_visited_hashes(
		&self,
		ancestry_chain: &AncestryChain<Block>,
		precommit_target_hash: Block::Hash,
		visited_hashes: &mut HashSet<Block::Hash>,
	) -> Result<(), ClientError>
	where
		NumberFor<Block>: finality_grandpa::BlockNumberOps,
	{
		use finality_grandpa::Chain;
		if let Ok(route) = ancestry_chain.ancestry(self.commit.target_hash, precommit_target_hash) {
			// ancestry starts from parent hash but the precommit target hash has been visited
			visited_hashes.insert(precommit_target_hash);
			visited_hashes.extend(route.iter());
			Ok(())
		} else {
			Err(ClientError::BadJustification(
				"invalid precommit ancestry proof in grandpa justification".to_string(),
			))
		}
	}

	/// Validate the commit and the votes' ancestry proofs.
	pub(crate) fn verify_with_voter_set(
		&self,
		set_id: u64,
		voters: &VoterSet<AuthorityId>,
	) -> Result<(), ClientError>
	where
		NumberFor<Block>: finality_grandpa::BlockNumberOps,
	{
		let ancestry_chain = AncestryChain::<Block>::new(&self.votes_ancestries);

		self.validate_commit(voters, &ancestry_chain)?;

		let mut buf = Vec::new();
		let mut visited_hashes = HashSet::new();
		for signed in self.commit.precommits.iter() {
			if !sp_finality_grandpa::check_message_signature_with_buffer(
				&finality_grandpa::Message::Precommit(signed.precommit.clone()),
				&signed.id,
				&signed.signature,
				self.round,
				set_id,
				&mut buf,
			) {
				debug!("Bad signature on message from {:?}", &signed.id);
				return Err(ClientError::BadJustification(
					"invalid signature for precommit in grandpa justification".to_string(),
				))
			}

			if self.commit.target_hash == signed.precommit.target_hash {
				continue
			}

			self.fill_visited_hashes(
				&ancestry_chain,
				signed.precommit.target_hash,
				&mut visited_hashes,
			)?;
		}

		let ancestry_hashes =
			self.votes_ancestries.iter().map(|h: &Block::Header| h.hash()).collect();

		if visited_hashes != ancestry_hashes {
			return Err(ClientError::BadJustification(
				"invalid precommit ancestries in grandpa justification with unused headers"
					.to_string(),
			))
		}

		Ok(())
	}

	/// The target block number and hash that this justifications proves finality for.
	pub fn target(&self) -> (NumberFor<Block>, Block::Hash) {
		(self.commit.target_number, self.commit.target_hash)
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
		let ancestry: HashMap<_, _> =
			ancestry.iter().cloned().map(|h: Block::Header| (h.hash(), h)).collect();

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
		let mut ancestors = Vec::new();
		let mut current_hash = block;
		while current_hash != base {
			if let Some(current_header) = self.ancestry.get(&current_hash) {
				current_hash = *current_header.parent_hash();
				ancestors.push(current_hash);
			} else {
				return Err(GrandpaError::NotDescendent)
			}
		}
		ancestors.pop(); // remove the base

		Ok(ancestors)
	}
}
