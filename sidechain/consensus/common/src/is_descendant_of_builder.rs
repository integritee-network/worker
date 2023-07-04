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
use crate::header_db::HeaderDbTrait;
use core::{hash::Hash as HashT, marker::PhantomData};
use itp_types::H256;
use its_primitives::traits::Header as HeaderT;

pub struct IsDescendantOfBuilder<Hash, HeaderDb, Error>(PhantomData<(Hash, HeaderDb, Error)>);

impl<'a, Hash, HeaderDb, Error> IsDescendantOfBuilder<Hash, HeaderDb, Error>
where
	Error: From<()>,
	Hash: PartialEq + HashT + Default + Into<H256> + From<H256> + Clone,
	HeaderDb: HeaderDbTrait,
{
	/// Builds the `is_descendant_of` closure for the fork-tree
	/// used when adding and removing nodes from the tree.
	pub fn build_is_descendant_of(
		current: Option<(&'a Hash, &'a Hash)>,
		header_db: &'a HeaderDb,
	) -> impl Fn(&Hash, &Hash) -> Result<bool, Error> + 'a {
		move |base, head| {
			// If the base is equal to the proposed head, then the head is for sure not a descendant of the base.
			if base == head {
				return Ok(false)
			}

			let mut head = head;
			if let Some((current_hash, current_parent_hash)) = current {
				// If the current hash is equal to the base, then it will not be a descendant of base.
				if current_hash == base {
					return Ok(false)
				}

				// If the current hash is the head and the parent is the base, then we know that
				// this current hash is the descendant of the parent. Otherwise we can set the
				// head to the parent and find the lowest common ancestor between `head`
				// and `base` in the tree.
				if current_hash == head {
					if current_parent_hash == base {
						return Ok(true)
					} else {
						head = current_parent_hash;
					}
				}
			}

			let ancestor =
				<LowestCommonAncestorFinder<Hash, HeaderDb>>::find_lowest_common_ancestor(
					head, base, header_db,
				)?;
			Ok(ancestor == *base)
		}
	}
}

pub struct LowestCommonAncestorFinder<Hash, HeaderDb>(PhantomData<(Hash, HeaderDb)>);

impl<Hash, HeaderDb> LowestCommonAncestorFinder<Hash, HeaderDb>
where
	Hash: PartialEq + Default + Into<H256> + From<H256> + Clone,
	HeaderDb: HeaderDbTrait,
{
	/// Used by the `build_is_descendant_of` to find the LCA of two nodes in the fork-tree.
	fn find_lowest_common_ancestor(a: &Hash, b: &Hash, header_db: &HeaderDb) -> Result<Hash, ()> {
		let header_1 = header_db.header(&a.clone().into()).ok_or(())?;
		let header_2 = header_db.header(&b.clone().into()).ok_or(())?;
		let mut blocknum_1 = header_1.block_number();
		let mut blocknum_2 = header_2.block_number();
		let mut parent_1 = Hash::from(header_1.parent_hash());
		let mut parent_2 = Hash::from(header_2.parent_hash());

		if *a == parent_2 {
			// Then a is the common ancestor of b and it means it is itself the ancestor
			return Ok(parent_2)
		}

		if *b == parent_1 {
			// Then b is the common ancestor of a and it means it is itself the ancestor
			return Ok(parent_1)
		}

		while blocknum_1 > blocknum_2 {
			// This means block 1 is further down in the tree than block 2
			let new_parent = header_db.header(&parent_1.clone().into()).ok_or(())?;

			if new_parent.block_number() >= blocknum_2 {
				blocknum_1 = new_parent.block_number();
				parent_1 = Hash::from(new_parent.parent_hash());
			} else {
				break
			}
		}

		while blocknum_2 > blocknum_1 {
			// This means block 2 is further down in the tree than block 1
			let new_parent = header_db.header(&parent_2.clone().into()).ok_or(())?;

			if new_parent.block_number() >= blocknum_1 {
				blocknum_2 = new_parent.block_number();
				parent_2 = Hash::from(new_parent.parent_hash());
			} else {
				break
			}
		}

		// At this point will be at equal height
		while parent_1 != parent_2 {
			// go up on both nodes
			let new_header_1 = header_db.header(&parent_1.into()).ok_or(())?;
			let new_header_2 = header_db.header(&parent_2.into()).ok_or(())?;
			parent_1 = Hash::from(new_header_1.parent_hash());
			parent_2 = Hash::from(new_header_2.parent_hash());
		}

		// Return any Parent node Hash as in worst case scenario it is the root which is shared amongst all
		Ok(parent_1)
	}
}
