use fork_tree::ForkTree;
use std::marker::PhantomData;
use its_primitives::{
	traits::{Block as BlockT, Header as HeaderT},
	types::{block_data::BlockData, header::SidechainHeader as Header, Block, SignedBlock}
};
use itp_types::H256;
use std::collections::HashMap;
use its_primitives::types::header::SidechainHeader;
use std::hash::Hash as HashT;
use std::borrow::Borrow;

// TODO: Build Cache for Latest Blocks?

// TODO: Remove all unecessary cloning/refactor to be more efficient

// TODO: Check Normally implemented on the Client in substrate I believe?
// TODO: Do we need all of these trait bounds?
pub trait HeaderDbTrait {
    type Header: HeaderT;
    /// Retrieves Header for the corresponding block hash
    fn header(&self, hash: &H256) -> Option<Self::Header>;
}

// TODO: Do we need all of these trait bounds?
pub struct HeaderDb<Hash, Header>(pub HashMap<Hash, Header>);
impl<Hash, Header> HeaderDb<Hash, Header> 
where
    Hash: PartialEq + Eq + HashT + Clone,
    Header: Clone
{
    pub fn new() -> Self {
        Self(HashMap::new())
    }

    pub fn insert(&mut self, hash: Hash, header: Header) {
        let _ = self.0.insert(hash, header);
    }
}

impl<Hash, Header> From<&[(Hash, Header)]> for HeaderDb<Hash, Header>
where
    Hash: HashT + Eq + Copy + Clone,
    Header: Copy + Clone,
{
    fn from(items: &[(Hash, Header)]) -> Self {
        let mut header_db = HeaderDb::<Hash, Header>::new();
        for item in items {
            let (hash, header) = item;
            header_db.insert(*hash, *header);
        }
        header_db
    }
}

// TODO: Do we need all of these trait bounds?
impl<Hash, Header> HeaderDbTrait for HeaderDb<Hash, Header>
where
    Hash: PartialEq + HashT + Into<H256> + From<H256> + std::cmp::Eq + Clone,
    Header: HeaderT + Clone + Into<SidechainHeader>
{
    type Header = SidechainHeader;

    fn header(&self, hash: &H256) -> Option<Self::Header> {
        let header = self.0.get(&Hash::from(*hash))?;
        Some(header.clone().into())
    }
}
#[derive(Debug)]
pub enum TestError {
	Error,
}

impl From<()> for TestError {
    fn from(a: ()) -> Self {
        TestError::Error
    }
}

impl std::fmt::Display for TestError {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "TestError")
    }
}

impl std::error::Error for TestError { }

// TODO: Do we need all of these trait bounds?
pub struct IsDescendentOfBuilder<Hash, HeaderDb, Error>(PhantomData<(Hash, HeaderDb, Error)>);
impl<'a, Hash, HeaderDb, Error> IsDescendentOfBuilder<Hash, HeaderDb, Error>
where
    Error: From<()>,
    Hash: PartialEq + HashT + Default + Into<H256> + From<H256> + Clone,
    HeaderDb: HeaderDbTrait
{
    pub fn build_is_descendent_of(
        current: Option<(&'a Hash, &'a Hash)>,
        header_db: &'a HeaderDb,
    ) -> impl Fn(&Hash, &Hash) -> Result<bool, Error> + 'a {
        move |base, head| {
            if base == head {
                return Ok(false)
            }

            let mut head = head;
            if let Some((current_hash, current_parent_hash)) = current {
                if current_hash == base {
                    return Ok(false)
                }

                if current_hash == head {
                    if current_parent_hash == base {
                        return Ok(true)
                    }
                    else {
                        head = current_parent_hash;
                    }
                }
            }

            let ancestor = 
                <LowestCommonAncestorFinder<Hash, HeaderDb>>::find_lowest_common_ancestor(head, base, header_db)?;
            Ok(ancestor == *base)
        }
    }
}

// TODO: Do we need all of these trait bounds?
pub struct LowestCommonAncestorFinder<Hash, HeaderDb>(PhantomData<(Hash, HeaderDb)>);
impl<Hash, HeaderDb> LowestCommonAncestorFinder<Hash, HeaderDb>
where
    Hash: PartialEq + Default + Into<H256> + From<H256> + Clone,
    HeaderDb: HeaderDbTrait,
{
    fn find_lowest_common_ancestor(a: &Hash, b: &Hash, header_db: &HeaderDb) -> Result<Hash, ()> {
        let mut header_1 = header_db.header(&a.clone().into()).ok_or(())?;
        let mut header_2 = header_db.header(&b.clone().into()).ok_or(())?;
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

        while blocknum_1 > blocknum_2 { // This means block 1 is further down in the tree than block 2
            let new_parent = header_db.header(&parent_1.clone().into()).ok_or(())?;
            // TODO: Research it is possible for a parent node to have a smaller block number?
            if new_parent.block_number() >= blocknum_2 {
                // go up to parent node
                blocknum_2 = new_parent.block_number();
                parent_1 = Hash::from(new_parent.parent_hash());    
            } else {
                break;
            }
        }

        while blocknum_2 > blocknum_1 { // This means block 2 is further down in the tree than block 1
            let new_parent = header_db.header(&parent_2.clone().into()).ok_or(())?;
            // TODO: Research it is possible for a parent node to have a smaller block number?
            if new_parent.block_number() >= blocknum_1 {
                blocknum_2 = new_parent.block_number();
                parent_2 = Hash::from(new_parent.parent_hash());    
            } else {
                break;
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
