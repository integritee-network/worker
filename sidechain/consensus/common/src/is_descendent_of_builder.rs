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

// TODO: Build Cache for Latest Blocks

// Normally implemented on the Client in substrate I believe?
pub trait HeaderDbTrait {
    type Header;
    /// Retrieves Header for the corresponding block hash
    // fn header(&self, hash: H256) -> Option<Block::HeaderType>;
    fn header(&self, hash: &H256) -> Option<Self::Header>;
}

pub struct HeaderDb<Hash, Header>(HashMap<Hash, Header>);
impl<Hash: PartialEq + HashT + Into<H256> + From<H256> + std::cmp::Eq + Clone, Header> HeaderDbTrait for HeaderDb<Hash, Header>
where
    Header: HeaderT + Clone + Into<SidechainHeader>
{
    type Header = SidechainHeader;
    fn header(&self, hash: &H256) -> Option<Self::Header> {
        let header = self.0.get(&Hash::from(*hash))?;
        Some(header.clone().into())
    }
}
impl<Hash: PartialEq + Eq + HashT + Clone, Header: Clone> HeaderDb<Hash, Header> {
    pub fn new() -> Self {
        Self {
            0: HashMap::new(),
        }
    }
}

// TODO: Pass in Block as Generic param?
struct IsDescendentOfBuilder<Hash, HeaderDb>(PhantomData<(Hash, HeaderDb)>);
impl<'a, Hash: PartialEq + HashT + Default + Into<H256> + From<H256> + Clone, HeaderDb: HeaderDbTrait> IsDescendentOfBuilder<Hash, HeaderDb> {
    fn build_is_descendent_of(
        current: Option<(&'a Hash, &'a Hash)>,
        header_db: &'a HeaderDb,
    ) -> impl Fn(&Hash, &Hash) -> Result<bool, ()> + 'a {
        move |base, head| {
            // TODO: Add body here
            if base == head {
                return Ok(false)
            }

            // let current = current.as_ref().map(|(c, p)| (c.borrow(), p.borrow()));

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

struct LowestCommonAncestorFinder<Hash, HeaderDb>(PhantomData<(Hash, HeaderDb)>);
impl <Hash: PartialEq + Default + Into<H256> + From<H256> + Clone, HeaderDb: HeaderDbTrait> LowestCommonAncestorFinder<Hash, HeaderDb> {
    fn find_lowest_common_ancestor(a: &Hash, b: &Hash, header_db: &HeaderDb) -> Result<Hash, ()> {
        let header_1 = header_db.header(&<Hash as Into<H256>>::into(a.clone())).ok_or(())?;
        // TODO: Implement lowest common ancestor algorithm
        /* 
        ** Need to access blocks and their headers for BlockHash and BlockNumber perhaps a cache?
        ** (BlockHash -> BlockHeader)
        */ 
        Ok(Default::default())
    }
}

#[test]
fn test_build_is_descendent_of_works() {
    let db = <HeaderDb<H256, SidechainHeader>>::new();
    let is_descendent_of = <IsDescendentOfBuilder<H256, HeaderDb<H256, SidechainHeader>>>::build_is_descendent_of(None, &db);
    let my_result = is_descendent_of(&[1; 32].into(), &[0; 32].into());
    // TODO: Add something there Nothing in DB yet
    assert_eq!(my_result, Err(()));
}
