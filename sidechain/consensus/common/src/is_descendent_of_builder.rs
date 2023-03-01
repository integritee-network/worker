use fork_tree::ForkTree;
use std::marker::PhantomData;


// TODO: Pass in Block as Generic param?
struct IsDescendentOfBuilder<Hash>(PhantomData<Hash>);
impl<'a, Hash: PartialEq> IsDescendentOfBuilder<Hash> {
    fn is_descendent_of(
        curr_block: Option<(&Hash, &Hash)>
    ) -> impl Fn(&Hash, &Hash) -> Result<bool, ()> + 'a {
        move |base, head| {
            // TODO: Add body here
            // Need to make call to find_lowest_common_ancestor
            Ok(true)
        }
    }
}

struct LowestCommonAncestorFinder<'a, Hash>(PhantomData<(&'a (), Hash)>);
impl <'a, Hash: PartialEq + Default> LowestCommonAncestorFinder<'a, Hash> {
    fn find_lowest_common_ancestor(a: Hash, b: Hash) -> &'a Hash {
        // TODO: Implement lowest common ancestor algorithm
        /* 
        ** Need to access blocks and their headers for BlockHash and BlockNumber perhaps a cache?
        ** (BlockHash -> BlockHeader)
        */ 
        Default::default()
    }
}
