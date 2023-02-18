use fork_tree::ForkTree;
use std::marker::PhantomData;

// TODO: Build Cache for Latest Blocks

// TODO: Pass in Block as Generic param?
struct IsDescendentOfBuilder<Hash>(PhantomData<Hash>);
impl<Hash: PartialEq> IsDescendentOfBuilder<Hash> {
    fn build_is_descendent_of(
        current: Option<(&Hash, &Hash)>
    ) -> impl Fn(&Hash, &Hash) -> Result<bool, ()> {
        move |base, head| {
            // TODO: Add body here
            // Need to make call to find_lowest_common_ancestor
            Ok(true)
        }
    }
}

struct LowestCommonAncestorFinder<Hash>(PhantomData<Hash>);
impl <Hash: PartialEq + Default> LowestCommonAncestorFinder<Hash> {
    fn find_lowest_common_ancestor(a: Hash, b: Hash) -> Hash {
        // TODO: Implement lowest common ancestor algorithm
        /* 
        ** Need to access blocks and their headers for BlockHash and BlockNumber perhaps a cache?
        ** (BlockHash -> BlockHeader)
        */ 
        Default::default()
    }
}

#[test]
fn test_build_is_descendent_of_works() {
    let is_descendent_of = <IsDescendentOfBuilder<u64>>::build_is_descendent_of(None);
    let my_result = is_descendent_of(&42u64, &42u64);
    assert_eq!(my_result, Ok(true));
}