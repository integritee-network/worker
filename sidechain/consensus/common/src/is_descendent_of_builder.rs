use fork_tree::ForkTree;
use std::marker::PhantomData;

struct IsDescendentOfBuilder<Hash>(PhantomData<Hash>);
impl<'a, Hash: PartialEq> IsDescendentOfBuilder<Hash> {
    fn build_is_descendent_of(
        curr_block: Option<(&Hash, &Hash)>
    ) -> impl Fn(&Hash, &Hash) -> Result<bool, ()> + 'a {
        move |base, head| {
            Ok(true)
        }
    }
}

struct LowestCommonAncestorFinder<Hash>(PhantomData<Hash>);
impl <Hash: PartialEq + Default> LowestCommonAncestorFinder<Hash> {
    fn find_lowest_common_ancestor(a: Hash, b: Hash) -> Hash {
        Default::default()
    }
}

#[test]
fn test_build_is_descendent_of_works() {
    let is_descendent_of = <IsDescendentOfBuilder<u64>>::build_is_descendent_of(None);
    let my_result = is_descendent_of(&42u64, &42u64);
    assert_eq!(my_result, Ok(true));
}
