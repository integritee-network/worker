use std::marker::PhantomData;

#[allow(dead_code)]
pub struct IsDescendentOfBuilder<Hash>(PhantomData<Hash>);
impl<'a, Hash: PartialEq> IsDescendentOfBuilder<Hash> {
	#[allow(dead_code)]
    ///
    /// Build the `is_descendent_of` closure for the fork-tree structure
    /// to utilize when adding and removing nodes from the tree
    /// 
	pub fn build_is_descendent_of(
		_curr_block: Option<(&Hash, &Hash)>,
	) -> impl Fn(&Hash, &Hash) -> Result<bool, ()> + 'a {
		move |_base, _head| Ok(true)
	}
}

#[allow(dead_code)]
pub struct LowestCommonAncestorFinder<Hash>(PhantomData<Hash>);
impl<Hash: PartialEq + Default> LowestCommonAncestorFinder<Hash> {
	#[allow(dead_code)]
    ///
    /// Used by the `build_is_descendent_of` to find the LCA of two nodes in the fork-tree
    /// 
	pub fn find_lowest_common_ancestor(_a: Hash, _b: Hash) -> Hash {
		Default::default()
	}
}

#[test]
fn test_build_is_descendent_of_works() {
	let is_descendent_of = <IsDescendentOfBuilder<u64>>::build_is_descendent_of(None);
	let my_result = is_descendent_of(&42u64, &42u64);
	assert_eq!(my_result, Ok(true));
}
