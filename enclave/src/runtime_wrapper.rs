//! This file has been semi-manually derived from node-template
//!
//! go to your node-template ./runtime and run
//! `cargo expand --no-default-features > node-runtime-expanded.rs`
//!
//! then extract all definitions for
//! Runtime, Origin, Log, InternalLog
//! and put them here
//!
//! you might have to repeat this procedure for runtime updates

use my_node_runtime::{AccountId, Indices, Hash, Nonce, opaque, Block, BlockNumber, AuthorityId, AuthoritySignature, Event};
use runtime_primitives::generic;
use runtime_primitives::traits::BlakeTwo256;
use std::vec::Vec;


#[structural_match]
#[rustc_copy_clone_marker]
pub struct Runtime;
#[automatically_derived]
#[allow(unused_qualifications)]
impl ::core::clone::Clone for Runtime {
    #[inline]
    fn clone(&self) -> Runtime { { *self } }
}
#[automatically_derived]
#[allow(unused_qualifications)]
impl ::core::marker::Copy for Runtime { }
#[automatically_derived]
#[allow(unused_qualifications)]
impl ::core::cmp::PartialEq for Runtime {
    #[inline]
    fn eq(&self, other: &Runtime) -> bool {
        match *other { Runtime => match *self { Runtime => true, }, }
    }
}
#[automatically_derived]
#[allow(unused_qualifications)]
impl ::core::cmp::Eq for Runtime {
    #[inline]
    #[doc(hidden)]
    fn assert_receiver_is_total_eq(&self) -> () { { } }
}
impl ::srml_support::runtime_primitives::traits::GetNodeBlockType for Runtime
 {
    type
    NodeBlock
    =
    opaque::Block;
}
impl ::srml_support::runtime_primitives::traits::GetRuntimeBlockType for
 Runtime {
    type
    RuntimeBlock
    =
    Block;
}


#[allow(non_camel_case_types)]
#[structural_match]
pub enum Origin {
    system(system::Origin<Runtime>),

    #[allow(dead_code)]
    Void(::srml_support::Void),
}
#[automatically_derived]
#[allow(unused_qualifications)]
#[allow(non_camel_case_types)]
impl ::core::clone::Clone for Origin {
    #[inline]
    fn clone(&self) -> Origin {
        match (&*self,) {
            (&Origin::system(ref __self_0),) =>
            Origin::system(::core::clone::Clone::clone(&(*__self_0))),
            (&Origin::Void(ref __self_0),) =>
            Origin::Void(::core::clone::Clone::clone(&(*__self_0))),
        }
    }
}
#[automatically_derived]
#[allow(unused_qualifications)]
#[allow(non_camel_case_types)]
impl ::core::cmp::PartialEq for Origin {
    #[inline]
    fn eq(&self, other: &Origin) -> bool {
        {
            let __self_vi =
                unsafe { ::core::intrinsics::discriminant_value(&*self) } as
                    isize;
            let __arg_1_vi =
                unsafe { ::core::intrinsics::discriminant_value(&*other) } as
                    isize;
            if true && __self_vi == __arg_1_vi {
                match (&*self, &*other) {
                    (&Origin::system(ref __self_0),
                     &Origin::system(ref __arg_1_0)) =>
                    (*__self_0) == (*__arg_1_0),
                    (&Origin::Void(ref __self_0),
                     &Origin::Void(ref __arg_1_0)) =>
                    (*__self_0) == (*__arg_1_0),
                    _ => unsafe { ::core::intrinsics::unreachable() }
                }
            } else { false }
        }
    }
    #[inline]
    fn ne(&self, other: &Origin) -> bool {
        {
            let __self_vi =
                unsafe { ::core::intrinsics::discriminant_value(&*self) } as
                    isize;
            let __arg_1_vi =
                unsafe { ::core::intrinsics::discriminant_value(&*other) } as
                    isize;
            if true && __self_vi == __arg_1_vi {
                match (&*self, &*other) {
                    (&Origin::system(ref __self_0),
                     &Origin::system(ref __arg_1_0)) =>
                    (*__self_0) != (*__arg_1_0),
                    (&Origin::Void(ref __self_0),
                     &Origin::Void(ref __arg_1_0)) =>
                    (*__self_0) != (*__arg_1_0),
                    _ => unsafe { ::core::intrinsics::unreachable() }
                }
            } else { true }
        }
    }
}
#[automatically_derived]
#[allow(unused_qualifications)]
#[allow(non_camel_case_types)]
impl ::core::cmp::Eq for Origin {
    #[inline]
    #[doc(hidden)]
    fn assert_receiver_is_total_eq(&self) -> () {
        {
            let _: ::core::cmp::AssertParamIsEq<system::Origin<Runtime>>;
            let _: ::core::cmp::AssertParamIsEq<::srml_support::Void>;
        }
    }
}
#[allow(dead_code)]
impl Origin {
    pub const
    INHERENT:
    Self
    =
    Origin::system(system::RawOrigin::Inherent);
    pub const
    ROOT:
    Self
    =
    Origin::system(system::RawOrigin::Root);
    pub fn signed(by: <Runtime as system::Trait>::AccountId) -> Self {
        Origin::system(system::RawOrigin::Signed(by))
    }
}
impl From<system::Origin<Runtime>> for Origin {
    fn from(x: system::Origin<Runtime>) -> Self { Origin::system(x) }
}
impl Into<Option<system::Origin<Runtime>>> for Origin {
    fn into(self) -> Option<system::Origin<Runtime>> {
        if let Origin::system(l) = self { Some(l) } else { None }
    }
}
impl From<Option<<Runtime as system::Trait>::AccountId>> for Origin {
    fn from(x: Option<<Runtime as system::Trait>::AccountId>) -> Self {
        <system::Origin<Runtime>>::from(x).into()
    }
}

/// Wrapper for all possible log entries for the `$trait` runtime. Provides binary-compatible
/// `Encode`/`Decode` implementations with the corresponding `generic::DigestItem`.
#[allow(non_camel_case_types)]
#[structural_match]
pub struct Log(InternalLog);
#[automatically_derived]
#[allow(unused_qualifications)]
#[allow(non_camel_case_types)]
impl ::core::clone::Clone for Log {
    #[inline]
    fn clone(&self) -> Log {
        match *self {
            Log(ref __self_0_0) =>
            Log(::core::clone::Clone::clone(&(*__self_0_0))),
        }
    }
}
#[automatically_derived]
#[allow(unused_qualifications)]
#[allow(non_camel_case_types)]
impl ::core::cmp::PartialEq for Log {
    #[inline]
    fn eq(&self, other: &Log) -> bool {
        match *other {
            Log(ref __self_1_0) =>
            match *self {
                Log(ref __self_0_0) => (*__self_0_0) == (*__self_1_0),
            },
        }
    }
    #[inline]
    fn ne(&self, other: &Log) -> bool {
        match *other {
            Log(ref __self_1_0) =>
            match *self {
                Log(ref __self_0_0) => (*__self_0_0) != (*__self_1_0),
            },
        }
    }
}
#[automatically_derived]
#[allow(unused_qualifications)]
#[allow(non_camel_case_types)]
impl ::core::cmp::Eq for Log {
    #[inline]
    #[doc(hidden)]
    fn assert_receiver_is_total_eq(&self) -> () {
        { let _: ::core::cmp::AssertParamIsEq<InternalLog>; }
    }
}
/// All possible log entries for the `$trait` runtime. `Encode`/`Decode` implementations
/// are auto-generated => it is not binary-compatible with `generic::DigestItem`.
#[allow(non_camel_case_types)]
#[structural_match]
pub enum InternalLog {
    system(system::Log<Runtime>),
    //consensus(consensus::Log<Runtime>),
}
#[automatically_derived]
#[allow(unused_qualifications)]
#[allow(non_camel_case_types)]
impl ::core::clone::Clone for InternalLog {
    #[inline]
    fn clone(&self) -> InternalLog {
        match (&*self,) {
            (&InternalLog::system(ref __self_0),) =>
            InternalLog::system(::core::clone::Clone::clone(&(*__self_0))),
        }
    }
}
#[automatically_derived]
#[allow(unused_qualifications)]
#[allow(non_camel_case_types)]
impl ::core::cmp::PartialEq for InternalLog {
    #[inline]
    fn eq(&self, other: &InternalLog) -> bool {
        {
            let __self_vi =
                unsafe { ::core::intrinsics::discriminant_value(&*self) } as
                    isize;
            let __arg_1_vi =
                unsafe { ::core::intrinsics::discriminant_value(&*other) } as
                    isize;
            if true && __self_vi == __arg_1_vi {
                match (&*self, &*other) {
                    (&InternalLog::system(ref __self_0),
                     &InternalLog::system(ref __arg_1_0)) =>
                    (*__self_0) == (*__arg_1_0),
                    _ => unsafe { ::core::intrinsics::unreachable() }
                }
            } else { false }
        }
    }
    #[inline]
    fn ne(&self, other: &InternalLog) -> bool {
        {
            let __self_vi =
                unsafe { ::core::intrinsics::discriminant_value(&*self) } as
                    isize;
            let __arg_1_vi =
                unsafe { ::core::intrinsics::discriminant_value(&*other) } as
                    isize;
            if true && __self_vi == __arg_1_vi {
                match (&*self, &*other) {
                    (&InternalLog::system(ref __self_0),
                     &InternalLog::system(ref __arg_1_0)) =>
                    (*__self_0) != (*__arg_1_0),
                    _ => unsafe { ::core::intrinsics::unreachable() }
                }
            } else { true }
        }
    }
}
#[automatically_derived]
#[allow(unused_qualifications)]
#[allow(non_camel_case_types)]
impl ::core::cmp::Eq for InternalLog {
    #[inline]
    #[doc(hidden)]
    fn assert_receiver_is_total_eq(&self) -> () {
        {
            let _: ::core::cmp::AssertParamIsEq<system::Log<Runtime>>;
        }
    }
}
#[allow(non_upper_case_globals, unused_attributes, unused_qualifications)]
const _IMPL_ENCODE_FOR_InternalLog: () =
    {
        #[allow(unknown_lints)]
        #[allow(rust_2018_idioms)]
        extern crate parity_codec as _parity_codec;
        impl _parity_codec::Encode for InternalLog {
            fn encode_to<EncOut: _parity_codec::Output>(&self,
                                                        dest: &mut EncOut) {
                match *self {
                    InternalLog::system(ref aa) => {
                        dest.push_byte(0usize as u8);
                        dest.push(aa);
                    }
                    _ => (),
                }
            }
        }
    };
#[allow(non_upper_case_globals, unused_attributes, unused_qualifications)]
const _IMPL_DECODE_FOR_InternalLog: () =
    {
        #[allow(unknown_lints)]
        #[allow(rust_2018_idioms)]
        extern crate parity_codec as _parity_codec;
        impl _parity_codec::Decode for InternalLog {
            fn decode<DecIn: _parity_codec::Input>(input: &mut DecIn)
             -> Option<Self> {
                match input.read_byte()? {
                    x if x == 0usize as u8 => {
                        Some(InternalLog::system(_parity_codec::Decode::decode(input)?))
                    }
                    _ => None,
                }
            }
        }
    };
impl Log {
    /// Try to convert `$name` into `generic::DigestItemRef`. Returns Some when
    /// `self` is a 'system' log && it has been marked as 'system' in macro call.
    /// Otherwise, None is returned.
    #[allow(unreachable_patterns)]
    fn dref<'a>(&'a self)
     ->
         Option<::runtime_primitives::generic::DigestItemRef<'a, Hash, AuthorityId,
                                                        AuthoritySignature>> {
        match self.0 {
            InternalLog::system(system::RawLog::ChangesTrieRoot(ref v)) =>
            Some(::runtime_primitives::generic::DigestItemRef::ChangesTrieRoot(v)),
            _ => None,
        }
    }
}
impl ::runtime_primitives::traits::DigestItem for Log {
    type
    Hash
    =
    <::runtime_primitives::generic::DigestItem<Hash, AuthorityId,
                                          AuthoritySignature> as
    ::runtime_primitives::traits::DigestItem>::Hash;
    type
    AuthorityId
    =
    <::runtime_primitives::generic::DigestItem<Hash, AuthorityId,
                                          AuthoritySignature> as
    ::runtime_primitives::traits::DigestItem>::AuthorityId;
    fn as_authorities_change(&self) -> Option<&[Self::AuthorityId]> {
        self.dref().and_then(|dref| dref.as_authorities_change())
    }
    fn as_changes_trie_root(&self) -> Option<&Self::Hash> {
        self.dref().and_then(|dref| dref.as_changes_trie_root())
    }
}
impl From<::runtime_primitives::generic::DigestItem<Hash, AuthorityId,
                                               AuthoritySignature>> for Log {
    /// Converts `generic::DigestItem` into `$name`. If `generic::DigestItem` represents
    /// a system item which is supported by the runtime, it is returned.
    /// Otherwise we expect a `Other` log item. Trying to convert from anything other
    /// will lead to panic in runtime, since the runtime does not supports this 'system'
    /// log item.
    #[allow(unreachable_patterns)]
    fn from(gen:
                ::runtime_primitives::generic::DigestItem<Hash, AuthorityId,
                                                     AuthoritySignature>)
     -> Self {
        match gen {
            ::runtime_primitives::generic::DigestItem::ChangesTrieRoot(value) =>
            Log(InternalLog::system(system::RawLog::ChangesTrieRoot(value))),
            _ =>
            gen.as_other().and_then(|value|
                                        ::runtime_primitives::codec::Decode::decode(&mut &value[..])).map(Log).expect("not allowed to fail in runtime"),
        }
    }
}
impl ::runtime_primitives::codec::Decode for Log {
    /// `generic::DigestItem` binary compatible decode.
    fn decode<I: ::runtime_primitives::codec::Input>(input: &mut I)
     -> Option<Self> {
        let gen:
                ::runtime_primitives::generic::DigestItem<Hash, AuthorityId,
                                                     AuthoritySignature> =
            ::runtime_primitives::codec::Decode::decode(input)?;
        Some(Log::from(gen))
    }
}
impl ::runtime_primitives::codec::Encode for Log {
    /// `generic::DigestItem` binary compatible encode.
    fn encode(&self) -> Vec<u8> {
        match self.dref() {
            Some(dref) => dref.encode(),
            None => {
                let gen:
                        ::runtime_primitives::generic::DigestItem<Hash,
                                                             AuthorityId,
                                                             AuthoritySignature> =
                    ::runtime_primitives::generic::DigestItem::Other(self.0.encode());
                gen.encode()
            }
        }
    }
}
impl From<system::Log<Runtime>> for Log {
    /// Converts single module log item into `$name`.
    fn from(x: system::Log<Runtime>) -> Self { Log(x.into()) }
}
impl From<system::Log<Runtime>> for InternalLog {
    /// Converts single module log item into `$internal`.
    fn from(x: system::Log<Runtime>) -> Self { InternalLog::system(x) }
}






impl system::Trait for Runtime {
	/// The identifier used to distinguish between accounts.
	type AccountId = AccountId;
	/// The lookup mechanism to get account ID from whatever is passed in dispatchers.
	type Lookup = Indices;
	/// The index type for storing how many extrinsics an account has signed.
	type Index = Nonce;
	/// The index type for blocks.
	type BlockNumber = BlockNumber;
	/// The type for hashing blocks and tries
	type Hash = Hash;
	/// The hashing algorithm used.
	type Hashing = BlakeTwo256;
	/// The header digest type.
	type Digest = generic::Digest<Log>;
	/// The header type.
	type Header = generic::Header<BlockNumber, BlakeTwo256, Log>;
	/// The ubiquitous event type.
	type Event = Event;
	/// The ubiquitous log type.
	type Log = Log;
	/// The ubiquitous origin type.
	type Origin = Origin;
}
/*
// TODO: get rid of Aura here
pub type Aura = aura::Module<Runtime>;

impl aura::Trait for Runtime {
	type HandleReport = ();
}
*/
impl timestamp::Trait for Runtime {}
/*
	/// A timestamp: seconds since the unix epoch.
	type Moment = u64;
	//type OnTimestampSet = Aura;
	type OnTimestampSet = ();
}
*/

impl contract::Trait for Runtime {

}
