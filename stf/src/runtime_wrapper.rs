/*
   Copyright 2019 Supercomputing Systems AG
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

//! This file has been semi-manually derived from node-template
//!
//! go to your node-template ./runtime and run
//! `cargo expand --no-default-features > node-runtime-expanded.rs`
//!
//! then extract all definitions for
//! Runtime, Log, InternalLog
//! and put them here
//!
//! you might have to repeat this procedure for runtime updates

//use node_runtime::{Balances, AccountId, Indices, Hash, Nonce, opaque, Block, BlockNumber, AuthorityId, AuthoritySignature, Event, Call, Origin};
use runtime_primitives::{
    generic,
    traits::{BlakeTwo256, ConvertInto, Block as BlockT},
    Permill, Perbill,
    weights::Weight
};
use version::RuntimeVersion;

pub use runtime_primitives::OpaqueExtrinsic as UncheckedExtrinsic;

use crate::{Signature, AuthorityId, AccountId, Hash};
pub type Call = [u8; 2];
pub type Index = u32;
pub type BlockNumber = u32;
pub type Balance = u128;
pub type Header = generic::Header<BlockNumber, BlakeTwo256>;
pub type Block = generic::Block<Header, UncheckedExtrinsic>;

use support::traits::Currency;
use std::vec::Vec;

/*
pub trait Trait: system::Trait {
    /// The overarching event type.
    //type Event: From<Event<Self>> + Into<<Self as system::Trait>::Event>;
}
*/

pub type System = system::Module<Runtime>;
pub type Timestamp = timestamp::Module<Runtime>;
pub type Indices = indices::Module<Runtime>;
pub type Balances = balances::Module<Runtime>;

pub use balances::Call as balancesCall;


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
impl ::support::sr_primitives::traits::GetNodeBlockType for Runtime
 {
    type NodeBlock = Block; //dummy
}
impl ::support::sr_primitives::traits::GetRuntimeBlockType for
 Runtime {
    type RuntimeBlock = Block;
}

impl balances::Trait for Runtime {
	/// The type for recording an account's balance.
	type Balance = Balance;
	/// What to do if an account's free balance gets zeroed.
	type OnFreeBalanceZero = ();
	/// What to do if a new account is created.
	type OnNewAccount = Indices;
	/// The ubiquitous event type.
	type Event = Event;
	type DustRemoval = ();
	type TransferPayment = ();
	type ExistentialDeposit = ExistentialDeposit;
	type TransferFee = TransferFee;
	type CreationFee = CreationFee;
}


impl system::Trait for Runtime {
	/// The identifier used to distinguish between accounts.
	type AccountId = AccountId;
	/// The aggregated dispatch type that is available for extrinsics.
	type Call = Call;
	/// The lookup mechanism to get account ID from whatever is passed in dispatchers.
	type Lookup = Indices;
	/// The index type for storing how many extrinsics an account has signed.
	type Index = Index;
	/// The index type for blocks.
	type BlockNumber = BlockNumber;
	/// The type for hashing blocks and tries.
	type Hash = Hash;
	/// The hashing algorithm used.
	type Hashing = BlakeTwo256;
	/// The header type.
	type Header = generic::Header<BlockNumber, BlakeTwo256>;
	/// The ubiquitous event type.
	type Event = Event;
	/// The ubiquitous origin type.
	type Origin = Origin;
	/// Maximum number of block number to block hash mappings to keep (oldest pruned first).
	type BlockHashCount = BlockHashCount;
	/// Maximum weight of each block.
	type MaximumBlockWeight = MaximumBlockWeight;
	/// Maximum size of all encoded transactions (in bytes) that are allowed in one block.
	type MaximumBlockLength = MaximumBlockLength;
	/// Portion of the block weight that is available to all normal transactions.
	type AvailableBlockRatio = AvailableBlockRatio;
	/// Version of the runtime.
	type Version = Version;
}

impl timestamp::Trait for Runtime {
	/// A timestamp: seconds since the unix epoch.
	type Moment = u64;
	type OnTimestampSet = ();
    type MinimumPeriod = MinimumPeriod;
}

impl indices::Trait for Runtime {
    /// The type for recording indexing into the account enumeration. If this ever overflows, there
    /// will be problems!
    type AccountIndex = u32;
    /// Use the standard means of resolving an index hint from an id.
    type ResolveHint = indices::SimpleResolveHint<Self::AccountId, Self::AccountIndex>;
    /// Determine whether an account is dead.
    type IsDeadAccount = Balances;
    /// The uniquitous event type.
    type Event = Event;
}

#[allow(non_camel_case_types)]
#[structural_match]
pub enum Origin {
    system(system::Origin<Runtime>),
    #[allow(dead_code)]
    Void(::support::Void),
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
            let _: ::core::cmp::AssertParamIsEq<::support::Void>;
        }
    }
}
#[allow(dead_code)]
impl Origin {
    pub const NONE: Self = Origin::system(system::RawOrigin::None);
    pub const ROOT: Self = Origin::system(system::RawOrigin::Root);
    pub fn signed(by: <Runtime as system::Trait>::AccountId) -> Self {
        Origin::system(system::RawOrigin::Signed(by))
    }
}
impl From<system::Origin<Runtime>> for Origin {
    fn from(x: system::Origin<Runtime>) -> Self { Origin::system(x) }
}
impl Into<::support::rstd::result::Result<system::Origin<Runtime>,
                                               Origin>> for Origin {
    fn into(self)
     -> ::support::rstd::result::Result<system::Origin<Runtime>, Self> {
        if let Origin::system(l) = self { Ok(l) } else { Err(self) }
    }
}
impl From<Option<<Runtime as system::Trait>::AccountId>> for Origin {
    fn from(x: Option<<Runtime as system::Trait>::AccountId>) -> Self {
        <system::Origin<Runtime>>::from(x).into()
    }
}

pub struct ExistentialDeposit;
impl ExistentialDeposit {
    pub fn get() -> u128 { 500 }
}
impl <I: From<u128>> ::support::traits::Get<I> for ExistentialDeposit {
    fn get() -> I { I::from(500) }
}
pub struct TransferFee;
impl TransferFee {
    pub fn get() -> u128 { 0 }
}
impl <I: From<u128>> ::support::traits::Get<I> for TransferFee {
    fn get() -> I { I::from(0) }
}
pub struct CreationFee;
impl CreationFee {
    pub fn get() -> u128 { 0 }
}
impl <I: From<u128>> ::support::traits::Get<I> for CreationFee {
    fn get() -> I { I::from(0) }
}
pub struct TransactionBaseFee;
impl TransactionBaseFee {
    pub fn get() -> u128 { 0 }
}
impl <I: From<u128>> ::support::traits::Get<I> for TransactionBaseFee {
    fn get() -> I { I::from(0) }
}
pub struct TransactionByteFee;
impl TransactionByteFee {
    pub fn get() -> u128 { 1 }
}
impl <I: From<u128>> ::support::traits::Get<I> for TransactionByteFee {
    fn get() -> I { I::from(1) }
}

pub const MILLISECS_PER_BLOCK: u64 = 6000;
pub const SLOT_DURATION: u64 = MILLISECS_PER_BLOCK;
pub const EPOCH_DURATION_IN_BLOCKS: u32 = 10 * MINUTES;
pub const MINUTES: BlockNumber =
    60_000 / (MILLISECS_PER_BLOCK as BlockNumber);
pub const HOURS: BlockNumber = MINUTES * 60;
pub const DAYS: BlockNumber = HOURS * 24;
pub const PRIMARY_PROBABILITY: (u64, u64) = (1, 4);
pub struct BlockHashCount;
impl BlockHashCount {
    pub fn get() -> BlockNumber { 250 }
}
impl <I: From<BlockNumber>> ::support::traits::Get<I> for BlockHashCount
 {
    fn get() -> I { I::from(250) }
}
pub struct MaximumBlockWeight;
impl MaximumBlockWeight {
    pub fn get() -> Weight { 1_000_000 }
}
impl <I: From<Weight>> ::support::traits::Get<I> for MaximumBlockWeight {
    fn get() -> I { I::from(1_000_000) }
}
pub struct AvailableBlockRatio;
impl AvailableBlockRatio {
    pub fn get() -> Perbill { Perbill::from_percent(75) }
}
impl <I: From<Perbill>> ::support::traits::Get<I> for AvailableBlockRatio
 {
    fn get() -> I { I::from(Perbill::from_percent(75)) }
}
pub struct MaximumBlockLength;
impl MaximumBlockLength {
    pub fn get() -> u32 { 5 * 1024 * 1024 }
}
impl <I: From<u32>> ::support::traits::Get<I> for MaximumBlockLength {
    fn get() -> I { I::from(5 * 1024 * 1024) }
}

pub struct Version;
impl Version {
    pub fn get() -> RuntimeVersion { VERSION }
}
impl <I: From<RuntimeVersion>> ::support::traits::Get<I> for Version {
    fn get() -> I { I::from(VERSION) }
}

pub struct MinimumPeriod;
impl MinimumPeriod {
    pub fn get() -> u64 { 5000 }
}
impl <I: From<u64>> ::support::traits::Get<I> for MinimumPeriod {
    fn get() -> I { I::from(5000) }
}

// dummy runtime API versions
type ApiId = [u8; 8];
type ApisVec = &'static [(ApiId, u32)];
const RUNTIME_API_VERSIONS: ApisVec = &[([0u8;8],0u32)];
/// This runtime version.
pub const VERSION: RuntimeVersion =
    RuntimeVersion{spec_name: { "sgx-trusted" },
                   impl_name: { "sgx-trusted" },
                   authoring_version: 3,
                   spec_version: 1,
                   impl_version: 1,
                   apis: RUNTIME_API_VERSIONS,};


#[allow(non_camel_case_types)]
#[structural_match]
#[derive(Debug)]
pub enum Event {
    system(system::Event),
    indices(indices::Event<Runtime>),
    balances(balances::Event<Runtime>),
}
#[automatically_derived]
#[allow(unused_qualifications)]
#[allow(non_camel_case_types)]
impl ::core::clone::Clone for Event {
    #[inline]
    fn clone(&self) -> Event {
        match (&*self,) {
            (&Event::system(ref __self_0),) =>
            Event::system(::core::clone::Clone::clone(&(*__self_0))),
            (&Event::indices(ref __self_0),) =>
            Event::indices(::core::clone::Clone::clone(&(*__self_0))),
            (&Event::balances(ref __self_0),) =>
            Event::balances(::core::clone::Clone::clone(&(*__self_0))),
        }
    }
}
#[automatically_derived]
#[allow(unused_qualifications)]
#[allow(non_camel_case_types)]
impl ::core::cmp::PartialEq for Event {
    #[inline]
    fn eq(&self, other: &Event) -> bool {
        {
            let __self_vi =
                unsafe { ::core::intrinsics::discriminant_value(&*self) } as
                    isize;
            let __arg_1_vi =
                unsafe { ::core::intrinsics::discriminant_value(&*other) } as
                    isize;
            if true && __self_vi == __arg_1_vi {
                match (&*self, &*other) {
                    (&Event::system(ref __self_0),
                     &Event::system(ref __arg_1_0)) =>
                            (*__self_0) == (*__arg_1_0),
                    (&Event::indices(ref __self_0),
                     &Event::indices(ref __arg_1_0)) =>
                            (*__self_0) == (*__arg_1_0),
                    (&Event::balances(ref __self_0),
                     &Event::balances(ref __arg_1_0)) =>
                            (*__self_0) == (*__arg_1_0),
                    _ => unsafe { ::core::intrinsics::unreachable() }
                }
            } else { false }
        }
    }
    #[inline]
    fn ne(&self, other: &Event) -> bool {
        {
            let __self_vi =
                unsafe { ::core::intrinsics::discriminant_value(&*self) } as
                    isize;
            let __arg_1_vi =
                unsafe { ::core::intrinsics::discriminant_value(&*other) } as
                    isize;
            if true && __self_vi == __arg_1_vi {
                match (&*self, &*other) {
                    (&Event::system(ref __self_0),
                     &Event::system(ref __arg_1_0)) =>
                    (*__self_0) != (*__arg_1_0),
                    (&Event::indices(ref __self_0),
                     &Event::indices(ref __arg_1_0)) =>
                    (*__self_0) != (*__arg_1_0),
                    (&Event::balances(ref __self_0),
                     &Event::balances(ref __arg_1_0)) =>
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
impl ::core::cmp::Eq for Event {
    #[inline]
    #[doc(hidden)]
    fn assert_receiver_is_total_eq(&self) -> () {
        {
            let _: ::core::cmp::AssertParamIsEq<system::Event>;
            let _: ::core::cmp::AssertParamIsEq<indices::Event<Runtime>>;
            let _: ::core::cmp::AssertParamIsEq<balances::Event<Runtime>>;
        }
    }
}
#[allow(non_upper_case_globals , unused_attributes , unused_qualifications)]
const _IMPL_ENCODE_FOR_Event: () =
    {
        #[allow(unknown_lints)]
        #[allow(rust_2018_idioms)]
        extern crate codec as _codec;
        impl _codec::Encode for Event {
            fn encode_to<EncOut: _codec::Output>(&self,
                                                              dest:
                                                                  &mut EncOut) {
                match *self {
                    Event::system(ref aa) => {
                        dest.push_byte(0usize as u8);
                        dest.push(aa);
                    }
                    Event::indices(ref aa) => {
                        dest.push_byte(1usize as u8);
                        dest.push(aa);
                    }
                    Event::balances(ref aa) => {
                        dest.push_byte(2usize as u8);
                        dest.push(aa);
                    }
                    _ => (),
                }
            }
        }
        impl _codec::EncodeLike for Event { }
    };
#[allow(non_upper_case_globals , unused_attributes , unused_qualifications)]
const _IMPL_DECODE_FOR_Event: () =
    {
        #[allow(unknown_lints)]
        #[allow(rust_2018_idioms)]
        extern crate codec as _codec;
        impl _codec::Decode for Event {
            fn decode<DecIn: _codec::Input>(input: &mut DecIn)
             -> core::result::Result<Self, _codec::Error> {
                match input.read_byte()? {
                    x if x == 0usize as u8 => {
                        Ok(Event::system({
                                             let res =
                                                 _codec::Decode::decode(input);
                                             match res {
                                                 Err(_) =>
                                                 return Err("Error decoding field Event :: system.0".into()),
                                                 Ok(a) => a,
                                             }
                                         }))
                    }
                    x if x == 1usize as u8 => {
                        Ok(Event::indices({
                                              let res =
                                                  _codec::Decode::decode(input);
                                              match res {
                                                  Err(_) =>
                                                  return Err("Error decoding field Event :: indices.0".into()),
                                                  Ok(a) => a,
                                              }
                                          }))
                    }
                    x if x == 2usize as u8 => {
                        Ok(Event::balances({
                                               let res =
                                                   _codec::Decode::decode(input);
                                               match res {
                                                   Err(_) =>
                                                   return Err("Error decoding field Event :: balances.0".into()),
                                                   Ok(a) => a,
                                               }
                                           }))
                    }
                    x => Err("No such variant in enum Event".into()),
                }
            }
        }
    };
impl From<system::Event> for Event {
    fn from(x: system::Event) -> Self { Event::system(x) }
}
impl From<indices::Event<Runtime>> for Event {
    fn from(x: indices::Event<Runtime>) -> Self { Event::indices(x) }
}
impl ::support::rstd::convert::TryInto<indices::Event<Runtime>> for Event
 {
    type
    Error
    =
    ();
    fn try_into(self)
     ->
         ::support::rstd::result::Result<indices::Event<Runtime>,
                                              Self::Error> {
        match self { Self::indices(evt) => Ok(evt), _ => Err(()), }
    }
}
impl From<balances::Event<Runtime>> for Event {
    fn from(x: balances::Event<Runtime>) -> Self { Event::balances(x) }
}
impl ::support::rstd::convert::TryInto<balances::Event<Runtime>> for
 Event {
    type
    Error
    =
    ();
    fn try_into(self)
     ->
         ::support::rstd::result::Result<balances::Event<Runtime>,
                                              Self::Error> {
        match self { Self::balances(evt) => Ok(evt), _ => Err(()), }
    }
}




/*
pub type Event<T> = RawEvent<<T as system::Trait>::AccountId>;
/// Events for this module.
///
#[structural_match]
pub enum RawEvent<AccountId> { SomethingStored(u32, AccountId), }
#[automatically_derived]
#[allow(unused_qualifications)]
impl <AccountId: ::core::clone::Clone> ::core::clone::Clone for
    RawEvent<AccountId> {
    #[inline]
    fn clone(&self) -> RawEvent<AccountId> {
        match (&*self,) {
            (&RawEvent::SomethingStored(ref __self_0, ref __self_1),) =>
            RawEvent::SomethingStored(::core::clone::Clone::clone(&(*__self_0)),
                                        ::core::clone::Clone::clone(&(*__self_1))),
        }
    }
}
#[automatically_derived]
#[allow(unused_qualifications)]
impl <AccountId: ::core::cmp::PartialEq> ::core::cmp::PartialEq for
    RawEvent<AccountId> {
    #[inline]
    fn eq(&self, other: &RawEvent<AccountId>) -> bool {
        match (&*self, &*other) {
            (&RawEvent::SomethingStored(ref __self_0, ref __self_1),
                &RawEvent::SomethingStored(ref __arg_1_0, ref __arg_1_1)) =>
            (*__self_0) == (*__arg_1_0) && (*__self_1) == (*__arg_1_1),
        }
    }
    #[inline]
    fn ne(&self, other: &RawEvent<AccountId>) -> bool {
        match (&*self, &*other) {
            (&RawEvent::SomethingStored(ref __self_0, ref __self_1),
                &RawEvent::SomethingStored(ref __arg_1_0, ref __arg_1_1)) =>
            (*__self_0) != (*__arg_1_0) || (*__self_1) != (*__arg_1_1),
        }
    }
}
#[automatically_derived]
#[allow(unused_qualifications)]
impl <AccountId: ::core::cmp::Eq> ::core::cmp::Eq for RawEvent<AccountId>
    {
    #[inline]
    #[doc(hidden)]
    fn assert_receiver_is_total_eq(&self) -> () {
        {
            let _: ::core::cmp::AssertParamIsEq<u32>;
            let _: ::core::cmp::AssertParamIsEq<AccountId>;
        }
    }
}
#[allow(non_upper_case_globals , unused_attributes ,
        unused_qualifications)]
const _IMPL_ENCODE_FOR_RawEvent: () =
    {
        #[allow(unknown_lints)]
        #[allow(rust_2018_idioms)]
        extern crate codec as _codec;
        impl <AccountId> _codec::Encode for
            RawEvent<AccountId> where AccountId: _codec::Encode,
            AccountId: _codec::Encode {
            fn encode_to<EncOut: _codec::Output>(&self,
                                                                dest:
                                                                    &mut EncOut) {
                match *self {
                    RawEvent::SomethingStored(ref aa, ref ba) => {
                        dest.push_byte(0usize as u8);
                        dest.push(aa);
                        dest.push(ba);
                    }
                    _ => (),
                }
            }
        }
        impl <AccountId> _codec::EncodeLike for
            RawEvent<AccountId> where AccountId: _codec::Encode,
            AccountId: _codec::Encode {
        }
    };
#[allow(non_upper_case_globals , unused_attributes ,
        unused_qualifications)]
const _IMPL_DECODE_FOR_RawEvent: () =
    {
        #[allow(unknown_lints)]
        #[allow(rust_2018_idioms)]
        extern crate codec as _codec;
        impl <AccountId> _codec::Decode for
            RawEvent<AccountId> where AccountId: _codec::Decode,
            AccountId: _codec::Decode {
            fn decode<DecIn: _codec::Input>(input:
                                                                &mut DecIn)
                -> core::result::Result<Self, _codec::Error> {
                match input.read_byte()? {
                    x if x == 0usize as u8 => {
                        Ok(RawEvent::SomethingStored({
                                                            let res =
                                                                _codec::Decode::decode(input);
                                                            match res {
                                                                Err(_) =>
                                                                return Err("Error decoding field RawEvent :: SomethingStored.0".into()),
                                                                Ok(a) => a,
                                                            }
                                                        },
                                                        {
                                                            let res =
                                                                _codec::Decode::decode(input);
                                                            match res {
                                                                Err(_) =>
                                                                return Err("Error decoding field RawEvent :: SomethingStored.1".into()),
                                                                Ok(a) => a,
                                                            }
                                                        }))
                    }
                    x => Err("No such variant in enum RawEvent".into()),
                }
            }
        }
    };
impl <AccountId> From<RawEvent<AccountId>> for () {
    fn from(_: RawEvent<AccountId>) -> () { () }
}
impl <AccountId> RawEvent<AccountId> {
    #[allow(dead_code)]
    pub fn metadata() -> &'static [::support::event::EventMetadata] {
        &[::support::event::EventMetadata{name:
                                                    ::support::event::DecodeDifferent::Encode("SomethingStored"),
                                                arguments:
                                                    ::support::event::DecodeDifferent::Encode(&["u32",
                                                                                                    "AccountId"]),
                                                documentation:
                                                    ::support::event::DecodeDifferent::Encode(&[]),}]
    }
}
*/
