#![feature(prelude_import)]
//! The Substrate Node Template runtime. This can be compiled with `#[no_std]`, ready for Wasm.
#![recursion_limit = "256"]
#[prelude_import]
use std::prelude::v1::*;
#[macro_use]
extern crate std;
use sp_std::prelude::*;
use sp_core::OpaqueMetadata;
use sp_runtime::{
    ApplyExtrinsicResult, generic, create_runtime_str, impl_opaque_keys, MultiSignature,
    transaction_validity::{TransactionValidity, TransactionSource},
};
use sp_runtime::traits::{
    BlakeTwo256, Block as BlockT, IdentityLookup, Verify, ConvertInto, IdentifyAccount,
};
use sp_api::impl_runtime_apis;
use sp_version::RuntimeVersion;
pub use timestamp::Call as TimestampCall;
pub use balances::Call as BalancesCall;
pub use sp_runtime::{Permill, Perbill};
pub use frame_support::{
    StorageValue, construct_runtime, parameter_types, traits::Randomness, weights::Weight,
};
/// An index to a block.
pub type BlockNumber = u32;
/// Alias to 512-bit hash when used in the context of a transaction signature on the chain.
pub type Signature = MultiSignature;
/// Some way of identifying an account on the chain. We intentionally make it equivalent
/// to the public key of our transaction signing scheme.
pub type AccountId = <<Signature as Verify>::Signer as IdentifyAccount>::AccountId;
/// The type for looking up accounts. We don't expect more than 4 billion of them, but you
/// never know...
pub type AccountIndex = u32;
/// Balance of an account.
pub type Balance = u128;
/// Index of a transaction in the chain.
pub type Index = u32;
/// A hash of some data used by the chain.
pub type Hash = sp_core::H256;
/// Digest item type.
pub type DigestItem = generic::DigestItem<Hash>;
/// Opaque types. These are used by the CLI to instantiate machinery that don't need to know
/// the specifics of the runtime. They can then be made to be agnostic over specific formats
/// of data like extrinsics, allowing for them to continue syncing the network through upgrades
/// to even the core data structures.
pub mod opaque {
    use super::*;
    pub use sp_runtime::OpaqueExtrinsic as UncheckedExtrinsic;
    /// Opaque block header type.
    pub type Header = generic::Header<BlockNumber, BlakeTwo256>;
    /// Opaque block type.
    pub type Block = generic::Block<Header, UncheckedExtrinsic>;
    /// Opaque block identifier type.
    pub type BlockId = generic::BlockId<Block>;
}
/// This runtime version.
pub const VERSION: RuntimeVersion = RuntimeVersion {
    spec_name: { ::sp_runtime::RuntimeString::Borrowed("node-template") },
    impl_name: { ::sp_runtime::RuntimeString::Borrowed("node-template") },
    authoring_version: 1,
    spec_version: 1,
    impl_version: 1,
    apis: RUNTIME_API_VERSIONS,
};
pub const MILLISECS_PER_BLOCK: u64 = 6000;
pub const SLOT_DURATION: u64 = MILLISECS_PER_BLOCK;
pub const MINUTES: BlockNumber = 60_000 / (MILLISECS_PER_BLOCK as BlockNumber);
pub const HOURS: BlockNumber = MINUTES * 60;
pub const DAYS: BlockNumber = HOURS * 24;
pub struct BlockHashCount;
impl BlockHashCount {
    pub fn get() -> BlockNumber {
        250
    }
}
impl<I: From<BlockNumber>> ::frame_support::traits::Get<I> for BlockHashCount {
    fn get() -> I {
        I::from(250)
    }
}
pub struct MaximumBlockWeight;
impl MaximumBlockWeight {
    pub fn get() -> Weight {
        1_000_000_000
    }
}
impl<I: From<Weight>> ::frame_support::traits::Get<I> for MaximumBlockWeight {
    fn get() -> I {
        I::from(1_000_000_000)
    }
}
pub struct AvailableBlockRatio;
impl AvailableBlockRatio {
    pub fn get() -> Perbill {
        Perbill::from_percent(75)
    }
}
impl<I: From<Perbill>> ::frame_support::traits::Get<I> for AvailableBlockRatio {
    fn get() -> I {
        I::from(Perbill::from_percent(75))
    }
}
pub struct MaximumBlockLength;
impl MaximumBlockLength {
    pub fn get() -> u32 {
        5 * 1024 * 1024
    }
}
impl<I: From<u32>> ::frame_support::traits::Get<I> for MaximumBlockLength {
    fn get() -> I {
        I::from(5 * 1024 * 1024)
    }
}
pub struct Version;
impl Version {
    pub fn get() -> RuntimeVersion {
        VERSION
    }
}
impl<I: From<RuntimeVersion>> ::frame_support::traits::Get<I> for Version {
    fn get() -> I {
        I::from(VERSION)
    }
}
impl system::Trait for Runtime {
    /// The identifier used to distinguish between accounts.
    type AccountId = AccountId;
    /// The aggregated dispatch type that is available for extrinsics.
    type Call = Call;
    /// The lookup mechanism to get account ID from whatever is passed in dispatchers.
    type Lookup = IdentityLookup<AccountId>;
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
    /// Converts a module to the index of the module in `construct_runtime!`.
    ///
    /// This type is being generated by `construct_runtime!`.
    type ModuleToIndex = ModuleToIndex;
    /// What to do if a new account is created.
    type OnNewAccount = ();
    /// What to do if an account is fully reaped from the system.
    type OnKilledAccount = ();
    /// The data to be stored in an account.
    type AccountData = balances::AccountData<Balance>;
}
pub struct MinimumPeriod;
impl MinimumPeriod {
    pub fn get() -> u64 {
        SLOT_DURATION / 2
    }
}
impl<I: From<u64>> ::frame_support::traits::Get<I> for MinimumPeriod {
    fn get() -> I {
        I::from(SLOT_DURATION / 2)
    }
}
impl timestamp::Trait for Runtime {
    /// A timestamp: milliseconds since the unix epoch.
    type Moment = u64;
    type OnTimestampSet = ();
    type MinimumPeriod = MinimumPeriod;
}
pub struct ExistentialDeposit;
impl ExistentialDeposit {
    pub fn get() -> u128 {
        500
    }
}
impl<I: From<u128>> ::frame_support::traits::Get<I> for ExistentialDeposit {
    fn get() -> I {
        I::from(500)
    }
}
impl balances::Trait for Runtime {
    /// The type for recording an account's balance.
    type Balance = Balance;
    /// The ubiquitous event type.
    type Event = Event;
    type DustRemoval = ();
    type ExistentialDeposit = ExistentialDeposit;
    type AccountStore = System;
}
pub struct TransactionBaseFee;
impl TransactionBaseFee {
    pub fn get() -> Balance {
        0
    }
}
impl<I: From<Balance>> ::frame_support::traits::Get<I> for TransactionBaseFee {
    fn get() -> I {
        I::from(0)
    }
}
pub struct TransactionByteFee;
impl TransactionByteFee {
    pub fn get() -> Balance {
        1
    }
}
impl<I: From<Balance>> ::frame_support::traits::Get<I> for TransactionByteFee {
    fn get() -> I {
        I::from(1)
    }
}
impl transaction_payment::Trait for Runtime {
    type Currency = balances::Module<Runtime>;
    type OnTransactionPayment = ();
    type TransactionBaseFee = TransactionBaseFee;
    type TransactionByteFee = TransactionByteFee;
    type WeightToFee = ConvertInto;
    type FeeMultiplierUpdate = ();
}
impl sudo::Trait for Runtime {
    type Event = Event;
    type Call = Call;
}
#[doc(hidden)]
mod sp_api_hidden_includes_construct_runtime {
    pub extern crate frame_support as hidden_include;
}
pub struct Runtime;
#[automatically_derived]
#[allow(unused_qualifications)]
impl ::core::clone::Clone for Runtime {
    #[inline]
    fn clone(&self) -> Runtime {
        {
            *self
        }
    }
}
#[automatically_derived]
#[allow(unused_qualifications)]
impl ::core::marker::Copy for Runtime {}
impl ::core::marker::StructuralPartialEq for Runtime {}
#[automatically_derived]
#[allow(unused_qualifications)]
impl ::core::cmp::PartialEq for Runtime {
    #[inline]
    fn eq(&self, other: &Runtime) -> bool {
        match *other {
            Runtime => match *self {
                Runtime => true,
            },
        }
    }
}
impl ::core::marker::StructuralEq for Runtime {}
#[automatically_derived]
#[allow(unused_qualifications)]
impl ::core::cmp::Eq for Runtime {
    #[inline]
    #[doc(hidden)]
    fn assert_receiver_is_total_eq(&self) -> () {
        {}
    }
}
#[automatically_derived]
#[allow(unused_qualifications)]
impl ::core::fmt::Debug for Runtime {
    fn fmt(&self, f: &mut ::core::fmt::Formatter) -> ::core::fmt::Result {
        match *self {
            Runtime => {
                let mut debug_trait_builder = f.debug_tuple("Runtime");
                debug_trait_builder.finish()
            }
        }
    }
}
impl self :: sp_api_hidden_includes_construct_runtime :: hidden_include :: sp_runtime :: traits :: GetNodeBlockType for Runtime { type NodeBlock = opaque :: Block ; }
impl self :: sp_api_hidden_includes_construct_runtime :: hidden_include :: sp_runtime :: traits :: GetRuntimeBlockType for Runtime { type RuntimeBlock = Block ; }
#[allow(non_camel_case_types)]
pub enum Event {
    system(system::Event<Runtime>),
    balances(balances::Event<Runtime>),
    sudo(sudo::Event<Runtime>),
}
#[automatically_derived]
#[allow(unused_qualifications)]
#[allow(non_camel_case_types)]
impl ::core::clone::Clone for Event {
    #[inline]
    fn clone(&self) -> Event {
        match (&*self,) {
            (&Event::system(ref __self_0),) => {
                Event::system(::core::clone::Clone::clone(&(*__self_0)))
            }
            (&Event::balances(ref __self_0),) => {
                Event::balances(::core::clone::Clone::clone(&(*__self_0)))
            }
            (&Event::sudo(ref __self_0),) => Event::sudo(::core::clone::Clone::clone(&(*__self_0))),
        }
    }
}
#[allow(non_camel_case_types)]
impl ::core::marker::StructuralPartialEq for Event {}
#[automatically_derived]
#[allow(unused_qualifications)]
#[allow(non_camel_case_types)]
impl ::core::cmp::PartialEq for Event {
    #[inline]
    fn eq(&self, other: &Event) -> bool {
        {
            let __self_vi = unsafe { ::core::intrinsics::discriminant_value(&*self) } as isize;
            let __arg_1_vi = unsafe { ::core::intrinsics::discriminant_value(&*other) } as isize;
            if true && __self_vi == __arg_1_vi {
                match (&*self, &*other) {
                    (&Event::system(ref __self_0), &Event::system(ref __arg_1_0)) => {
                        (*__self_0) == (*__arg_1_0)
                    }
                    (&Event::balances(ref __self_0), &Event::balances(ref __arg_1_0)) => {
                        (*__self_0) == (*__arg_1_0)
                    }
                    (&Event::sudo(ref __self_0), &Event::sudo(ref __arg_1_0)) => {
                        (*__self_0) == (*__arg_1_0)
                    }
                    _ => unsafe { ::core::intrinsics::unreachable() },
                }
            } else {
                false
            }
        }
    }
    #[inline]
    fn ne(&self, other: &Event) -> bool {
        {
            let __self_vi = unsafe { ::core::intrinsics::discriminant_value(&*self) } as isize;
            let __arg_1_vi = unsafe { ::core::intrinsics::discriminant_value(&*other) } as isize;
            if true && __self_vi == __arg_1_vi {
                match (&*self, &*other) {
                    (&Event::system(ref __self_0), &Event::system(ref __arg_1_0)) => {
                        (*__self_0) != (*__arg_1_0)
                    }
                    (&Event::balances(ref __self_0), &Event::balances(ref __arg_1_0)) => {
                        (*__self_0) != (*__arg_1_0)
                    }
                    (&Event::sudo(ref __self_0), &Event::sudo(ref __arg_1_0)) => {
                        (*__self_0) != (*__arg_1_0)
                    }
                    _ => unsafe { ::core::intrinsics::unreachable() },
                }
            } else {
                true
            }
        }
    }
}
#[allow(non_camel_case_types)]
impl ::core::marker::StructuralEq for Event {}
#[automatically_derived]
#[allow(unused_qualifications)]
#[allow(non_camel_case_types)]
impl ::core::cmp::Eq for Event {
    #[inline]
    #[doc(hidden)]
    fn assert_receiver_is_total_eq(&self) -> () {
        {
            let _: ::core::cmp::AssertParamIsEq<system::Event<Runtime>>;
            let _: ::core::cmp::AssertParamIsEq<balances::Event<Runtime>>;
            let _: ::core::cmp::AssertParamIsEq<sudo::Event<Runtime>>;
        }
    }
}
const _: () = {
    #[allow(unknown_lints)]
    #[allow(rust_2018_idioms)]
    extern crate codec as _parity_scale_codec;
    impl _parity_scale_codec::Encode for Event {
        fn encode_to<EncOut: _parity_scale_codec::Output>(&self, dest: &mut EncOut) {
            match *self {
                Event::system(ref aa) => {
                    dest.push_byte(0usize as u8);
                    dest.push(aa);
                }
                Event::balances(ref aa) => {
                    dest.push_byte(1usize as u8);
                    dest.push(aa);
                }
                Event::sudo(ref aa) => {
                    dest.push_byte(2usize as u8);
                    dest.push(aa);
                }
                _ => (),
            }
        }
    }
    impl _parity_scale_codec::EncodeLike for Event {}
};
const _: () = {
    #[allow(unknown_lints)]
    #[allow(rust_2018_idioms)]
    extern crate codec as _parity_scale_codec;
    impl _parity_scale_codec::Decode for Event {
        fn decode<DecIn: _parity_scale_codec::Input>(
            input: &mut DecIn,
        ) -> core::result::Result<Self, _parity_scale_codec::Error> {
            match input.read_byte()? {
                x if x == 0usize as u8 => Ok(Event::system({
                    let res = _parity_scale_codec::Decode::decode(input);
                    match res {
                        Err(_) => return Err("Error decoding field Event :: system.0".into()),
                        Ok(a) => a,
                    }
                })),
                x if x == 1usize as u8 => Ok(Event::balances({
                    let res = _parity_scale_codec::Decode::decode(input);
                    match res {
                        Err(_) => return Err("Error decoding field Event :: balances.0".into()),
                        Ok(a) => a,
                    }
                })),
                x if x == 2usize as u8 => Ok(Event::sudo({
                    let res = _parity_scale_codec::Decode::decode(input);
                    match res {
                        Err(_) => return Err("Error decoding field Event :: sudo.0".into()),
                        Ok(a) => a,
                    }
                })),
                x => Err("No such variant in enum Event".into()),
            }
        }
    }
};
impl core::fmt::Debug for Event {
    fn fmt(&self, fmt: &mut core::fmt::Formatter) -> core::fmt::Result {
        match self {
            Self::system(ref a0) => fmt.debug_tuple("Event::system").field(a0).finish(),
            Self::balances(ref a0) => fmt.debug_tuple("Event::balances").field(a0).finish(),
            Self::sudo(ref a0) => fmt.debug_tuple("Event::sudo").field(a0).finish(),
            _ => Ok(()),
        }
    }
}
impl From<system::Event<Runtime>> for Event {
    fn from(x: system::Event<Runtime>) -> Self {
        Event::system(x)
    }
}
impl ::frame_support::sp_std::convert::TryInto<system::Event<Runtime>> for Event {
    type Error = ();
    fn try_into(
        self,
    ) -> ::frame_support::sp_std::result::Result<system::Event<Runtime>, Self::Error> {
        match self {
            Self::system(evt) => Ok(evt),
            _ => Err(()),
        }
    }
}
impl From<balances::Event<Runtime>> for Event {
    fn from(x: balances::Event<Runtime>) -> Self {
        Event::balances(x)
    }
}
impl ::frame_support::sp_std::convert::TryInto<balances::Event<Runtime>> for Event {
    type Error = ();
    fn try_into(
        self,
    ) -> ::frame_support::sp_std::result::Result<balances::Event<Runtime>, Self::Error> {
        match self {
            Self::balances(evt) => Ok(evt),
            _ => Err(()),
        }
    }
}
impl From<sudo::Event<Runtime>> for Event {
    fn from(x: sudo::Event<Runtime>) -> Self {
        Event::sudo(x)
    }
}
impl ::frame_support::sp_std::convert::TryInto<sudo::Event<Runtime>> for Event {
    type Error = ();
    fn try_into(
        self,
    ) -> ::frame_support::sp_std::result::Result<sudo::Event<Runtime>, Self::Error> {
        match self {
            Self::sudo(evt) => Ok(evt),
            _ => Err(()),
        }
    }
}
impl Runtime {
    #[allow(dead_code)]
    pub fn outer_event_metadata() -> ::frame_support::event::OuterEventMetadata {
        ::frame_support::event::OuterEventMetadata {
            name: ::frame_support::event::DecodeDifferent::Encode("Event"),
            events: ::frame_support::event::DecodeDifferent::Encode(&[
                (
                    "system",
                    ::frame_support::event::FnEncode(system::Event::<Runtime>::metadata),
                ),
                (
                    "balances",
                    ::frame_support::event::FnEncode(balances::Event::<Runtime>::metadata),
                ),
                (
                    "sudo",
                    ::frame_support::event::FnEncode(sudo::Event::<Runtime>::metadata),
                ),
            ]),
        }
    }
    #[allow(dead_code)]
    pub fn __module_events_system() -> &'static [::frame_support::event::EventMetadata] {
        system::Event::<Runtime>::metadata()
    }
    #[allow(dead_code)]
    pub fn __module_events_balances() -> &'static [::frame_support::event::EventMetadata] {
        balances::Event::<Runtime>::metadata()
    }
    #[allow(dead_code)]
    pub fn __module_events_sudo() -> &'static [::frame_support::event::EventMetadata] {
        sudo::Event::<Runtime>::metadata()
    }
}
#[allow(non_camel_case_types)]
pub enum Origin {
    system(system::Origin<Runtime>),
    #[allow(dead_code)]
    Void(::frame_support::Void),
}
#[automatically_derived]
#[allow(unused_qualifications)]
#[allow(non_camel_case_types)]
impl ::core::clone::Clone for Origin {
    #[inline]
    fn clone(&self) -> Origin {
        match (&*self,) {
            (&Origin::system(ref __self_0),) => {
                Origin::system(::core::clone::Clone::clone(&(*__self_0)))
            }
            (&Origin::Void(ref __self_0),) => {
                Origin::Void(::core::clone::Clone::clone(&(*__self_0)))
            }
        }
    }
}
#[allow(non_camel_case_types)]
impl ::core::marker::StructuralPartialEq for Origin {}
#[automatically_derived]
#[allow(unused_qualifications)]
#[allow(non_camel_case_types)]
impl ::core::cmp::PartialEq for Origin {
    #[inline]
    fn eq(&self, other: &Origin) -> bool {
        {
            let __self_vi = unsafe { ::core::intrinsics::discriminant_value(&*self) } as isize;
            let __arg_1_vi = unsafe { ::core::intrinsics::discriminant_value(&*other) } as isize;
            if true && __self_vi == __arg_1_vi {
                match (&*self, &*other) {
                    (&Origin::system(ref __self_0), &Origin::system(ref __arg_1_0)) => {
                        (*__self_0) == (*__arg_1_0)
                    }
                    (&Origin::Void(ref __self_0), &Origin::Void(ref __arg_1_0)) => {
                        (*__self_0) == (*__arg_1_0)
                    }
                    _ => unsafe { ::core::intrinsics::unreachable() },
                }
            } else {
                false
            }
        }
    }
    #[inline]
    fn ne(&self, other: &Origin) -> bool {
        {
            let __self_vi = unsafe { ::core::intrinsics::discriminant_value(&*self) } as isize;
            let __arg_1_vi = unsafe { ::core::intrinsics::discriminant_value(&*other) } as isize;
            if true && __self_vi == __arg_1_vi {
                match (&*self, &*other) {
                    (&Origin::system(ref __self_0), &Origin::system(ref __arg_1_0)) => {
                        (*__self_0) != (*__arg_1_0)
                    }
                    (&Origin::Void(ref __self_0), &Origin::Void(ref __arg_1_0)) => {
                        (*__self_0) != (*__arg_1_0)
                    }
                    _ => unsafe { ::core::intrinsics::unreachable() },
                }
            } else {
                true
            }
        }
    }
}
#[allow(non_camel_case_types)]
impl ::core::marker::StructuralEq for Origin {}
#[automatically_derived]
#[allow(unused_qualifications)]
#[allow(non_camel_case_types)]
impl ::core::cmp::Eq for Origin {
    #[inline]
    #[doc(hidden)]
    fn assert_receiver_is_total_eq(&self) -> () {
        {
            let _: ::core::cmp::AssertParamIsEq<system::Origin<Runtime>>;
            let _: ::core::cmp::AssertParamIsEq<::frame_support::Void>;
        }
    }
}
impl core::fmt::Debug for Origin {
    fn fmt(&self, fmt: &mut core::fmt::Formatter) -> core::fmt::Result {
        match self {
            Self::system(ref a0) => fmt.debug_tuple("Origin::system").field(a0).finish(),
            Self::Void(ref a0) => fmt.debug_tuple("Origin::Void").field(a0).finish(),
            _ => Ok(()),
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
    fn from(x: system::Origin<Runtime>) -> Self {
        Origin::system(x)
    }
}
impl Into<::frame_support::sp_std::result::Result<system::Origin<Runtime>, Origin>> for Origin {
    fn into(self) -> ::frame_support::sp_std::result::Result<system::Origin<Runtime>, Self> {
        if let Origin::system(l) = self {
            Ok(l)
        } else {
            Err(self)
        }
    }
}
impl From<Option<<Runtime as system::Trait>::AccountId>> for Origin {
    fn from(x: Option<<Runtime as system::Trait>::AccountId>) -> Self {
        <system::Origin<Runtime>>::from(x).into()
    }
}
pub type System = system::Module<Runtime>;
pub type Timestamp = timestamp::Module<Runtime>;
pub type Balances = balances::Module<Runtime>;
pub type TransactionPayment = transaction_payment::Module<Runtime>;
pub type Sudo = sudo::Module<Runtime>;
type AllModules = ((Sudo, (TransactionPayment, (Balances, (Timestamp,)))));
/// Provides an implementation of `ModuleToIndex` to map a module
/// to its index in the runtime.
pub struct ModuleToIndex;
impl self::sp_api_hidden_includes_construct_runtime::hidden_include::traits::ModuleToIndex
    for ModuleToIndex
{
    fn module_to_index<M: 'static>() -> Option<usize> {
        let type_id =
            self::sp_api_hidden_includes_construct_runtime::hidden_include::sp_std::any::TypeId::of::<
                M,
            >();
        if type_id == self :: sp_api_hidden_includes_construct_runtime :: hidden_include :: sp_std :: any :: TypeId :: of :: < System > ( ) { return Some ( 0usize ) }
        if type_id == self :: sp_api_hidden_includes_construct_runtime :: hidden_include :: sp_std :: any :: TypeId :: of :: < Timestamp > ( ) { return Some ( 1usize ) }
        if type_id == self :: sp_api_hidden_includes_construct_runtime :: hidden_include :: sp_std :: any :: TypeId :: of :: < Balances > ( ) { return Some ( 2usize ) }
        if type_id == self :: sp_api_hidden_includes_construct_runtime :: hidden_include :: sp_std :: any :: TypeId :: of :: < TransactionPayment > ( ) { return Some ( 3usize ) }
        if type_id == self :: sp_api_hidden_includes_construct_runtime :: hidden_include :: sp_std :: any :: TypeId :: of :: < Sudo > ( ) { return Some ( 4usize ) }
        None
    }
}
pub enum Call {
    System(::frame_support::dispatch::CallableCallFor<System, Runtime>),
    Timestamp(::frame_support::dispatch::CallableCallFor<Timestamp, Runtime>),
    Balances(::frame_support::dispatch::CallableCallFor<Balances, Runtime>),
    Sudo(::frame_support::dispatch::CallableCallFor<Sudo, Runtime>),
}
#[automatically_derived]
#[allow(unused_qualifications)]
impl ::core::clone::Clone for Call {
    #[inline]
    fn clone(&self) -> Call {
        match (&*self,) {
            (&Call::System(ref __self_0),) => {
                Call::System(::core::clone::Clone::clone(&(*__self_0)))
            }
            (&Call::Timestamp(ref __self_0),) => {
                Call::Timestamp(::core::clone::Clone::clone(&(*__self_0)))
            }
            (&Call::Balances(ref __self_0),) => {
                Call::Balances(::core::clone::Clone::clone(&(*__self_0)))
            }
            (&Call::Sudo(ref __self_0),) => Call::Sudo(::core::clone::Clone::clone(&(*__self_0))),
        }
    }
}
impl ::core::marker::StructuralPartialEq for Call {}
#[automatically_derived]
#[allow(unused_qualifications)]
impl ::core::cmp::PartialEq for Call {
    #[inline]
    fn eq(&self, other: &Call) -> bool {
        {
            let __self_vi = unsafe { ::core::intrinsics::discriminant_value(&*self) } as isize;
            let __arg_1_vi = unsafe { ::core::intrinsics::discriminant_value(&*other) } as isize;
            if true && __self_vi == __arg_1_vi {
                match (&*self, &*other) {
                    (&Call::System(ref __self_0), &Call::System(ref __arg_1_0)) => {
                        (*__self_0) == (*__arg_1_0)
                    }
                    (&Call::Timestamp(ref __self_0), &Call::Timestamp(ref __arg_1_0)) => {
                        (*__self_0) == (*__arg_1_0)
                    }
                    (&Call::Balances(ref __self_0), &Call::Balances(ref __arg_1_0)) => {
                        (*__self_0) == (*__arg_1_0)
                    }
                    (&Call::Sudo(ref __self_0), &Call::Sudo(ref __arg_1_0)) => {
                        (*__self_0) == (*__arg_1_0)
                    }
                    _ => unsafe { ::core::intrinsics::unreachable() },
                }
            } else {
                false
            }
        }
    }
    #[inline]
    fn ne(&self, other: &Call) -> bool {
        {
            let __self_vi = unsafe { ::core::intrinsics::discriminant_value(&*self) } as isize;
            let __arg_1_vi = unsafe { ::core::intrinsics::discriminant_value(&*other) } as isize;
            if true && __self_vi == __arg_1_vi {
                match (&*self, &*other) {
                    (&Call::System(ref __self_0), &Call::System(ref __arg_1_0)) => {
                        (*__self_0) != (*__arg_1_0)
                    }
                    (&Call::Timestamp(ref __self_0), &Call::Timestamp(ref __arg_1_0)) => {
                        (*__self_0) != (*__arg_1_0)
                    }
                    (&Call::Balances(ref __self_0), &Call::Balances(ref __arg_1_0)) => {
                        (*__self_0) != (*__arg_1_0)
                    }
                    (&Call::Sudo(ref __self_0), &Call::Sudo(ref __arg_1_0)) => {
                        (*__self_0) != (*__arg_1_0)
                    }
                    _ => unsafe { ::core::intrinsics::unreachable() },
                }
            } else {
                true
            }
        }
    }
}
impl ::core::marker::StructuralEq for Call {}
#[automatically_derived]
#[allow(unused_qualifications)]
impl ::core::cmp::Eq for Call {
    #[inline]
    #[doc(hidden)]
    fn assert_receiver_is_total_eq(&self) -> () {
        {
            let _: ::core::cmp::AssertParamIsEq<
                ::frame_support::dispatch::CallableCallFor<System, Runtime>,
            >;
            let _: ::core::cmp::AssertParamIsEq<
                ::frame_support::dispatch::CallableCallFor<Timestamp, Runtime>,
            >;
            let _: ::core::cmp::AssertParamIsEq<
                ::frame_support::dispatch::CallableCallFor<Balances, Runtime>,
            >;
            let _: ::core::cmp::AssertParamIsEq<
                ::frame_support::dispatch::CallableCallFor<Sudo, Runtime>,
            >;
        }
    }
}
const _: () = {
    #[allow(unknown_lints)]
    #[allow(rust_2018_idioms)]
    extern crate codec as _parity_scale_codec;
    impl _parity_scale_codec::Encode for Call {
        fn encode_to<EncOut: _parity_scale_codec::Output>(&self, dest: &mut EncOut) {
            match *self {
                Call::System(ref aa) => {
                    dest.push_byte(0usize as u8);
                    dest.push(aa);
                }
                Call::Timestamp(ref aa) => {
                    dest.push_byte(1usize as u8);
                    dest.push(aa);
                }
                Call::Balances(ref aa) => {
                    dest.push_byte(2usize as u8);
                    dest.push(aa);
                }
                Call::Sudo(ref aa) => {
                    dest.push_byte(3usize as u8);
                    dest.push(aa);
                }
                _ => (),
            }
        }
    }
    impl _parity_scale_codec::EncodeLike for Call {}
};
const _: () = {
    #[allow(unknown_lints)]
    #[allow(rust_2018_idioms)]
    extern crate codec as _parity_scale_codec;
    impl _parity_scale_codec::Decode for Call {
        fn decode<DecIn: _parity_scale_codec::Input>(
            input: &mut DecIn,
        ) -> core::result::Result<Self, _parity_scale_codec::Error> {
            match input.read_byte()? {
                x if x == 0usize as u8 => Ok(Call::System({
                    let res = _parity_scale_codec::Decode::decode(input);
                    match res {
                        Err(_) => return Err("Error decoding field Call :: System.0".into()),
                        Ok(a) => a,
                    }
                })),
                x if x == 1usize as u8 => Ok(Call::Timestamp({
                    let res = _parity_scale_codec::Decode::decode(input);
                    match res {
                        Err(_) => return Err("Error decoding field Call :: Timestamp.0".into()),
                        Ok(a) => a,
                    }
                })),
                x if x == 2usize as u8 => Ok(Call::Balances({
                    let res = _parity_scale_codec::Decode::decode(input);
                    match res {
                        Err(_) => return Err("Error decoding field Call :: Balances.0".into()),
                        Ok(a) => a,
                    }
                })),
                x if x == 3usize as u8 => Ok(Call::Sudo({
                    let res = _parity_scale_codec::Decode::decode(input);
                    match res {
                        Err(_) => return Err("Error decoding field Call :: Sudo.0".into()),
                        Ok(a) => a,
                    }
                })),
                x => Err("No such variant in enum Call".into()),
            }
        }
    }
};
impl core::fmt::Debug for Call {
    fn fmt(&self, fmt: &mut core::fmt::Formatter) -> core::fmt::Result {
        match self {
            Self::System(ref a0) => fmt.debug_tuple("Call::System").field(a0).finish(),
            Self::Timestamp(ref a0) => fmt.debug_tuple("Call::Timestamp").field(a0).finish(),
            Self::Balances(ref a0) => fmt.debug_tuple("Call::Balances").field(a0).finish(),
            Self::Sudo(ref a0) => fmt.debug_tuple("Call::Sudo").field(a0).finish(),
            _ => Ok(()),
        }
    }
}
impl ::frame_support::dispatch::GetDispatchInfo for Call {
    fn get_dispatch_info(&self) -> ::frame_support::dispatch::DispatchInfo {
        match self {
            Call::System(call) => call.get_dispatch_info(),
            Call::Timestamp(call) => call.get_dispatch_info(),
            Call::Balances(call) => call.get_dispatch_info(),
            Call::Sudo(call) => call.get_dispatch_info(),
        }
    }
}
impl ::frame_support::dispatch::GetCallMetadata for Call {
    fn get_call_metadata(&self) -> ::frame_support::dispatch::CallMetadata {
        use ::frame_support::dispatch::GetCallName;
        match self {
            Call::System(call) => {
                let function_name = call.get_call_name();
                let pallet_name = "System";
                ::frame_support::dispatch::CallMetadata {
                    function_name,
                    pallet_name,
                }
            }
            Call::Timestamp(call) => {
                let function_name = call.get_call_name();
                let pallet_name = "Timestamp";
                ::frame_support::dispatch::CallMetadata {
                    function_name,
                    pallet_name,
                }
            }
            Call::Balances(call) => {
                let function_name = call.get_call_name();
                let pallet_name = "Balances";
                ::frame_support::dispatch::CallMetadata {
                    function_name,
                    pallet_name,
                }
            }
            Call::Sudo(call) => {
                let function_name = call.get_call_name();
                let pallet_name = "Sudo";
                ::frame_support::dispatch::CallMetadata {
                    function_name,
                    pallet_name,
                }
            }
        }
    }
    fn get_module_names() -> &'static [&'static str] {
        &["System", "Timestamp", "Balances", "Sudo"]
    }
    fn get_call_names(module: &str) -> &'static [&'static str] {
        use ::frame_support::dispatch::{Callable, GetCallName};
        match module {
            "System" => <<System as Callable<Runtime>>::Call as GetCallName>::get_call_names(),
            "Timestamp" => {
                <<Timestamp as Callable<Runtime>>::Call as GetCallName>::get_call_names()
            }
            "Balances" => <<Balances as Callable<Runtime>>::Call as GetCallName>::get_call_names(),
            "Sudo" => <<Sudo as Callable<Runtime>>::Call as GetCallName>::get_call_names(),
            _ => ::std::rt::begin_panic("internal error: entered unreachable code"),
        }
    }
}
impl ::frame_support::dispatch::Dispatchable for Call {
    type Origin = Origin;
    type Trait = Call;
    type Info = ::frame_support::weights::DispatchInfo;
    type PostInfo = ::frame_support::weights::PostDispatchInfo;
    fn dispatch(self, origin: Origin) -> ::frame_support::dispatch::DispatchResultWithPostInfo {
        match self {
            Call::System(call) => call.dispatch(origin),
            Call::Timestamp(call) => call.dispatch(origin),
            Call::Balances(call) => call.dispatch(origin),
            Call::Sudo(call) => call.dispatch(origin),
        }
    }
}
impl ::frame_support::dispatch::IsSubType<System, Runtime> for Call {
    #[allow(unreachable_patterns)]
    fn is_sub_type(&self) -> Option<&::frame_support::dispatch::CallableCallFor<System, Runtime>> {
        match *self {
            Call::System(ref r) => Some(r),
            _ => None,
        }
    }
}
impl From<::frame_support::dispatch::CallableCallFor<System, Runtime>> for Call {
    fn from(call: ::frame_support::dispatch::CallableCallFor<System, Runtime>) -> Self {
        Call::System(call)
    }
}
impl ::frame_support::dispatch::IsSubType<Timestamp, Runtime> for Call {
    #[allow(unreachable_patterns)]
    fn is_sub_type(
        &self,
    ) -> Option<&::frame_support::dispatch::CallableCallFor<Timestamp, Runtime>> {
        match *self {
            Call::Timestamp(ref r) => Some(r),
            _ => None,
        }
    }
}
impl From<::frame_support::dispatch::CallableCallFor<Timestamp, Runtime>> for Call {
    fn from(call: ::frame_support::dispatch::CallableCallFor<Timestamp, Runtime>) -> Self {
        Call::Timestamp(call)
    }
}
impl ::frame_support::dispatch::IsSubType<Balances, Runtime> for Call {
    #[allow(unreachable_patterns)]
    fn is_sub_type(
        &self,
    ) -> Option<&::frame_support::dispatch::CallableCallFor<Balances, Runtime>> {
        match *self {
            Call::Balances(ref r) => Some(r),
            _ => None,
        }
    }
}
impl From<::frame_support::dispatch::CallableCallFor<Balances, Runtime>> for Call {
    fn from(call: ::frame_support::dispatch::CallableCallFor<Balances, Runtime>) -> Self {
        Call::Balances(call)
    }
}
impl ::frame_support::dispatch::IsSubType<Sudo, Runtime> for Call {
    #[allow(unreachable_patterns)]
    fn is_sub_type(&self) -> Option<&::frame_support::dispatch::CallableCallFor<Sudo, Runtime>> {
        match *self {
            Call::Sudo(ref r) => Some(r),
            _ => None,
        }
    }
}
impl From<::frame_support::dispatch::CallableCallFor<Sudo, Runtime>> for Call {
    fn from(call: ::frame_support::dispatch::CallableCallFor<Sudo, Runtime>) -> Self {
        Call::Sudo(call)
    }
}
impl Runtime {
    pub fn metadata() -> ::frame_support::metadata::RuntimeMetadataPrefixed {
        :: frame_support :: metadata :: RuntimeMetadataLastVersion { modules : :: frame_support :: metadata :: DecodeDifferent :: Encode ( & [ :: frame_support :: metadata :: ModuleMetadata { name : :: frame_support :: metadata :: DecodeDifferent :: Encode ( "System" ) , storage : Some ( :: frame_support :: metadata :: DecodeDifferent :: Encode ( :: frame_support :: metadata :: FnEncode ( system :: Module :: < Runtime > :: storage_metadata ) ) ) , calls : Some ( :: frame_support :: metadata :: DecodeDifferent :: Encode ( :: frame_support :: metadata :: FnEncode ( system :: Module :: < Runtime > :: call_functions ) ) ) , event : Some ( :: frame_support :: metadata :: DecodeDifferent :: Encode ( :: frame_support :: metadata :: FnEncode ( { # [ allow ( dead_code ) ] enum ProcMacroHack { Value = ( "Runtime :: [< __module_events_ system >]" , 0 ) . 1 , } { Runtime :: __module_events_system } } ) ) ) , constants : :: frame_support :: metadata :: DecodeDifferent :: Encode ( :: frame_support :: metadata :: FnEncode ( system :: Module :: < Runtime > :: module_constants_metadata ) ) , errors : :: frame_support :: metadata :: DecodeDifferent :: Encode ( :: frame_support :: metadata :: FnEncode ( < system :: Module < Runtime > as :: frame_support :: metadata :: ModuleErrorMetadata > :: metadata ) ) , } , :: frame_support :: metadata :: ModuleMetadata { name : :: frame_support :: metadata :: DecodeDifferent :: Encode ( "Timestamp" ) , storage : Some ( :: frame_support :: metadata :: DecodeDifferent :: Encode ( :: frame_support :: metadata :: FnEncode ( timestamp :: Module :: < Runtime > :: storage_metadata ) ) ) , calls : Some ( :: frame_support :: metadata :: DecodeDifferent :: Encode ( :: frame_support :: metadata :: FnEncode ( timestamp :: Module :: < Runtime > :: call_functions ) ) ) , event : None , constants : :: frame_support :: metadata :: DecodeDifferent :: Encode ( :: frame_support :: metadata :: FnEncode ( timestamp :: Module :: < Runtime > :: module_constants_metadata ) ) , errors : :: frame_support :: metadata :: DecodeDifferent :: Encode ( :: frame_support :: metadata :: FnEncode ( < timestamp :: Module < Runtime > as :: frame_support :: metadata :: ModuleErrorMetadata > :: metadata ) ) , } , :: frame_support :: metadata :: ModuleMetadata { name : :: frame_support :: metadata :: DecodeDifferent :: Encode ( "Balances" ) , storage : Some ( :: frame_support :: metadata :: DecodeDifferent :: Encode ( :: frame_support :: metadata :: FnEncode ( balances :: Module :: < Runtime > :: storage_metadata ) ) ) , calls : Some ( :: frame_support :: metadata :: DecodeDifferent :: Encode ( :: frame_support :: metadata :: FnEncode ( balances :: Module :: < Runtime > :: call_functions ) ) ) , event : Some ( :: frame_support :: metadata :: DecodeDifferent :: Encode ( :: frame_support :: metadata :: FnEncode ( { # [ allow ( dead_code ) ] enum ProcMacroHack { Value = ( "Runtime :: [< __module_events_ balances >]" , 0 ) . 1 , } { Runtime :: __module_events_balances } } ) ) ) , constants : :: frame_support :: metadata :: DecodeDifferent :: Encode ( :: frame_support :: metadata :: FnEncode ( balances :: Module :: < Runtime > :: module_constants_metadata ) ) , errors : :: frame_support :: metadata :: DecodeDifferent :: Encode ( :: frame_support :: metadata :: FnEncode ( < balances :: Module < Runtime > as :: frame_support :: metadata :: ModuleErrorMetadata > :: metadata ) ) , } , :: frame_support :: metadata :: ModuleMetadata { name : :: frame_support :: metadata :: DecodeDifferent :: Encode ( "TransactionPayment" ) , storage : Some ( :: frame_support :: metadata :: DecodeDifferent :: Encode ( :: frame_support :: metadata :: FnEncode ( transaction_payment :: Module :: < Runtime > :: storage_metadata ) ) ) , calls : None , event : None , constants : :: frame_support :: metadata :: DecodeDifferent :: Encode ( :: frame_support :: metadata :: FnEncode ( transaction_payment :: Module :: < Runtime > :: module_constants_metadata ) ) , errors : :: frame_support :: metadata :: DecodeDifferent :: Encode ( :: frame_support :: metadata :: FnEncode ( < transaction_payment :: Module < Runtime > as :: frame_support :: metadata :: ModuleErrorMetadata > :: metadata ) ) , } , :: frame_support :: metadata :: ModuleMetadata { name : :: frame_support :: metadata :: DecodeDifferent :: Encode ( "Sudo" ) , storage : Some ( :: frame_support :: metadata :: DecodeDifferent :: Encode ( :: frame_support :: metadata :: FnEncode ( sudo :: Module :: < Runtime > :: storage_metadata ) ) ) , calls : Some ( :: frame_support :: metadata :: DecodeDifferent :: Encode ( :: frame_support :: metadata :: FnEncode ( sudo :: Module :: < Runtime > :: call_functions ) ) ) , event : Some ( :: frame_support :: metadata :: DecodeDifferent :: Encode ( :: frame_support :: metadata :: FnEncode ( { # [ allow ( dead_code ) ] enum ProcMacroHack { Value = ( "Runtime :: [< __module_events_ sudo >]" , 0 ) . 1 , } { Runtime :: __module_events_sudo } } ) ) ) , constants : :: frame_support :: metadata :: DecodeDifferent :: Encode ( :: frame_support :: metadata :: FnEncode ( sudo :: Module :: < Runtime > :: module_constants_metadata ) ) , errors : :: frame_support :: metadata :: DecodeDifferent :: Encode ( :: frame_support :: metadata :: FnEncode ( < sudo :: Module < Runtime > as :: frame_support :: metadata :: ModuleErrorMetadata > :: metadata ) ) , } ] ) , extrinsic : :: frame_support :: metadata :: ExtrinsicMetadata { version : < UncheckedExtrinsic as :: frame_support :: sp_runtime :: traits :: ExtrinsicMetadata > :: VERSION , signed_extensions : < < UncheckedExtrinsic as :: frame_support :: sp_runtime :: traits :: ExtrinsicMetadata > :: SignedExtensions as :: frame_support :: sp_runtime :: traits :: SignedExtension > :: identifier ( ) . into_iter ( ) . map ( :: frame_support :: metadata :: DecodeDifferent :: Encode ) . collect ( ) , } , } . into ( )
    }
}
#[cfg(any(feature = "std", test))]
pub type SystemConfig = system::GenesisConfig;
#[cfg(any(feature = "std", test))]
pub type BalancesConfig = balances::GenesisConfig<Runtime>;
#[cfg(any(feature = "std", test))]
pub type SudoConfig = sudo::GenesisConfig<Runtime>;
#[cfg(any(feature = "std", test))]
#[serde(rename_all = "camelCase")]
#[serde(deny_unknown_fields)]
pub struct GenesisConfig {
    pub system: Option<SystemConfig>,
    pub balances: Option<BalancesConfig>,
    pub sudo: Option<SudoConfig>,
}
#[doc(hidden)]
#[allow(non_upper_case_globals, unused_attributes, unused_qualifications)]
const _IMPL_SERIALIZE_FOR_GenesisConfig: () = {
    #[allow(unknown_lints)]
    #[allow(rust_2018_idioms)]
    extern crate serde as _serde;
    #[automatically_derived]
    impl _serde::Serialize for GenesisConfig {
        fn serialize<__S>(&self, __serializer: __S) -> _serde::export::Result<__S::Ok, __S::Error>
        where
            __S: _serde::Serializer,
        {
            let mut __serde_state = match _serde::Serializer::serialize_struct(
                __serializer,
                "GenesisConfig",
                false as usize + 1 + 1 + 1,
            ) {
                _serde::export::Ok(__val) => __val,
                _serde::export::Err(__err) => {
                    return _serde::export::Err(__err);
                }
            };
            match _serde::ser::SerializeStruct::serialize_field(
                &mut __serde_state,
                "system",
                &self.system,
            ) {
                _serde::export::Ok(__val) => __val,
                _serde::export::Err(__err) => {
                    return _serde::export::Err(__err);
                }
            };
            match _serde::ser::SerializeStruct::serialize_field(
                &mut __serde_state,
                "balances",
                &self.balances,
            ) {
                _serde::export::Ok(__val) => __val,
                _serde::export::Err(__err) => {
                    return _serde::export::Err(__err);
                }
            };
            match _serde::ser::SerializeStruct::serialize_field(
                &mut __serde_state,
                "sudo",
                &self.sudo,
            ) {
                _serde::export::Ok(__val) => __val,
                _serde::export::Err(__err) => {
                    return _serde::export::Err(__err);
                }
            };
            _serde::ser::SerializeStruct::end(__serde_state)
        }
    }
};
#[doc(hidden)]
#[allow(non_upper_case_globals, unused_attributes, unused_qualifications)]
const _IMPL_DESERIALIZE_FOR_GenesisConfig: () = {
    #[allow(unknown_lints)]
    #[allow(rust_2018_idioms)]
    extern crate serde as _serde;
    #[automatically_derived]
    impl<'de> _serde::Deserialize<'de> for GenesisConfig {
        fn deserialize<__D>(__deserializer: __D) -> _serde::export::Result<Self, __D::Error>
        where
            __D: _serde::Deserializer<'de>,
        {
            #[allow(non_camel_case_types)]
            enum __Field {
                __field0,
                __field1,
                __field2,
            }
            struct __FieldVisitor;
            impl<'de> _serde::de::Visitor<'de> for __FieldVisitor {
                type Value = __Field;
                fn expecting(
                    &self,
                    __formatter: &mut _serde::export::Formatter,
                ) -> _serde::export::fmt::Result {
                    _serde::export::Formatter::write_str(__formatter, "field identifier")
                }
                fn visit_u64<__E>(self, __value: u64) -> _serde::export::Result<Self::Value, __E>
                where
                    __E: _serde::de::Error,
                {
                    match __value {
                        0u64 => _serde::export::Ok(__Field::__field0),
                        1u64 => _serde::export::Ok(__Field::__field1),
                        2u64 => _serde::export::Ok(__Field::__field2),
                        _ => _serde::export::Err(_serde::de::Error::invalid_value(
                            _serde::de::Unexpected::Unsigned(__value),
                            &"field index 0 <= i < 3",
                        )),
                    }
                }
                fn visit_str<__E>(self, __value: &str) -> _serde::export::Result<Self::Value, __E>
                where
                    __E: _serde::de::Error,
                {
                    match __value {
                        "system" => _serde::export::Ok(__Field::__field0),
                        "balances" => _serde::export::Ok(__Field::__field1),
                        "sudo" => _serde::export::Ok(__Field::__field2),
                        _ => _serde::export::Err(_serde::de::Error::unknown_field(__value, FIELDS)),
                    }
                }
                fn visit_bytes<__E>(
                    self,
                    __value: &[u8],
                ) -> _serde::export::Result<Self::Value, __E>
                where
                    __E: _serde::de::Error,
                {
                    match __value {
                        b"system" => _serde::export::Ok(__Field::__field0),
                        b"balances" => _serde::export::Ok(__Field::__field1),
                        b"sudo" => _serde::export::Ok(__Field::__field2),
                        _ => {
                            let __value = &_serde::export::from_utf8_lossy(__value);
                            _serde::export::Err(_serde::de::Error::unknown_field(__value, FIELDS))
                        }
                    }
                }
            }
            impl<'de> _serde::Deserialize<'de> for __Field {
                #[inline]
                fn deserialize<__D>(__deserializer: __D) -> _serde::export::Result<Self, __D::Error>
                where
                    __D: _serde::Deserializer<'de>,
                {
                    _serde::Deserializer::deserialize_identifier(__deserializer, __FieldVisitor)
                }
            }
            struct __Visitor<'de> {
                marker: _serde::export::PhantomData<GenesisConfig>,
                lifetime: _serde::export::PhantomData<&'de ()>,
            }
            impl<'de> _serde::de::Visitor<'de> for __Visitor<'de> {
                type Value = GenesisConfig;
                fn expecting(
                    &self,
                    __formatter: &mut _serde::export::Formatter,
                ) -> _serde::export::fmt::Result {
                    _serde::export::Formatter::write_str(__formatter, "struct GenesisConfig")
                }
                #[inline]
                fn visit_seq<__A>(
                    self,
                    mut __seq: __A,
                ) -> _serde::export::Result<Self::Value, __A::Error>
                where
                    __A: _serde::de::SeqAccess<'de>,
                {
                    let __field0 = match match _serde::de::SeqAccess::next_element::<
                        Option<SystemConfig>,
                    >(&mut __seq)
                    {
                        _serde::export::Ok(__val) => __val,
                        _serde::export::Err(__err) => {
                            return _serde::export::Err(__err);
                        }
                    } {
                        _serde::export::Some(__value) => __value,
                        _serde::export::None => {
                            return _serde::export::Err(_serde::de::Error::invalid_length(
                                0usize,
                                &"struct GenesisConfig with 3 elements",
                            ));
                        }
                    };
                    let __field1 = match match _serde::de::SeqAccess::next_element::<
                        Option<BalancesConfig>,
                    >(&mut __seq)
                    {
                        _serde::export::Ok(__val) => __val,
                        _serde::export::Err(__err) => {
                            return _serde::export::Err(__err);
                        }
                    } {
                        _serde::export::Some(__value) => __value,
                        _serde::export::None => {
                            return _serde::export::Err(_serde::de::Error::invalid_length(
                                1usize,
                                &"struct GenesisConfig with 3 elements",
                            ));
                        }
                    };
                    let __field2 = match match _serde::de::SeqAccess::next_element::<
                        Option<SudoConfig>,
                    >(&mut __seq)
                    {
                        _serde::export::Ok(__val) => __val,
                        _serde::export::Err(__err) => {
                            return _serde::export::Err(__err);
                        }
                    } {
                        _serde::export::Some(__value) => __value,
                        _serde::export::None => {
                            return _serde::export::Err(_serde::de::Error::invalid_length(
                                2usize,
                                &"struct GenesisConfig with 3 elements",
                            ));
                        }
                    };
                    _serde::export::Ok(GenesisConfig {
                        system: __field0,
                        balances: __field1,
                        sudo: __field2,
                    })
                }
                #[inline]
                fn visit_map<__A>(
                    self,
                    mut __map: __A,
                ) -> _serde::export::Result<Self::Value, __A::Error>
                where
                    __A: _serde::de::MapAccess<'de>,
                {
                    let mut __field0: _serde::export::Option<Option<SystemConfig>> =
                        _serde::export::None;
                    let mut __field1: _serde::export::Option<Option<BalancesConfig>> =
                        _serde::export::None;
                    let mut __field2: _serde::export::Option<Option<SudoConfig>> =
                        _serde::export::None;
                    while let _serde::export::Some(__key) =
                        match _serde::de::MapAccess::next_key::<__Field>(&mut __map) {
                            _serde::export::Ok(__val) => __val,
                            _serde::export::Err(__err) => {
                                return _serde::export::Err(__err);
                            }
                        }
                    {
                        match __key {
                            __Field::__field0 => {
                                if _serde::export::Option::is_some(&__field0) {
                                    return _serde::export::Err(
                                        <__A::Error as _serde::de::Error>::duplicate_field(
                                            "system",
                                        ),
                                    );
                                }
                                __field0 = _serde::export::Some(
                                    match _serde::de::MapAccess::next_value::<Option<SystemConfig>>(
                                        &mut __map,
                                    ) {
                                        _serde::export::Ok(__val) => __val,
                                        _serde::export::Err(__err) => {
                                            return _serde::export::Err(__err);
                                        }
                                    },
                                );
                            }
                            __Field::__field1 => {
                                if _serde::export::Option::is_some(&__field1) {
                                    return _serde::export::Err(
                                        <__A::Error as _serde::de::Error>::duplicate_field(
                                            "balances",
                                        ),
                                    );
                                }
                                __field1 = _serde::export::Some(
                                    match _serde::de::MapAccess::next_value::<Option<BalancesConfig>>(
                                        &mut __map,
                                    ) {
                                        _serde::export::Ok(__val) => __val,
                                        _serde::export::Err(__err) => {
                                            return _serde::export::Err(__err);
                                        }
                                    },
                                );
                            }
                            __Field::__field2 => {
                                if _serde::export::Option::is_some(&__field2) {
                                    return _serde::export::Err(
                                        <__A::Error as _serde::de::Error>::duplicate_field("sudo"),
                                    );
                                }
                                __field2 = _serde::export::Some(
                                    match _serde::de::MapAccess::next_value::<Option<SudoConfig>>(
                                        &mut __map,
                                    ) {
                                        _serde::export::Ok(__val) => __val,
                                        _serde::export::Err(__err) => {
                                            return _serde::export::Err(__err);
                                        }
                                    },
                                );
                            }
                        }
                    }
                    let __field0 = match __field0 {
                        _serde::export::Some(__field0) => __field0,
                        _serde::export::None => {
                            match _serde::private::de::missing_field("system") {
                                _serde::export::Ok(__val) => __val,
                                _serde::export::Err(__err) => {
                                    return _serde::export::Err(__err);
                                }
                            }
                        }
                    };
                    let __field1 = match __field1 {
                        _serde::export::Some(__field1) => __field1,
                        _serde::export::None => {
                            match _serde::private::de::missing_field("balances") {
                                _serde::export::Ok(__val) => __val,
                                _serde::export::Err(__err) => {
                                    return _serde::export::Err(__err);
                                }
                            }
                        }
                    };
                    let __field2 = match __field2 {
                        _serde::export::Some(__field2) => __field2,
                        _serde::export::None => match _serde::private::de::missing_field("sudo") {
                            _serde::export::Ok(__val) => __val,
                            _serde::export::Err(__err) => {
                                return _serde::export::Err(__err);
                            }
                        },
                    };
                    _serde::export::Ok(GenesisConfig {
                        system: __field0,
                        balances: __field1,
                        sudo: __field2,
                    })
                }
            }
            const FIELDS: &'static [&'static str] = &["system", "balances", "sudo"];
            _serde::Deserializer::deserialize_struct(
                __deserializer,
                "GenesisConfig",
                FIELDS,
                __Visitor {
                    marker: _serde::export::PhantomData::<GenesisConfig>,
                    lifetime: _serde::export::PhantomData,
                },
            )
        }
    }
};
#[cfg(any(feature = "std", test))]
impl ::sp_runtime::BuildStorage for GenesisConfig {
    fn assimilate_storage(
        &self,
        storage: &mut ::sp_runtime::Storage,
    ) -> std::result::Result<(), String> {
        if let Some(ref extra) = self.system {
            :: sp_runtime :: BuildModuleGenesisStorage :: < Runtime , system :: __InherentHiddenInstance > :: build_module_genesis_storage ( extra , storage ) ? ;
        }
        if let Some(ref extra) = self.balances {
            :: sp_runtime :: BuildModuleGenesisStorage :: < Runtime , balances :: __InherentHiddenInstance > :: build_module_genesis_storage ( extra , storage ) ? ;
        }
        if let Some(ref extra) = self.sudo {
            :: sp_runtime :: BuildModuleGenesisStorage :: < Runtime , sudo :: __InherentHiddenInstance > :: build_module_genesis_storage ( extra , storage ) ? ;
        }
        Ok(())
    }
}
trait InherentDataExt {
    fn create_extrinsics(
        &self,
    ) -> ::frame_support::inherent::Vec<<Block as ::frame_support::inherent::BlockT>::Extrinsic>;
    fn check_extrinsics(&self, block: &Block) -> ::frame_support::inherent::CheckInherentsResult;
}
impl InherentDataExt for ::frame_support::inherent::InherentData {
    fn create_extrinsics(
        &self,
    ) -> ::frame_support::inherent::Vec<<Block as ::frame_support::inherent::BlockT>::Extrinsic>
    {
        use ::frame_support::inherent::ProvideInherent;
        use ::frame_support::inherent::Extrinsic;
        let mut inherents = Vec::new();
        if let Some(inherent) = Timestamp::create_inherent(self) {
            inherents.push(
                UncheckedExtrinsic::new(Call::Timestamp(inherent), None).expect(
                    "Runtime UncheckedExtrinsic is not Opaque, so it has to return `Some`; qed",
                ),
            );
        }
        inherents
    }
    fn check_extrinsics(&self, block: &Block) -> ::frame_support::inherent::CheckInherentsResult {
        use ::frame_support::inherent::{ProvideInherent, IsFatalError};
        let mut result = ::frame_support::inherent::CheckInherentsResult::new();
        for xt in block.extrinsics() {
            if ::frame_support::inherent::Extrinsic::is_signed(xt).unwrap_or(false) {
                break;
            }
            match xt.function {
                Call::Timestamp(ref call) => {
                    if let Err(e) = Timestamp::check_inherent(call, self) {
                        result
                            .put_error(Timestamp::INHERENT_IDENTIFIER, &e)
                            .expect("There is only one fatal error; qed");
                        if e.is_fatal_error() {
                            return result;
                        }
                    }
                }
                _ => {}
            }
        }
        result
    }
}
impl ::frame_support::unsigned::ValidateUnsigned for Runtime {
    type Call = Call;
    fn pre_dispatch(
        call: &Self::Call,
    ) -> Result<(), ::frame_support::unsigned::TransactionValidityError> {
        #[allow(unreachable_patterns)]
        match call {
            _ => Ok(()),
        }
    }
    fn validate_unsigned(
        #[allow(unused_variables)] source: ::frame_support::unsigned::TransactionSource,
        call: &Self::Call,
    ) -> ::frame_support::unsigned::TransactionValidity {
        #[allow(unreachable_patterns)]
        match call {
            _ => ::frame_support::unsigned::UnknownTransaction::NoUnsignedValidator.into(),
        }
    }
}
/// The address format for describing accounts.
pub type Address = AccountId;
/// Block header type as expected by this runtime.
pub type Header = generic::Header<BlockNumber, BlakeTwo256>;
/// Block type as expected by this runtime.
pub type Block = generic::Block<Header, UncheckedExtrinsic>;
/// A Block signed with a Justification
pub type SignedBlock = generic::SignedBlock<Block>;
/// BlockId type as expected by this runtime.
pub type BlockId = generic::BlockId<Block>;
/// The SignedExtension to the basic transaction logic.
pub type SignedExtra = (
    system::CheckVersion<Runtime>,
    system::CheckGenesis<Runtime>,
    system::CheckEra<Runtime>,
    system::CheckNonce<Runtime>,
    system::CheckWeight<Runtime>,
    transaction_payment::ChargeTransactionPayment<Runtime>,
);
/// Unchecked extrinsic type as expected by this runtime.
pub type UncheckedExtrinsic = generic::UncheckedExtrinsic<Address, Call, Signature, SignedExtra>;
/// Extrinsic type that has already been checked.
pub type CheckedExtrinsic = generic::CheckedExtrinsic<AccountId, Call, SignedExtra>;
/// Executive: handles dispatch to the various modules.
pub type Executive =
    frame_executive::Executive<Runtime, Block, system::ChainContext<Runtime>, Runtime, AllModules>;
#[doc(hidden)]
mod sp_api_hidden_includes_IMPL_RUNTIME_APIS {
    pub extern crate sp_api as sp_api;
}
pub struct RuntimeApi {}
/// Implements all runtime apis for the client side.
#[cfg(any(feature = "std", test))]
pub struct RuntimeApiImpl<
    Block: self::sp_api_hidden_includes_IMPL_RUNTIME_APIS::sp_api::BlockT,
    C: self::sp_api_hidden_includes_IMPL_RUNTIME_APIS::sp_api::CallApiAt<Block> + 'static,
> where
    C::StateBackend: self::sp_api_hidden_includes_IMPL_RUNTIME_APIS::sp_api::StateBackend<
        self::sp_api_hidden_includes_IMPL_RUNTIME_APIS::sp_api::HashFor<Block>,
    >,
{
    call: &'static C,
    commit_on_success: std::cell::RefCell<bool>,
    initialized_block: std::cell::RefCell<
        Option<self::sp_api_hidden_includes_IMPL_RUNTIME_APIS::sp_api::BlockId<Block>>,
    >,
    changes: std::cell::RefCell<
        self::sp_api_hidden_includes_IMPL_RUNTIME_APIS::sp_api::OverlayedChanges,
    >,
    storage_transaction_cache: std::cell::RefCell<
        self::sp_api_hidden_includes_IMPL_RUNTIME_APIS::sp_api::StorageTransactionCache<
            Block,
            C::StateBackend,
        >,
    >,
    recorder: Option<self::sp_api_hidden_includes_IMPL_RUNTIME_APIS::sp_api::ProofRecorder<Block>>,
}
#[cfg(any(feature = "std", test))]
unsafe impl<
        Block: self::sp_api_hidden_includes_IMPL_RUNTIME_APIS::sp_api::BlockT,
        C: self::sp_api_hidden_includes_IMPL_RUNTIME_APIS::sp_api::CallApiAt<Block>,
    > Send for RuntimeApiImpl<Block, C>
where
    C::StateBackend: self::sp_api_hidden_includes_IMPL_RUNTIME_APIS::sp_api::StateBackend<
        self::sp_api_hidden_includes_IMPL_RUNTIME_APIS::sp_api::HashFor<Block>,
    >,
{
}
#[cfg(any(feature = "std", test))]
unsafe impl<
        Block: self::sp_api_hidden_includes_IMPL_RUNTIME_APIS::sp_api::BlockT,
        C: self::sp_api_hidden_includes_IMPL_RUNTIME_APIS::sp_api::CallApiAt<Block>,
    > Sync for RuntimeApiImpl<Block, C>
where
    C::StateBackend: self::sp_api_hidden_includes_IMPL_RUNTIME_APIS::sp_api::StateBackend<
        self::sp_api_hidden_includes_IMPL_RUNTIME_APIS::sp_api::HashFor<Block>,
    >,
{
}
#[cfg(any(feature = "std", test))]
impl<
        Block: self::sp_api_hidden_includes_IMPL_RUNTIME_APIS::sp_api::BlockT,
        C: self::sp_api_hidden_includes_IMPL_RUNTIME_APIS::sp_api::CallApiAt<Block>,
    > self::sp_api_hidden_includes_IMPL_RUNTIME_APIS::sp_api::ApiErrorExt
    for RuntimeApiImpl<Block, C>
where
    C::StateBackend: self::sp_api_hidden_includes_IMPL_RUNTIME_APIS::sp_api::StateBackend<
        self::sp_api_hidden_includes_IMPL_RUNTIME_APIS::sp_api::HashFor<Block>,
    >,
{
    type Error = C::Error;
}
#[cfg(any(feature = "std", test))]
impl<
        Block: self::sp_api_hidden_includes_IMPL_RUNTIME_APIS::sp_api::BlockT,
        C: self::sp_api_hidden_includes_IMPL_RUNTIME_APIS::sp_api::CallApiAt<Block>,
    > self::sp_api_hidden_includes_IMPL_RUNTIME_APIS::sp_api::ApiExt<Block>
    for RuntimeApiImpl<Block, C>
where
    C::StateBackend: self::sp_api_hidden_includes_IMPL_RUNTIME_APIS::sp_api::StateBackend<
        self::sp_api_hidden_includes_IMPL_RUNTIME_APIS::sp_api::HashFor<Block>,
    >,
{
    type StateBackend = C::StateBackend;
    fn map_api_result<F: FnOnce(&Self) -> std::result::Result<R, E>, R, E>(
        &self,
        map_call: F,
    ) -> std::result::Result<R, E>
    where
        Self: Sized,
    {
        *self.commit_on_success.borrow_mut() = false;
        let res = map_call(self);
        *self.commit_on_success.borrow_mut() = true;
        self.commit_on_ok(&res);
        res
    }
    fn has_api<A: self::sp_api_hidden_includes_IMPL_RUNTIME_APIS::sp_api::RuntimeApiInfo + ?Sized>(
        &self,
        at: &self::sp_api_hidden_includes_IMPL_RUNTIME_APIS::sp_api::BlockId<Block>,
    ) -> std::result::Result<bool, C::Error>
    where
        Self: Sized,
    {
        self.call
            .runtime_version_at(at)
            .map(|v| v.has_api_with(&A::ID, |v| v == A::VERSION))
    }
    fn has_api_with<
        A: self::sp_api_hidden_includes_IMPL_RUNTIME_APIS::sp_api::RuntimeApiInfo + ?Sized,
        P: Fn(u32) -> bool,
    >(
        &self,
        at: &self::sp_api_hidden_includes_IMPL_RUNTIME_APIS::sp_api::BlockId<Block>,
        pred: P,
    ) -> std::result::Result<bool, C::Error>
    where
        Self: Sized,
    {
        self.call
            .runtime_version_at(at)
            .map(|v| v.has_api_with(&A::ID, pred))
    }
    fn record_proof(&mut self) {
        self.recorder = Some(Default::default());
    }
    fn extract_proof(
        &mut self,
    ) -> Option<self::sp_api_hidden_includes_IMPL_RUNTIME_APIS::sp_api::StorageProof> {
        self.recorder.take().map(|recorder| {
            let trie_nodes = recorder
                .read()
                .iter()
                .filter_map(|(_k, v)| v.as_ref().map(|v| v.to_vec()))
                .collect();
            self::sp_api_hidden_includes_IMPL_RUNTIME_APIS::sp_api::StorageProof::new(trie_nodes)
        })
    }
    fn into_storage_changes(
        &self,
        backend: &Self::StateBackend,
        changes_trie_state: Option<
            &self::sp_api_hidden_includes_IMPL_RUNTIME_APIS::sp_api::ChangesTrieState<
                self::sp_api_hidden_includes_IMPL_RUNTIME_APIS::sp_api::HashFor<Block>,
                self::sp_api_hidden_includes_IMPL_RUNTIME_APIS::sp_api::NumberFor<Block>,
            >,
        >,
        parent_hash: Block::Hash,
    ) -> std::result::Result<
        self::sp_api_hidden_includes_IMPL_RUNTIME_APIS::sp_api::StorageChanges<
            Self::StateBackend,
            Block,
        >,
        String,
    >
    where
        Self: Sized,
    {
        self.initialized_block.borrow_mut().take();
        self.changes
            .replace(Default::default())
            .into_storage_changes(
                backend,
                changes_trie_state,
                parent_hash,
                self.storage_transaction_cache.replace(Default::default()),
            )
    }
}
#[cfg(any(feature = "std", test))]
impl<Block: self::sp_api_hidden_includes_IMPL_RUNTIME_APIS::sp_api::BlockT, C>
    self::sp_api_hidden_includes_IMPL_RUNTIME_APIS::sp_api::ConstructRuntimeApi<Block, C>
    for RuntimeApi
where
    C: self::sp_api_hidden_includes_IMPL_RUNTIME_APIS::sp_api::CallApiAt<Block> + 'static,
    C::StateBackend: self::sp_api_hidden_includes_IMPL_RUNTIME_APIS::sp_api::StateBackend<
        self::sp_api_hidden_includes_IMPL_RUNTIME_APIS::sp_api::HashFor<Block>,
    >,
{
    type RuntimeApi = RuntimeApiImpl<Block, C>;
    fn construct_runtime_api<'a>(
        call: &'a C,
    ) -> self::sp_api_hidden_includes_IMPL_RUNTIME_APIS::sp_api::ApiRef<'a, Self::RuntimeApi> {
        RuntimeApiImpl {
            call: unsafe { std::mem::transmute(call) },
            commit_on_success: true.into(),
            initialized_block: None.into(),
            changes: Default::default(),
            recorder: Default::default(),
            storage_transaction_cache: Default::default(),
        }
        .into()
    }
}
#[cfg(any(feature = "std", test))]
impl<
        Block: self::sp_api_hidden_includes_IMPL_RUNTIME_APIS::sp_api::BlockT,
        C: self::sp_api_hidden_includes_IMPL_RUNTIME_APIS::sp_api::CallApiAt<Block>,
    > RuntimeApiImpl<Block, C>
where
    C::StateBackend: self::sp_api_hidden_includes_IMPL_RUNTIME_APIS::sp_api::StateBackend<
        self::sp_api_hidden_includes_IMPL_RUNTIME_APIS::sp_api::HashFor<Block>,
    >,
{
    fn call_api_at<
        R: self::sp_api_hidden_includes_IMPL_RUNTIME_APIS::sp_api::Encode
            + self::sp_api_hidden_includes_IMPL_RUNTIME_APIS::sp_api::Decode
            + PartialEq,
        F: FnOnce(
            &C,
            &Self,
            &std::cell::RefCell<
                self::sp_api_hidden_includes_IMPL_RUNTIME_APIS::sp_api::OverlayedChanges,
            >,
            &std::cell::RefCell<
                self::sp_api_hidden_includes_IMPL_RUNTIME_APIS::sp_api::StorageTransactionCache<
                    Block,
                    C::StateBackend,
                >,
            >,
            &std::cell::RefCell<
                Option<self::sp_api_hidden_includes_IMPL_RUNTIME_APIS::sp_api::BlockId<Block>>,
            >,
            &Option<self::sp_api_hidden_includes_IMPL_RUNTIME_APIS::sp_api::ProofRecorder<Block>>,
        ) -> std::result::Result<
            self::sp_api_hidden_includes_IMPL_RUNTIME_APIS::sp_api::NativeOrEncoded<R>,
            E,
        >,
        E,
    >(
        &self,
        call_api_at: F,
    ) -> std::result::Result<
        self::sp_api_hidden_includes_IMPL_RUNTIME_APIS::sp_api::NativeOrEncoded<R>,
        E,
    > {
        let res = call_api_at(
            &self.call,
            self,
            &self.changes,
            &self.storage_transaction_cache,
            &self.initialized_block,
            &self.recorder,
        );
        self.commit_on_ok(&res);
        res
    }
    fn commit_on_ok<R, E>(&self, res: &std::result::Result<R, E>) {
        if *self.commit_on_success.borrow() {
            if res.is_err() {
                self.changes.borrow_mut().discard_prospective();
            } else {
                self.changes.borrow_mut().commit_prospective();
            }
        }
    }
}
impl sp_api::runtime_decl_for_Core::Core<Block> for Runtime {
    fn version() -> RuntimeVersion {
        VERSION
    }
    fn execute_block(block: Block) {
        Executive::execute_block(block)
    }
    fn initialize_block(header: &<Block as BlockT>::Header) {
        Executive::initialize_block(header)
    }
}
#[cfg(any(feature = "std", test))]
impl<
        __SR_API_BLOCK__: self::sp_api_hidden_includes_IMPL_RUNTIME_APIS::sp_api::BlockT
            + std::panic::UnwindSafe
            + std::panic::RefUnwindSafe,
        RuntimeApiImplCall: self::sp_api_hidden_includes_IMPL_RUNTIME_APIS::sp_api::CallApiAt<__SR_API_BLOCK__>
            + 'static,
    > sp_api::Core<__SR_API_BLOCK__> for RuntimeApiImpl<__SR_API_BLOCK__, RuntimeApiImplCall>
where
    RuntimeApiImplCall::StateBackend:
        self::sp_api_hidden_includes_IMPL_RUNTIME_APIS::sp_api::StateBackend<
            self::sp_api_hidden_includes_IMPL_RUNTIME_APIS::sp_api::HashFor<__SR_API_BLOCK__>,
        >,
    RuntimeVersion: std::panic::UnwindSafe + std::panic::RefUnwindSafe,
    __SR_API_BLOCK__: std::panic::UnwindSafe + std::panic::RefUnwindSafe,
    <__SR_API_BLOCK__ as BlockT>::Header: std::panic::UnwindSafe + std::panic::RefUnwindSafe,
    __SR_API_BLOCK__::Header: std::panic::UnwindSafe + std::panic::RefUnwindSafe,
{
    fn Core_version_runtime_api_impl(
        &self,
        at: &self::sp_api_hidden_includes_IMPL_RUNTIME_APIS::sp_api::BlockId<__SR_API_BLOCK__>,
        context: self::sp_api_hidden_includes_IMPL_RUNTIME_APIS::sp_api::ExecutionContext,
        params: Option<()>,
        params_encoded: Vec<u8>,
    ) -> std::result::Result<
        self::sp_api_hidden_includes_IMPL_RUNTIME_APIS::sp_api::NativeOrEncoded<RuntimeVersion>,
        RuntimeApiImplCall::Error,
    > {
        self.call_api_at(
            |call_runtime_at,
             core_api,
             changes,
             storage_transaction_cache,
             initialized_block,
             recorder| {
                sp_api::runtime_decl_for_Core::version_call_api_at(
                    call_runtime_at,
                    core_api,
                    at,
                    params_encoded,
                    changes,
                    storage_transaction_cache,
                    initialized_block,
                    params.map(|p| {
                        sp_api::runtime_decl_for_Core::version_native_call_generator::<
                            Runtime,
                            __SR_API_BLOCK__,
                            Block,
                        >()
                    }),
                    context,
                    recorder,
                )
            },
        )
    }
    fn Core_execute_block_runtime_api_impl(
        &self,
        at: &self::sp_api_hidden_includes_IMPL_RUNTIME_APIS::sp_api::BlockId<__SR_API_BLOCK__>,
        context: self::sp_api_hidden_includes_IMPL_RUNTIME_APIS::sp_api::ExecutionContext,
        params: Option<(__SR_API_BLOCK__)>,
        params_encoded: Vec<u8>,
    ) -> std::result::Result<
        self::sp_api_hidden_includes_IMPL_RUNTIME_APIS::sp_api::NativeOrEncoded<()>,
        RuntimeApiImplCall::Error,
    > {
        self.call_api_at(
            |call_runtime_at,
             core_api,
             changes,
             storage_transaction_cache,
             initialized_block,
             recorder| {
                sp_api::runtime_decl_for_Core::execute_block_call_api_at(
                    call_runtime_at,
                    core_api,
                    at,
                    params_encoded,
                    changes,
                    storage_transaction_cache,
                    initialized_block,
                    params.map(|p| {
                        sp_api::runtime_decl_for_Core::execute_block_native_call_generator::<
                            Runtime,
                            __SR_API_BLOCK__,
                            Block,
                        >(p)
                    }),
                    context,
                    recorder,
                )
            },
        )
    }
    fn Core_initialize_block_runtime_api_impl(
        &self,
        at: &self::sp_api_hidden_includes_IMPL_RUNTIME_APIS::sp_api::BlockId<__SR_API_BLOCK__>,
        context: self::sp_api_hidden_includes_IMPL_RUNTIME_APIS::sp_api::ExecutionContext,
        params: Option<(&<__SR_API_BLOCK__ as BlockT>::Header)>,
        params_encoded: Vec<u8>,
    ) -> std::result::Result<
        self::sp_api_hidden_includes_IMPL_RUNTIME_APIS::sp_api::NativeOrEncoded<()>,
        RuntimeApiImplCall::Error,
    > {
        self.call_api_at(
            |call_runtime_at,
             core_api,
             changes,
             storage_transaction_cache,
             initialized_block,
             recorder| {
                sp_api::runtime_decl_for_Core::initialize_block_call_api_at(
                    call_runtime_at,
                    core_api,
                    at,
                    params_encoded,
                    changes,
                    storage_transaction_cache,
                    initialized_block,
                    params.map(|p| {
                        sp_api::runtime_decl_for_Core::initialize_block_native_call_generator::<
                            Runtime,
                            __SR_API_BLOCK__,
                            Block,
                        >(p)
                    }),
                    context,
                    recorder,
                )
            },
        )
    }
}
const RUNTIME_API_VERSIONS: self::sp_api_hidden_includes_IMPL_RUNTIME_APIS::sp_api::ApisVec =
    ::sp_version::sp_std::borrow::Cow::Borrowed(&[(
        sp_api::runtime_decl_for_Core::ID,
        sp_api::runtime_decl_for_Core::VERSION,
    )]);
pub mod api {
    use super::*;
    #[cfg(feature = "std")]
    pub fn dispatch(method: &str, mut data: &[u8]) -> Option<Vec<u8>> {
        match method {
            "Core_version" => Some(
                self::sp_api_hidden_includes_IMPL_RUNTIME_APIS::sp_api::Encode::encode(&{
                    #[allow(deprecated)]
                    <Runtime as sp_api::runtime_decl_for_Core::Core<Block>>::version()
                }),
            ),
            "Core_execute_block" => {
                Some(
                    self::sp_api_hidden_includes_IMPL_RUNTIME_APIS::sp_api::Encode::encode(&{
                        let block : Block = match self :: sp_api_hidden_includes_IMPL_RUNTIME_APIS :: sp_api :: Decode :: decode ( & mut data ) { Ok ( input ) => input , Err ( e ) => { :: std :: rt :: begin_panic_fmt ( & :: core :: fmt :: Arguments :: new_v1 ( & [ "Bad input data provided to " , ": " ] , & match ( & "execute_block" , & e . what ( ) ) { ( arg0 , arg1 ) => [ :: core :: fmt :: ArgumentV1 :: new ( arg0 , :: core :: fmt :: Display :: fmt ) , :: core :: fmt :: ArgumentV1 :: new ( arg1 , :: core :: fmt :: Display :: fmt ) ] , } ) ) } } ;
                        #[allow(deprecated)]
                        <Runtime as sp_api::runtime_decl_for_Core::Core<Block>>::execute_block(
                            block,
                        )
                    }),
                )
            }
            "Core_initialize_block" => {
                Some(
                    self::sp_api_hidden_includes_IMPL_RUNTIME_APIS::sp_api::Encode::encode(&{
                        let header : < Block as BlockT > :: Header = match self :: sp_api_hidden_includes_IMPL_RUNTIME_APIS :: sp_api :: Decode :: decode ( & mut data ) { Ok ( input ) => input , Err ( e ) => { :: std :: rt :: begin_panic_fmt ( & :: core :: fmt :: Arguments :: new_v1 ( & [ "Bad input data provided to " , ": " ] , & match ( & "initialize_block" , & e . what ( ) ) { ( arg0 , arg1 ) => [ :: core :: fmt :: ArgumentV1 :: new ( arg0 , :: core :: fmt :: Display :: fmt ) , :: core :: fmt :: ArgumentV1 :: new ( arg1 , :: core :: fmt :: Display :: fmt ) ] , } ) ) } } ;
                        #[allow(deprecated)]
                        <Runtime as sp_api::runtime_decl_for_Core::Core<Block>>::initialize_block(
                            &header,
                        )
                    }),
                )
            }
            _ => None,
        }
    }
}
