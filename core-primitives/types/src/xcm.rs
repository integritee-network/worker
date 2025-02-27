// Copyright (C) Parity Technologies (UK) Ltd.
// This file is part of Polkadot.

// Polkadot is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

// Polkadot is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.

// You should have received a copy of the GNU General Public License
// along with Polkadot.  If not, see <http://www.gnu.org/licenses/>.

// this is a backport of XCMv4 types

use codec::{Decode, Encode};
use sp_std::sync::Arc;

/// XCMv5 Junctions
#[derive(Encode, Decode, Debug, Clone)]
pub struct Location {
	/// The number of parent junctions at the beginning of this `Location`.
	pub parents: u8,
	/// The interior (i.e. non-parent) junctions that this `Location` contains.
	pub interior: Junctions,
}

impl Default for Location {
	fn default() -> Self {
		Self { parents: 0, interior: Junctions::Here }
	}
}

#[derive(Encode, Decode, Debug, Clone)]
/// XCMv4 Junctions
pub enum Junctions {
	/// The interpreting consensus system.
	Here,
	/// A relative path comprising 1 junction.
	X1(Arc<[Junction; 1]>),
	/// A relative path comprising 2 junctions.
	X2(Arc<[Junction; 2]>),
	/// A relative path comprising 3 junctions.
	X3(Arc<[Junction; 3]>),
	/// A relative path comprising 4 junctions.
	X4(Arc<[Junction; 4]>),
	/// A relative path comprising 5 junctions.
	X5(Arc<[Junction; 5]>),
	/// A relative path comprising 6 junctions.
	X6(Arc<[Junction; 6]>),
	/// A relative path comprising 7 junctions.
	X7(Arc<[Junction; 7]>),
	/// A relative path comprising 8 junctions.
	X8(Arc<[Junction; 8]>),
}

/// XCMv4 Junction
#[derive(Encode, Decode, Debug)]
pub enum Junction {
	/// An indexed parachain belonging to and operated by the context.
	///
	/// Generally used when the context is a Polkadot Relay-chain.
	Parachain(#[codec(compact)] u32),
	/// A 32-byte identifier for an account of a specific network that is respected as a sovereign
	/// endpoint within the context.
	///
	/// Generally used when the context is a Substrate-based chain.
	AccountId32 { network: Option<NetworkId>, id: [u8; 32] },
	/// An 8-byte index for an account of a specific network that is respected as a sovereign
	/// endpoint within the context.
	///
	/// May be used when the context is a Frame-based chain and includes e.g. an indices pallet.
	AccountIndex64 {
		network: Option<NetworkId>,
		#[codec(compact)]
		index: u64,
	},
	/// A 20-byte identifier for an account of a specific network that is respected as a sovereign
	/// endpoint within the context.
	///
	/// May be used when the context is an Ethereum or Bitcoin chain or smart-contract.
	AccountKey20 { network: Option<NetworkId>, key: [u8; 20] },
	/// An instanced, indexed pallet that forms a constituent part of the context.
	///
	/// Generally used when the context is a Frame-based chain.
	PalletInstance(u8),
	/// A non-descript index within the context location.
	///
	/// Usage will vary widely owing to its generality.
	///
	/// NOTE: Try to avoid using this and instead use a more specific item.
	GeneralIndex(#[codec(compact)] u128),
	/// A nondescript array datum, 32 bytes, acting as a key within the context
	/// location.
	///
	/// Usage will vary widely owing to its generality.
	///
	/// NOTE: Try to avoid using this and instead use a more specific item.
	// Note this is implemented as an array with a length rather than using `BoundedVec` owing to
	// the bound for `Copy`.
	GeneralKey { length: u8, data: [u8; 32] },
	/// The unambiguous child.
	///
	/// Not currently used except as a fallback when deriving context.
	OnlyChild,
	/// A pluralistic body existing within consensus.
	///
	/// Typical to be used to represent a governance origin of a chain, but could in principle be
	/// used to represent things such as multisigs also.
	Plurality { id: BodyId, part: BodyPart },
	/// A global network capable of externalizing its own consensus. This is not generally
	/// meaningful outside of the universal level.
	GlobalConsensus(NetworkId),
}

#[derive(Encode, Decode, Debug)]
pub enum NetworkId {
	/// Network specified by the first 32 bytes of its genesis block.
	ByGenesis([u8; 32]),
	/// Network defined by the first 32-bytes of the hash and number of some block it contains.
	ByFork { block_number: u64, block_hash: [u8; 32] },
	/// The Polkadot mainnet Relay-chain.
	Polkadot,
	/// The Kusama canary-net Relay-chain.
	Kusama,
	/// The Westend testnet Relay-chain.
	Westend,
	/// The Rococo testnet Relay-chain.
	Rococo,
	/// The Wococo testnet Relay-chain.
	Wococo,
	/// An Ethereum network specified by its chain ID.
	Ethereum {
		/// The EIP-155 chain ID.
		#[codec(compact)]
		chain_id: u64,
	},
	/// The Bitcoin network, including hard-forks supported by Bitcoin Core development team.
	BitcoinCore,
	/// The Bitcoin network, including hard-forks supported by Bitcoin Cash developers.
	BitcoinCash,
	/// The Polkadot Bulletin chain.
	PolkadotBulletin,
}

#[derive(Encode, Decode, Debug)]
pub enum BodyId {
	/// The only body in its context.
	Unit,
	/// A named body.
	Moniker([u8; 4]),
	/// An indexed body.
	Index(#[codec(compact)] u32),
	/// The unambiguous executive body (for Polkadot, this would be the Polkadot council).
	Executive,
	/// The unambiguous technical body (for Polkadot, this would be the Technical Committee).
	Technical,
	/// The unambiguous legislative body (for Polkadot, this could be considered the opinion of a
	/// majority of lock-voters).
	Legislative,
	/// The unambiguous judicial body (this doesn't exist on Polkadot, but if it were to get a
	/// "grand oracle", it may be considered as that).
	Judicial,
	/// The unambiguous defense body (for Polkadot, an opinion on the topic given via a public
	/// referendum on the `staking_admin` track).
	Defense,
	/// The unambiguous administration body (for Polkadot, an opinion on the topic given via a
	/// public referendum on the `general_admin` track).
	Administration,
	/// The unambiguous treasury body (for Polkadot, an opinion on the topic given via a public
	/// referendum on the `treasurer` track).
	Treasury,
}

#[derive(Encode, Decode, Debug)]
pub enum BodyPart {
	/// The body's declaration, under whatever means it decides.
	Voice,
	/// A given number of members of the body.
	Members {
		#[codec(compact)]
		count: u32,
	},
	/// A given number of members of the body, out of some larger caucus.
	Fraction {
		#[codec(compact)]
		nom: u32,
		#[codec(compact)]
		denom: u32,
	},
	/// No less than the given proportion of members of the body.
	AtLeastProportion {
		#[codec(compact)]
		nom: u32,
		#[codec(compact)]
		denom: u32,
	},
	/// More than the given proportion of members of the body.
	MoreThanProportion {
		#[codec(compact)]
		nom: u32,
		#[codec(compact)]
		denom: u32,
	},
}
