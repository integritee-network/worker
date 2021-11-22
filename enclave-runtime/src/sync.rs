/*
	Copyright 2021 Integritee AG and Supercomputing Systems AG
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

//! Primitives to handle multithreaded state access in the enclave.
//!
//! Note: In general the design should try to minimize usage of these, as potential deadlocks can
//! occur. Documentation of the `SgxRwLock` says that panics __might__ occur when trying to acquire
//! a lock multiple times in the same thread. However, tests have shown that it also might result in
//! a deadlock.
//!
//! @clangenb: Does currently not see any way to entirely get rid of these synchronization
//! primitives because we can only start new threads from the untrusted side. `parking_lot` would be
//! an alternative to consider for the primitives. It has several performance and ergonomic benefits
//! over the `std` lib's. One of the benefits would be compile-time deadlock detection (experimental).
//! Unfortunately, it would need to be ported to SGX.
//!
//! `https://amanieu.github.io/parking_lot/parking_lot/index.html`

use crate::error::{Error, Result as EnclaveResult};
use lazy_static::lazy_static;
use std::sync::{SgxRwLock, SgxRwLockReadGuard, SgxRwLockWriteGuard};

lazy_static! {
	pub static ref SIDECHAIN_DB_LOCK: SgxRwLock<()> = Default::default();
}

pub struct EnclaveLock;

impl SidechainRwLock for EnclaveLock {
	fn read_sidechain_db() -> EnclaveResult<SgxRwLockReadGuard<'static, ()>> {
		SIDECHAIN_DB_LOCK.read().map_err(|e| Error::Other(e.into()))
	}

	fn write_sidechain_db() -> EnclaveResult<SgxRwLockWriteGuard<'static, ()>> {
		SIDECHAIN_DB_LOCK.write().map_err(|e| Error::Other(e.into()))
	}
}

pub trait SidechainRwLock {
	fn read_sidechain_db() -> EnclaveResult<SgxRwLockReadGuard<'static, ()>>;
	fn write_sidechain_db() -> EnclaveResult<SgxRwLockWriteGuard<'static, ()>>;
}

// simple type defs to prevent too long names
type AggregatedReadGuards<'a> = SgxRwLockReadGuard<'a, ()>;
type AggregatedWriteGuards<'a> = SgxRwLockWriteGuard<'a, ()>;

/// Useful, if all state must be accessed. Reduces the number of lines.
pub trait EnclaveStateRWLock: SidechainRwLock {
	/// return read locks of all enclave states
	fn read_all() -> EnclaveResult<AggregatedReadGuards<'static>>;

	/// return write locks of all enclave states
	fn write_all() -> EnclaveResult<AggregatedWriteGuards<'static>>;
}

impl<T: SidechainRwLock> EnclaveStateRWLock for T {
	fn read_all() -> EnclaveResult<AggregatedReadGuards<'static>> {
		Self::read_sidechain_db()
	}

	fn write_all() -> EnclaveResult<AggregatedWriteGuards<'static>> {
		Self::write_sidechain_db()
	}
}

#[cfg(feature = "test")]
pub mod tests {
	use super::*;
	pub fn sidechain_rw_lock_works() {
		drop(EnclaveLock::read_sidechain_db().unwrap());
		drop(EnclaveLock::write_sidechain_db().unwrap());

		let x1 = EnclaveLock::read_sidechain_db().unwrap();
		let x2 = EnclaveLock::read_sidechain_db().unwrap();

		drop((x1, x2));
		drop(EnclaveLock::write_sidechain_db().unwrap())
	}

	pub fn enclave_rw_lock_works() {
		drop(EnclaveLock::read_all().unwrap());
		drop(EnclaveLock::write_all().unwrap());

		let x1 = EnclaveLock::read_all().unwrap();
		let x2 = EnclaveLock::read_all().unwrap();

		drop((x1, x2));
		drop(EnclaveLock::write_all().unwrap())
	}
}
