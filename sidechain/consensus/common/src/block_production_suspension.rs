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

//! Mechanisms to (temporarily) suspend the production of sidechain blocks.

#[cfg(feature = "sgx")]
use std::sync::SgxRwLock as RwLock;

#[cfg(feature = "std")]
use std::sync::RwLock;

use crate::error::{Error, Result};
use log::*;

/// Trait to suspend the production of sidechain blocks.
pub trait SuspendBlockProduction {
	/// Suspend any sidechain block production.
	fn suspend_for_sync(&self) -> Result<()>;

	/// Resume block sidechain block production.
	fn resume(&self) -> Result<()>;
}

/// Trait to query if sidechain block production is suspended.
pub trait IsBlockProductionSuspended {
	fn is_suspended(&self) -> Result<bool>;

	fn is_sync_ongoing(&self) -> Result<bool>;
}

/// Implementation for suspending and resuming sidechain block production.
#[derive(Default)]
pub struct BlockProductionSuspender {
	is_suspended: RwLock<bool>,
	sync_is_ongoing: RwLock<bool>,
}

impl BlockProductionSuspender {
	pub fn new(is_suspended: bool) -> Self {
		BlockProductionSuspender {
			is_suspended: RwLock::new(is_suspended),
			sync_is_ongoing: RwLock::new(false),
		}
	}
}

impl SuspendBlockProduction for BlockProductionSuspender {
	fn suspend_for_sync(&self) -> Result<()> {
		let mut suspended_lock = self.is_suspended.write().map_err(|_| Error::LockPoisoning)?;
		*suspended_lock = true;

		let mut sync_is_ongoing_lock =
			self.sync_is_ongoing.write().map_err(|_| Error::LockPoisoning)?;
		*sync_is_ongoing_lock = true;

		info!("Suspend sidechain block production");
		Ok(())
	}

	fn resume(&self) -> Result<()> {
		let mut suspended_lock = self.is_suspended.write().map_err(|_| Error::LockPoisoning)?;
		*suspended_lock = false;
		info!("Resume sidechain block production");
		Ok(())
	}
}

impl IsBlockProductionSuspended for BlockProductionSuspender {
	fn is_suspended(&self) -> Result<bool> {
		Ok(*self.is_suspended.read().map_err(|_| Error::LockPoisoning)?)
	}

	fn is_sync_ongoing(&self) -> Result<bool> {
		Ok(*self.sync_is_ongoing.read().map_err(|_| Error::LockPoisoning)?)
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn initial_production_is_not_suspended() {
		let block_production_suspender = BlockProductionSuspender::default();
		assert!(!block_production_suspender.is_suspended().unwrap());
	}

	#[test]
	fn suspending_production_works() {
		let block_production_suspender = BlockProductionSuspender::default();

		block_production_suspender.suspend_for_sync().unwrap();
		assert!(block_production_suspender.is_suspended().unwrap());

		block_production_suspender.resume().unwrap();
		assert!(!block_production_suspender.is_suspended().unwrap());
	}
}
