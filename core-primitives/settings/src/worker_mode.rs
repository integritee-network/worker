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

#[derive(Eq, PartialEq, Debug, Clone)]
pub enum WorkerMode {
	OffChainWorker,
	Sidechain,
	Teeracle,
}

pub trait ProvideWorkerMode {
	fn worker_mode() -> WorkerMode;
}

#[derive(Default, Copy, Clone)]
pub struct WorkerModeProvider;

#[cfg(feature = "offchain-worker")]
impl ProvideWorkerMode for WorkerModeProvider {
	fn worker_mode() -> WorkerMode {
		WorkerMode::OffChainWorker
	}
}

#[cfg(feature = "teeracle")]
impl ProvideWorkerMode for WorkerModeProvider {
	fn worker_mode() -> WorkerMode {
		WorkerMode::Teeracle
	}
}

#[cfg(feature = "sidechain")]
impl ProvideWorkerMode for WorkerModeProvider {
	fn worker_mode() -> WorkerMode {
		WorkerMode::Sidechain
	}
}

// Default to `Sidechain` worker mode when no cargo features are set.
#[cfg(not(any(feature = "sidechain", feature = "teeracle", feature = "offchain-worker")))]
impl ProvideWorkerMode for WorkerModeProvider {
	fn worker_mode() -> WorkerMode {
		WorkerMode::Sidechain
	}
}
