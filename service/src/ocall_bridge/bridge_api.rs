/*
	Copyright 2021 Integritee AG and Supercomputing Systems AG
	Copyright (C) 2017-2019 Baidu, Inc. All Rights Reserved.

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

use itp_enclave_api::remote_attestation::QveReport;
use lazy_static::lazy_static;
use log::*;
use parking_lot::RwLock;
use sgx_types::*;
use std::{sync::Arc, vec::Vec};

#[cfg(test)]
use mockall::predicate::*;
#[cfg(test)]
use mockall::*;

lazy_static! {
	/// global state for the component factory
	/// access is always routed through 'Bridge', do not use directly!
	static ref COMPONENT_FACTORY: RwLock<Option<Arc<dyn GetOCallBridgeComponents + Send + Sync>>> =
		RwLock::new(None);
}

/// The Bridge is the static/global interface to inject concrete implementations
/// (or rather the factories for them) - this is done at startup of the worker.
/// On the other side, it is used by the o-call FFI to retrieve the state and forward calls
/// to their respective implementation.
pub struct Bridge;

impl Bridge {
	pub fn get_ra_api() -> Arc<dyn RemoteAttestationBridge> {
		debug!("Requesting RemoteAttestation OCall API instance");

		COMPONENT_FACTORY
			.read()
			.as_ref()
			.expect("Component factory has not been set. Use `initialize()`")
			.get_ra_api()
	}

	pub fn get_sidechain_api() -> Arc<dyn SidechainBridge> {
		COMPONENT_FACTORY
			.read()
			.as_ref()
			.expect("Component factory has not been set. Use `initialize()`")
			.get_sidechain_api()
	}

	pub fn get_oc_api() -> Arc<dyn WorkerOnChainBridge> {
		debug!("Requesting WorkerOnChain OCall API instance");

		COMPONENT_FACTORY
			.read()
			.as_ref()
			.expect("Component factory has not been set. Use `initialize()`")
			.get_oc_api()
	}

	pub fn get_ipfs_api() -> Arc<dyn IpfsBridge> {
		debug!("Requesting IPFS OCall API instance");

		COMPONENT_FACTORY
			.read()
			.as_ref()
			.expect("Component factory has not been set. Use `initialize()`")
			.get_ipfs_api()
	}

	pub fn get_metrics_api() -> Arc<dyn MetricsBridge> {
		COMPONENT_FACTORY
			.read()
			.as_ref()
			.expect("Component factory has not been set. Use `initialize()`")
			.get_metrics_api()
	}

	pub fn initialize(component_factory: Arc<dyn GetOCallBridgeComponents + Send + Sync>) {
		debug!("Initializing OCall bridge with component factory");

		*COMPONENT_FACTORY.write() = Some(component_factory);
	}
}

/// Factory trait (abstract factory) that creates instances
/// of all the components of the OCall Bridge
pub trait GetOCallBridgeComponents {
	/// remote attestation OCall API
	fn get_ra_api(&self) -> Arc<dyn RemoteAttestationBridge>;

	/// side chain OCall API
	fn get_sidechain_api(&self) -> Arc<dyn SidechainBridge>;

	/// on chain (parentchain) OCall API
	fn get_oc_api(&self) -> Arc<dyn WorkerOnChainBridge>;

	/// ipfs OCall API
	fn get_ipfs_api(&self) -> Arc<dyn IpfsBridge>;

	/// Metrics OCall API.
	fn get_metrics_api(&self) -> Arc<dyn MetricsBridge>;
}

/// OCall bridge errors
#[derive(Debug, thiserror::Error)]
pub enum OCallBridgeError {
	#[error("GetQuote Error: {0}")]
	GetQuote(sgx_status_t),
	#[error("InitQuote Error: {0}")]
	InitQuote(sgx_status_t),
	#[error("GetUpdateInfo Error: {0}")]
	GetUpdateInfo(sgx_status_t),
	#[error("GetIasSocket Error: {0}")]
	GetIasSocket(String),
	#[error("UpdateMetric Error: {0}")]
	UpdateMetric(String),
	#[error("Propose sidechain block failed: {0}")]
	ProposeSidechainBlock(String),
	#[error("Failed to fetch sidechain blocks from peer: {0}")]
	FetchSidechainBlocksFromPeer(String),
	#[error("Sending extrinsics to parentchain failed: {0}")]
	SendExtrinsicsToParentchain(String),
	#[error("IPFS Error: {0}")]
	IpfsError(String),
	#[error("DirectInvocation Error: {0}")]
	DirectInvocationError(String),
	#[error("Node API factory error: {0}")]
	NodeApiFactory(#[from] itp_node_api::node_api_factory::NodeApiFactoryError),
}

impl From<OCallBridgeError> for sgx_status_t {
	fn from(o: OCallBridgeError) -> sgx_status_t {
		match o {
			OCallBridgeError::GetQuote(s) => s,
			OCallBridgeError::InitQuote(s) => s,
			OCallBridgeError::GetUpdateInfo(s) => s,
			_ => sgx_status_t::SGX_ERROR_UNEXPECTED,
		}
	}
}

pub type OCallBridgeResult<T> = Result<T, OCallBridgeError>;

/// Trait for all the OCalls related to remote attestation
#[cfg_attr(test, automock)]
pub trait RemoteAttestationBridge {
	/// initialize the quote
	fn init_quote(&self) -> OCallBridgeResult<(sgx_target_info_t, sgx_epid_group_id_t)>;

	/// get the intel attestation service socket
	fn get_ias_socket(&self) -> OCallBridgeResult<i32>;

	/// retrieve the quote from intel
	fn get_quote(
		&self,
		revocation_list: Vec<u8>,
		report: sgx_report_t,
		quote_type: sgx_quote_sign_type_t,
		spid: sgx_spid_t,
		quote_nonce: sgx_quote_nonce_t,
	) -> OCallBridgeResult<(sgx_report_t, Vec<u8>)>;

	/// retrieve the quote from dcap server
	fn get_dcap_quote(&self, report: sgx_report_t, quote_size: u32) -> OCallBridgeResult<Vec<u8>>;

	// Retrieve verification of quote
	fn get_qve_report_on_quote(
		&self,
		quote: Vec<u8>,
		current_time: i64,
		quote_collateral: &sgx_ql_qve_collateral_t,
		qve_report_info: sgx_ql_qe_report_info_t,
		supplemental_data_size: u32,
	) -> OCallBridgeResult<QveReport>;

	/// --
	fn get_update_info(
		&self,
		platform_blob: sgx_platform_info_t,
		enclave_trusted: i32,
	) -> OCallBridgeResult<sgx_update_info_bit_t>;
}

/// Trait for all the OCalls related to parentchain operations
#[cfg_attr(test, automock)]
pub trait WorkerOnChainBridge {
	fn worker_request(&self, request: Vec<u8>) -> OCallBridgeResult<Vec<u8>>;

	fn send_to_parentchain(&self, extrinsics_encoded: Vec<u8>) -> OCallBridgeResult<()>;
}

/// Trait for updating metrics from inside the enclave.
#[cfg_attr(test, automock)]
pub trait MetricsBridge {
	fn update_metric(&self, metric_encoded: Vec<u8>) -> OCallBridgeResult<()>;
}

/// Trait for all the OCalls related to sidechain operations
#[cfg_attr(test, automock)]
pub trait SidechainBridge {
	fn propose_sidechain_blocks(&self, signed_blocks_encoded: Vec<u8>) -> OCallBridgeResult<()>;

	fn store_sidechain_blocks(&self, signed_blocks_encoded: Vec<u8>) -> OCallBridgeResult<()>;

	fn fetch_sidechain_blocks_from_peer(
		&self,
		last_imported_block_hash_encoded: Vec<u8>,
		maybe_until_block_hash_encoded: Vec<u8>,
		shard_identifier_encoded: Vec<u8>,
	) -> OCallBridgeResult<Vec<u8>>;
}

/// type for IPFS
pub type Cid = [u8; 46];

/// Trait for all the OCalls related to IPFS
#[cfg_attr(test, automock)]
pub trait IpfsBridge {
	fn write_to_ipfs(&self, data: &'static [u8]) -> OCallBridgeResult<Cid>;

	fn read_from_ipfs(&self, cid: Cid) -> OCallBridgeResult<()>;
}

/// Trait for the direct invocation OCalls
#[cfg_attr(test, automock)]
pub trait DirectInvocationBridge {
	fn update_status_event(
		&self,
		hash_vec: Vec<u8>,
		status_update_vec: Vec<u8>,
	) -> OCallBridgeResult<()>;

	fn send_status(&self, hash_vec: Vec<u8>, status_vec: Vec<u8>) -> OCallBridgeResult<()>;
}
