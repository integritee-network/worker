//! Some definitions and traits that facilitate interaction with the enclave.
//!
//! This serves as a proof of concept on how we could design the interface between the worker and
//! the enclave.
//!
//! Design principle here should be to keep the traits as slim as possible - because then the
//! worker can also define slim interfaces with less demanding trait bounds.
//!
//! This can further be simplified once https://github.com/integritee-network/worker/issues/254
//! is implemented. Then we can replace the several ffi::<enclave_call> and the boilerplate code
//! around it with a simple `fn ecall(call: CallEnum) -> Result<D: Decode>`, which wraps one single
//! ffi function.

use crate::error::Error;

pub mod direct_request;
pub mod enclave_base;
pub mod enclave_test;
pub mod error;
pub mod remote_attestation;
pub mod sidechain;
pub mod teeracle_api;
pub mod utils;

#[cfg(feature = "implement-ffi")]
pub use sgx_urts::SgxEnclave;

#[cfg(feature = "implement-ffi")]
use sgx_types::sgx_enclave_id_t;

pub type EnclaveResult<T> = Result<T, Error>;

#[cfg(feature = "implement-ffi")]
#[derive(Clone, Debug, Default)]
pub struct Enclave {
	eid: sgx_enclave_id_t,
	sgx_enclave: SgxEnclave,
}

#[cfg(feature = "implement-ffi")]
impl Enclave {
	pub fn new(sgx_enclave: SgxEnclave) -> Self {
		Enclave { eid: sgx_enclave.geteid(), sgx_enclave }
	}

	pub fn destroy(self) {
		self.sgx_enclave.destroy()
	}
}
