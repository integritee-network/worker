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

#[cfg(all(feature = "std", feature = "sgx"))]
compile_error!(
	"feature \"real-ffi\" and feature \"no-linking\" cannot be enabled at the same time"
);

use crate::error::Error;
use sgx_types::*;

pub mod direct_request;
pub mod enclave_base;
pub mod enclave_test;
pub mod error;
pub mod remote_attestation;
pub mod sidechain;
pub mod teeracle_api;
pub mod utils;

#[cfg(feature = "real-ffi")]
pub use sgx_urts::SgxEnclave;

pub type EnclaveResult<T> = Result<T, Error>;

#[cfg(feature = "real-ffi")]
#[derive(Clone, Debug, Default)]
pub struct Enclave {
	eid: sgx_enclave_id_t,
	sgx_enclave: SgxEnclave,
}

#[cfg(feature = "real-ffi")]
impl Enclave {
	pub fn new(sgx_enclave: SgxEnclave) -> Self {
		Enclave { eid: sgx_enclave.geteid(), sgx_enclave }
	}

	pub fn destroy(self) {
		self.sgx_enclave.destroy()
	}
}
