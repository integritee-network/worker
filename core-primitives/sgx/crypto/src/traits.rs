//! Abstraction over the state crypto that is used in the enclave
use std::vec::Vec;

pub trait StateCrypto {
	type Error;
	fn encrypt(data: &mut [u8]) -> Result<(), Self::Error>;
	fn decrypt(data: &mut [u8]) -> Result<(), Self::Error>;
}

pub trait ShieldingCrypto {
	type Error;
	fn encrypt(data: &[u8]) -> Result<Vec<u8>, Self::Error>;
	fn decrypt(data: &[u8]) -> Result<Vec<u8>, Self::Error>;
}
