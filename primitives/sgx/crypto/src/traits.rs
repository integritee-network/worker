//! Abstraction over the state crypto that is used in the enclave
pub trait StateCrypto {
	type Error;
	fn encrypt(data: &mut [u8]) -> Result<(), Self::Error>;
	fn decrypt(data: &mut [u8]) -> Result<(), Self::Error>;
}
