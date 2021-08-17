pub trait StateCrypto {
	type Error;
	fn encrypt(&self, data: &mut [u8]) -> Result<(), Self::Error>;
	fn decrypt(&self, data: &mut [u8]) -> Result<(), Self::Error>;
}
