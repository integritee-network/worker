//! SGX file IO abstractions

#![cfg_attr(not(feature = "std"), no_std)]

#[cfg(all(feature = "std", feature = "sgx"))]
compile_error!("feature \"std\" and feature \"sgx\" cannot be enabled at the same time");

#[cfg(all(not(feature = "std"), feature = "sgx"))]
extern crate sgx_tstd as std;

use std::{
	convert::AsRef,
	fs,
	io::{Read, Result as IOResult, Write},
	path::Path,
	string::String,
	vec::Vec,
};

#[cfg(feature = "sgx")]
pub use sgx::*;

/// Abstraction around IO that is supposed to use the `std::io::File`
pub trait IO: Sized {
	type Error: From<std::io::Error> + std::fmt::Debug + 'static;

	fn read() -> Result<Self, Self::Error>;
	fn write(&self) -> Result<(), Self::Error>;
}

/// Abstraction around IO that is supposed to use `SgxFile`. We expose it also in `std` to
/// be able to put it as trait bounds in `std` and use it in tests.
pub trait SealedIO: Sized {
	type Error: From<std::io::Error> + std::fmt::Debug + 'static;

	/// Type that is unsealed.
	type Unsealed;

	fn unseal() -> Result<Self::Unsealed, Self::Error>;
	fn seal(unsealed: Self::Unsealed) -> Result<(), Self::Error>;
}

pub fn read<P: AsRef<Path>>(path: P) -> IOResult<Vec<u8>> {
	let mut buf = Vec::new();
	fs::File::open(path).map(|mut f| f.read_to_end(&mut buf))??;
	Ok(buf)
}

pub fn write<P: AsRef<Path>>(bytes: &[u8], path: P) -> IOResult<()> {
	fs::File::create(path).map(|mut f| f.write_all(bytes))?
}

pub fn read_to_string<P: AsRef<Path>>(filepath: P) -> IOResult<String> {
	let mut contents = String::new();
	fs::File::open(filepath).map(|mut f| f.read_to_string(&mut contents))??;
	Ok(contents)
}

#[cfg(feature = "sgx")]
mod sgx {
	use std::{
		convert::AsRef,
		io::{Read, Result, Write},
		path::Path,
		sgxfs::SgxFile,
		vec::Vec,
	};

	pub fn unseal<P: AsRef<Path>>(path: P) -> Result<Vec<u8>> {
		let mut buf = Vec::new();
		SgxFile::open(path).map(|mut f| f.read_to_end(&mut buf))??;
		Ok(buf)
	}

	pub fn seal<P: AsRef<Path>>(bytes: &[u8], path: P) -> Result<()> {
		SgxFile::create(path).map(|mut f| f.write_all(bytes))?
	}
}
