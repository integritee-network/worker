//! # temp-dir
//!
//! Copied from the original tempdir crate with tiny adjustments for SGX-compatibility.
//!
//! Note: The temp-dir is deprecated and there might be uncovered security aspects. If we want to
//! use this in production, we should run some checks.

#![cfg_attr(not(feature = "std"), no_std)]

#[cfg(all(feature = "std", feature = "sgx"))]
compile_error!("feature \"std\" and feature \"sgx\" cannot be enabled at the same time");

#[cfg(all(not(feature = "std"), feature = "sgx"))]
extern crate sgx_tstd as std;

use core::sync::atomic::{AtomicU32, Ordering};
use std::{
	borrow::ToOwned,
	collections::hash_map::RandomState,
	format,
	hash::{BuildHasher, Hasher},
	path::{Path, PathBuf},
	string::String,
};

/// Serve some low-security random ID to prevent temp-dir clashes across multiple processes.
fn rand_id() -> String {
	// u64 always has more than 4 bytes so this never panics.
	format!("{:x}", RandomState::new().build_hasher().finish())[..4].to_owned()
}

lazy_static::lazy_static! {
	/// A unique identifier, which is instanciated upon process start, but it is
	/// not the process id itself.
	///
	/// This is a workaround for `sgx_tstd` lib not exposing the `process::id()`.
	pub static ref PROCESS_UNIQUE_ID: String = rand_id();
}

static COUNTER: AtomicU32 = AtomicU32::new(0);

/// The path of an existing writable directory in a system temporary directory.
///
/// Drop the struct to delete the directory and everything under it.
/// Deletes symbolic links and does not follow them.
///
/// Ignores any error while deleting.
/// See [`TempDir::panic_on_cleanup_error`](struct.TempDir.html#method.panic_on_cleanup_error).
///
/// # Example
/// ```rust
/// use itp_sgx_temp_dir::TempDir;
/// let d = TempDir::new().unwrap();
/// // Prints "/tmp/t1a9b-0".
/// println!("{:?}", d.path());
/// let f = d.child("file1");
/// // Prints "/tmp/t1a9b-0/file1".
/// println!("{:?}", f);
/// std::fs::write(&f, b"abc").unwrap();
/// assert_eq!(
///     "abc",
///     std::fs::read_to_string(&f).unwrap(),
/// );
/// // Prints "/tmp/t1a9b-1".
/// println!("{:?}", TempDir::new().unwrap().path());
/// ```
#[derive(Clone, PartialOrd, Ord, PartialEq, Eq, Hash, Debug)]
pub struct TempDir {
	path_buf: Option<PathBuf>,
	panic_on_delete_err: bool,
}
impl TempDir {
	fn remove_dir(path: &Path) -> Result<(), std::io::Error> {
		match std::fs::remove_dir_all(path) {
			Ok(()) => Ok(()),
			Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
			Err(e) => Err(std::io::Error::new(
				e.kind(),
				format!("error removing directory and contents {:?}: {}", path, e),
			)),
		}
	}

	/// Create a new empty directory in a system temporary directory.
	///
	/// Drop the struct to delete the directory and everything under it.
	/// Deletes symbolic links and does not follow them.
	///
	/// Ignores any error while deleting.
	/// See [`TempDir::panic_on_cleanup_error`](struct.TempDir.html#method.panic_on_cleanup_error).
	///
	/// # Errors
	/// Returns `Err` when it fails to create the directory.
	///
	/// # Example
	/// ```rust
	/// // Prints "/tmp/t1a9b-0".
	/// println!("{:?}", itp_sgx_temp_dir::TempDir::new().unwrap().path());
	/// ```
	pub fn new() -> Result<Self, std::io::Error> {
		// Prefix with 't' to avoid name collisions with `temp-file` crate.
		Self::with_prefix("t")
	}

	/// Create a new empty directory in a system temporary directory.
	/// Use `prefix` as the first part of the directory's name.
	///
	/// Drop the struct to delete the directory and everything under it.
	/// Deletes symbolic links and does not follow them.
	///
	/// Ignores any error while deleting.
	/// See [`TempDir::panic_on_cleanup_error`](struct.TempDir.html#method.panic_on_cleanup_error).
	///
	/// # Errors
	/// Returns `Err` when it fails to create the directory.
	///
	/// # Example
	/// ```rust
	/// // Prints "/tmp/ok1a9b-0".
	/// println!("{:?}", itp_sgx_temp_dir::TempDir::with_prefix("ok").unwrap().path());
	/// ```
	pub fn with_prefix(prefix: impl AsRef<str>) -> Result<Self, std::io::Error> {
		let path_buf = std::env::temp_dir().join(format!(
			"{}{}-{:x}",
			prefix.as_ref(),
			// std::process::id(), -> The original tempdir crate had this, but the sgx-std lib does not expose it.
			*PROCESS_UNIQUE_ID,
			COUNTER.fetch_add(1, Ordering::AcqRel),
		));
		std::fs::create_dir(&path_buf).map_err(|e| {
			std::io::Error::new(
				e.kind(),
				format!("error creating directory {:?}: {}", &path_buf, e),
			)
		})?;
		Ok(Self { path_buf: Some(path_buf), panic_on_delete_err: false })
	}

	/// Remove the directory on its contents now.  Do nothing later on drop.
	///
	/// # Errors
	/// Returns an error if the directory exists and we fail to remove it and its contents.
	#[allow(clippy::missing_panics_doc)]
	pub fn cleanup(mut self) -> Result<(), std::io::Error> {
		Self::remove_dir(&self.path_buf.take().unwrap())
	}

	/// Make the struct panic on Drop if it hits an error while
	/// removing the directory or its contents.
	#[must_use]
	pub fn panic_on_cleanup_error(mut self) -> Self {
		Self { path_buf: self.path_buf.take(), panic_on_delete_err: true }
	}

	/// Do not delete the directory or its contents.
	///
	/// This is useful when debugging a test.
	pub fn leak(mut self) {
		self.path_buf.take();
	}

	/// The path to the directory.
	#[must_use]
	#[allow(clippy::missing_panics_doc)]
	pub fn path(&self) -> &Path {
		self.path_buf.as_ref().unwrap()
	}

	/// The path to `name` under the directory.
	#[must_use]
	#[allow(clippy::missing_panics_doc)]
	pub fn child(&self, name: impl AsRef<str>) -> PathBuf {
		let mut result = self.path_buf.as_ref().unwrap().clone();
		result.push(name.as_ref());
		result
	}
}
impl Drop for TempDir {
	fn drop(&mut self) {
		if let Some(path) = self.path_buf.take() {
			let result = Self::remove_dir(&path);
			if self.panic_on_delete_err {
				if let Err(e) = result {
					panic!("{}", e);
				}
			}
		}
	}
}

#[cfg(test)]
mod test;
