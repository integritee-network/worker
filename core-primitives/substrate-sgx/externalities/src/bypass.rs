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

//! Converts maps to vecs for serialization.
//! from https://github.com/DenisKolodin/vectorize
//!
//! `bypass` is necessary to force deriving serialization of complex type specs.

use serde::{Deserialize, Deserializer, Serialize, Serializer};

#[allow(unused)]
pub fn serialize<'a, T, S>(target: T, ser: S) -> Result<S::Ok, S::Error>
where
	S: Serializer,
	T: Serialize + 'a,
{
	serde::Serialize::serialize(&target, ser)
}

#[allow(unused)]
pub fn deserialize<'de, T, D>(des: D) -> Result<T, D::Error>
where
	D: Deserializer<'de>,
	T: Deserialize<'de>,
{
	serde::Deserialize::deserialize(des)
}

#[cfg(test)]
mod tests {
	use serde::{de::DeserializeOwned, Deserialize, Serialize};
	use std::fmt;

	trait Requirement:
		DeserializeOwned + Serialize + Clone + fmt::Debug + Sync + Send + 'static
	{
	}

	trait ComplexSpec: Requirement {}

	#[derive(Debug, Serialize, Deserialize)]
	struct MyComplexType<T: ComplexSpec> {
		#[serde(with = "super")] // = "vectorize::bypass"
		inner: Option<T>,
	}
}
