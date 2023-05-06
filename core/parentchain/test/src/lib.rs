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

//! Builder patterns for common structs used in tests.

#![cfg_attr(not(feature = "std"), no_std)]

mod parentchain_block_builder;
mod parentchain_header_builder;

pub use parentchain_block_builder::{Block, ParentchainBlockBuilder, SignedBlock};
pub use parentchain_header_builder::{BlockNumber, Header, ParentchainHeaderBuilder, H256};
