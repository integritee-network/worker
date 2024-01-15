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

use crate::{Integritee, ParentchainInstance, TargetA, TargetB};
use codec::{Compact, Decode, Encode};
use core::{any::TypeId, marker::PhantomData};
use ita_stf::{Getter, TrustedCall, TrustedCallSigned};
use itc_parentchain_indirect_calls_executor::{
	error::{Error, Result},
	IndirectDispatch,
};
use itp_stf_primitives::{traits::IndirectExecutor, types::TrustedOperation};
use itp_types::{parentchain::ParentchainId, Moment};
use log::info;

#[derive(Debug, Clone, Encode, Decode, Eq, PartialEq)]
pub struct TimestampSetArgs<I: ParentchainInstance> {
	now: Compact<Moment>,
	_phantom: PhantomData<I>,
}

impl<Executor: IndirectExecutor<TrustedCallSigned, Error>, I: ParentchainInstance + 'static>
	IndirectDispatch<Executor, TrustedCallSigned> for TimestampSetArgs<I>
{
	fn dispatch(&self, executor: &Executor) -> Result<()> {
		info!("Found TimestampSet extrinsic in block: now = {:?}", self.now);
		let enclave_account_id = executor.get_enclave_account()?;
		let parentchain_id = if TypeId::of::<I>() == TypeId::of::<Integritee>() {
			ParentchainId::Integritee
		} else if TypeId::of::<I>() == TypeId::of::<TargetA>() {
			ParentchainId::TargetA
		} else if TypeId::of::<I>() == TypeId::of::<TargetB>() {
			ParentchainId::TargetB
		} else {
			return Err(Error::Other("unknown parentchain instance".into()))
		};
		let trusted_call =
			TrustedCall::timestamp_set(enclave_account_id, self.now.0, parentchain_id);
		let shard = executor.get_default_shard();
		let signed_trusted_call = executor.sign_call_with_self(&trusted_call, &shard)?;
		let trusted_operation =
			TrustedOperation::<TrustedCallSigned, Getter>::indirect_call(signed_trusted_call);

		let encrypted_trusted_call = executor.encrypt(&trusted_operation.encode())?;
		executor.submit_trusted_call(shard, encrypted_trusted_call);
		Ok(())
	}
}
