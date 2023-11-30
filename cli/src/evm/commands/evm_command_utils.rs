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

#[macro_export]
macro_rules! get_layer_two_evm_nonce {
	($signer_pair:ident, $cli:ident, $trusted_args:ident ) => {{
		use ita_stf::{Getter, TrustedCallSigned};

		let top = TrustedOperation::<TrustedCallSigned, Getter>::get(Getter::trusted(
			TrustedGetter::evm_nonce($signer_pair.public().into())
				.sign(&KeyPair::Sr25519(Box::new($signer_pair.clone()))),
		));
		let res = perform_trusted_operation::<Index>($cli, $trusted_args, &top);
		let nonce = res.ok().unwrap_or(0);
		debug!("got evm nonce: {:?}", nonce);
		nonce
	}};
}
