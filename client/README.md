# SubstraTEE CLI client
Interact with the SubstraTEE chain and workers from the command line

Includes
* keystore (incompatible with polkadot js app json)
* basic balance transfer
* SubstraTEE-specific calls

## examples
```
> substratee-client new-account
> substratee-client 127.0.0.1 transfer 5GpuFm6t1AU9xpTAnQnHXakTGA9rSHz8xNkEvx7RVQz2BVpd 5FkGDttiYa9ZoDAuNxzwEdLzkgt6ngWykSBhobGvoFUcUo8B 12345
> substratee-client 127.0.0.1:9979 list-workers
number of workers registered: 1
Enclave 1
   AccountId: 5DvVAZAWnFS6ufCteSbuh46miVUCQH5oZ231SXHQGswCdGx9
   MRENCLAVE: HvKRosdfbbLayao3rAq4xmN2fnxBVX79DfDdeJ9YcTo5
   RA timestamp: 2020-02-22 06:32:37 UTC
   URL: 127.0.0.1:2000
```
