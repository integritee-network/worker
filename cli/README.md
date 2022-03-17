# Integritee CLI client
Interact with the Integritee chain and workers from the command line

Includes
* keystore (incompatible with polkadot js app json)
* basic balance transfer
* Integritee-specific calls

## examples
```
> ./integritee-cli transfer //Bob //Alice 12345
> ./integritee-cli -u ws://127.0.0.1 list-workers
number of workers registered: 1
Enclave 1
   AccountId: 5HN8RGEiJuc9iNA3vfiYj7Lk6ULWzBZXvSDheohBu3usSUqn
   MRENCLAVE: 4GMb72Acyg8hnnnGEJ89jZK5zxNC4LvSe2ME96wLRV6J
   RA timestamp: 2022-03-16 10:43:12.001 UTC
   URL: wss://127.0.0.1:2345
> ./integritee-cli -P 2345 trusted --direct --mrenclave 4GMb72Acyg8hnnn
GE4LvSe2ME96wLRV6J unshield-funds //Bob //Alice 12345
from ss58 is 5FHneW46xGXgs5mUiveU4sbTyGBzmstUspZC92UhjJM694ty
to   ss58 is 5GrwvaEF5zXb26Fz9rcQpDWS57CtERHpNehXCPcNoHGKutQY
send trusted call unshield_funds from 5FHneW46xGXgs5mUiveU4sbTyGBzmstUspZC92UhjJM694ty to 5GrwvaEF5zXb26Fz9rcQpDWS57CtERHpNehXCPcNoHGKutQY: 12345
Trusted call 0x69ddfd1698bd2d629180c2dca34ce7add087526c51f43cf68245241b3f13154e is Submitted
Trusted call 0x69ddfd1698bd2d629180c2dca34ce7add087526c51f43cf68245241b3f13154e is Invalid

```
