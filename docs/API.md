# 🚀 Integritee CLI Tool

📝 **Note**: Run the commands inside the `BEST-Energy/bin` directory.

**🔧 Usage**

```
$ ./integritee-cli [OPTIONS] <SUBCOMMAND>
```


## ❓ Get Help

```
$ ./integritee-cli --help
```


## 🔍 Get List of Workers

To get a list of workers, run the following command inside the `BEST-Energy/bin` directory:


```
$ ./integritee-cli list-workers
```

👀 This will provide you with a detailed list of all available workers.

## Store `Orders`, `Market_Results` `Store` and `Publish` Root Hash

**🔧 Usage**
```
$ ./integritee-cli trusted --mrenclave <MRENCLAVE> pay-as-bid <ACCOUNT> <ORDERS_STRING>
```

**💻 Sample Command**

```
$ ./integritee-cli trusted --mrenclave 7LpjC5R5oiAj1k472NTQarCy3oaPxU9giasuENBJUHbd --direct pay-as-bid //Alice '[{"id":0,"order_type":"ask","time_slot":"2022-03-04T05:06:07+00:00","actor_id":"actor_0","cluster_index":0,"energy_kwh":5,"price_euro_per_kwh":0.19},{"id":1,"order_type":"ask","time_slot":"2022-03-04T05:06:07+00:00","actor_id":"actor_1","cluster_index":0,"energy_kwh":8.8,"price_euro_per_kwh":0.23}]'
```

## Generate `Merkle_Proof`

**🔧 Usage**
```
$ ./integritee-cli trusted --mrenclave <MRENCLAVE> pay-as-bid-proof <ACCOUNT> <ORDERS_STRING> <LEAF_INDEX>
```

**💻 Sample Command**

```
$ ./integritee-cli trusted --mrenclave 3VuxiVpMnk9hDtYtN732Wo5eDmfxPE9125PWzY6JEEAg --direct pay-as-bid-proof //Alice '[{"id":0,"order_type":"ask","time_slot":"2022-03-04T05:06:07+00:00","actor_id":"actor_0","cluster_index":0,"energy_kwh":5,"price_euro_per_kwh":0.19},{"id":1,"order_type":"ask","time_slot":"2022-03-04T05:06:07+00:00","actor_id":"actor_1","cluster_index":0,"energy_kwh":8.8,"price_euro_per_kwh":0.23}]' 0
```

## Verify `Merkle_Proof`

**🔧 Usage**

```
$ ./integritee-cli trusted --mrenclave <MRENCLAVE> verify-proof <MERKLE_PROOF_JSON>
```

**💻 Sample Command**

```
$ ./integritee-cli trusted --mrenclave gR4hLUg2g4ERAPW1bn8vfysn17pEBV1QZ645ByhZk7W --direct verify-proof "{\"root\":\"0x0db7b3827b7640210cbd9030d7ef152f2fd5ed9d8cf861b0003aabac8970d310\",\"proof\":[\"0x087de1f2a70b740689695bd372c5328f85871f5672db79a95df567be5d8a2e04\"],\"number_of_leaves\":2,\"leaf_index\":0,\"leaf\":[0,0,0,0,0,0,0,0,1,100,50,48,50,50,45,48,51,45,48,52,84,48,53,58,48,54,58,48,55,43,48,48,58,48,48,28,97,99,116,111,114,95,48,1,0,0,0,0,0,0,0,0,0,0,20,64,82,184,30,133,235,81,200,63]}"
```
