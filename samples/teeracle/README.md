# Teeracle install into Securitee's kubernetes cluster

This example is about to install [Integritee's Teeracle](https://docs.integritee.network/3-our-technology/3.5-use-cases/3.5.3-teeracle-oracle-framework).

*Prerequisites:*

* Ensure you have access to a Kubernetes cluster with SGX-enabled nodes and kubectl installed and configured. The easiest way to get started is to order Kubernetes from Securitee [Securitee Kubernetes](https://securitee.tech/products/), which offers SGX-enabled nodes.
* You have [Helm](https://helm.sh/docs/intro/install/) installed

## Kubernetes deployment walkthrough

We are now installing Teeracle

### Install steps


* Edit the configuration values in file [kubernetes/values.yaml](kubernetes/values.yaml)
    ```yaml
    app:
      url: "wss://rococo.api.integritee.network"
      interval: "2m"
    ```
* Install the Teeracle into the cluster

    ```bash
    helm install -f ./kubernetes/values.yaml teeracle ./kubernetes --create-namespace -n teeracle
    or run
    ./install-teeracle.sh
    ```


