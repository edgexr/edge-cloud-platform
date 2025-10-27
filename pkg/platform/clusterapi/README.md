# Cluster API Provider

The ClusterAPI platform implements a platform that uses the Kubernetes
[Cluster API](https://cluster-api.sigs.k8s.io/) to manage Kubernetes
clusters.

Currently, this only supports the metal3 infrastructure provider.

We do not support deploying the cluster API controllers.
Please see [README_k3s.md](./README_k3s.md) for an example of setting
up the cluster API management cluster as part of local testing.
