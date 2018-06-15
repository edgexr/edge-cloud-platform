# Agent for Openstack platform hosting Kubernetes cluster

This is an agent that will create a kubernetes cluster in openstack for a tenant. 
The agent supports GRPC as well HTTP REST API.  Swagger json under api/ directory for API documentation.
The program requires platform environment, which can be set up by sourcing `k8sopenstack.env` located under `k8s-prov` directory or the equivalent. Please refer to README.md under `k8s-prov` directory for further information.

## Example using curl

To create a kubernetes `mini` cluster for a tenant consisting of total three VM nodes running one k8s master and two k8s nodes:

```
curl -sv http://localhost:18889/v1/provision -H "Content-Type: application/json" -d '{"provisions": [{"name":"test-1", "tenant":"tenant-1", "kind":"kubernetes-mini-openstack"}]}'
```

This will create three new VMs via openstack nova.  The VM instances will boot up and start installation of kubernetes cluster.
You may need to wait a few minutes to see the cluster form.

To see the VM instances:

```
openstack server list
```

If the instances are up then you can use ssh to each node to see the progress. Once kubernetes cluster is formed, you can ssh into master node and do:

```
kubectl get nodes
```


To destroy the above cluster:

```
curl -sv http://localhost:18889/v1/destroy -H "Content-Type: application/json" -d '{"provisions": [{"name":"test-1", "tenant":"tenant-1", "kind":"kubernetes-mini-openstack"}]}'
```
