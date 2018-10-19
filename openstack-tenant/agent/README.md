# Agent for Openstack platform hosting Kubernetes cluster

This is an agent that will create a kubernetes cluster in openstack for a tenant, perform reverse proxy, and other functions. 
There can be one or more agent nodes and services per cloudlet. A given tenant may have one or more agents. An agent can manage one or more kubernetes clusters.  A kubernetes cluster per tenant can host one or more tenant apps. A tenant may have one or more kubernetes clusters.  

The kubernetes clusters per tenant can be created based on `flavors`. The `flavors` are abstractions similiar to `m1.small` or `m1.large` in openstack or AWS and other cloud  platforms.  The `flavors` for the `mexosagent` are different. They are not merely for descriptions required for provisioning a single virtual machine instance resources.  The `mexosagent` extends this idea to cluster configuration and resource descriptions.  A `flavor` therefore can include such things as the number of machine instances, the type of networks, the number of master nodes vs. worker nodes, how the agents interact with the cluster, etc.  The `flavors` can be defined and created on the fly. Although typically a set of useful `flavors` are created beforehand. This is typically done by the Controller as needed.

The agent supports GRPC as well HTTP REST API.  Swagger json under api/ directory for API documentation.

The program requires platform environment, which can be set up by sourcing `k8sopenstack.env` located under `k8s-prov` directory or the equivalent. Please refer to README.md under `k8s-prov` directory for further information.

## building

You may need to set environment variable for docker builds:

```
export DOCKER_ID_USER=yourusername
```

Adjust the values of the DOCKER API version and docker hub user ID. DOCKER_API_VERSION may or may not need to be set.
If you have multiple docker binaries, you may check by doing `docker version`. We are compatible with API version 1.37.
The build process builds the container image and pushes to the repo. The target machine can pull the image and run.

TODO: establish a private docker repo. Automate push and pull and relaunch.

## Running the Agent

The agent runs on a node with sufficient access to the Internet and the internal network in which kubernetes cluster and containers are hosted.  The openstack network has to be setup properly for this.  An instance of openstack router has to be created and directed to route between the public and private network.  Typically a private network is created for the kubernetes cluster which is isolated from the internet.  The traffic from the private network has to be NAT'ed and routed via a router.

The agent is deployed as a docker container image.  Pull the image on the agent node:

```
docker pull mobiledgex/mexosagent
```

Some preparations are needed.  The agent needs proper CA issued certificates as it runs `https` service as well as `grpc` and `rest api`.  See the README.md under `acme` directory for more information. The `https` service is reverse proxy for the internal services hosted inside kubernetes clusters in the private network. The `TLS` is terminated at the proxy. This allows for simpler certificate management. Only one certificate is needed for the reverse proxy. The rest of the origin services can run without `TLS` and securely.  

Partly due to the above, the agent needs a proper FQDN in the public DNS service. The code here uses `cloudflare` API to register the FQDN for the agent service.  This also simplifies the DNS management.  All internal kubernetes DNS names are still available within the kubernetes cluster. There is no need to register individual internal origin services behind the reverse proxy. The reverse proxy allows for path name based routing to backend origin services.   This allows for limiting the number of dedicated public IP addresses that are routable on the Internet.  Only the reverse proxy needs to have the reserved IP externally exposed. One IP address can be shared among many services.

Once certficate and key PEM files are available, place them under `certs` directory which should be in the working directory where you run the container.

```
$ ls certs
cert.pem  key.pem
```

Also create a sub directory called `k8sopenstack` and place some environment variables files as described before.
```
$ ls -a k8sopenstack/
.  ..  .k8sopenstack.env  .k8sopenstack.os.env  .k8sopenstack.toml  .k8sopenstack.userdata
```


The agent can then be run as:

```
docker run --rm --name proxy -v `pwd`/certs:/var/www/.cache -v /etc/ssl/certs:/etc/ssl/certs -v `pwd`/k8sopenstack:/k8sopenstack --network host -e MEX_K8SOS_ENV=/k8sopenstack/.k8sopenstack.os.env -e MEX_K8SOS_CONFIG=/k8sopenstack/.k8sopenstack.toml -e MEX_K8SOS_USERDATA=/k8sopenstack/.k8sopenstack.userdata --name agent1.medge.gq  mobiledgex/mexosagent   -debug
```

The environment variables `MEX_K8SOS_ENV`, `MEX_K8SOS_CONFIG` and `MEX_K8SOS_USERDATA` are used for provisioning API.

The `certs` directory is mounted as `/var/www/.cache` inside container. The `k8sopenstack` is mounted inside the container as `/k8sopenstack` to give access to the environment variables to the `mexosagent` running inside the container. 


## Examples using curl

The APIs can be accessed via `GRPC` or `HTTP REST API`.  Here `curl` based examples are shown.


### Cluster provisioning

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

### Reverse Proxy

The agent implements dynamic reverse proxy that can be programmed on the fly via API.

For example,

```
curl  http://agent1.medge.gq:18889/v1/proxy -H "Content-Type: application/json" -d '{ "message": "add", "proxies": [  {"path": "/test2", "origin":"http://10.101.101.202:8081" } ] }'
```

When this is run from any `curl` enabled machine on Internet, it will direct the agent running on `agent1.medge.gq` machine in the cloudlet to add a reverse proxy for the origin server specified.  The origin server here is running inside a kubernetes cluster on a  private network.

This is assuming that there is a HTTP service at port 8081 on node with IP address, within private network, set to 10.101.101.202.
The specifics of the private network settings are known to the client of the Agent. The calling side had previously already requested creation of the cluster with specific parameters. Subseqeuent calls are based on knowledge of the cluster on the caller's side.

TODO: APIs to query the state of the Agent side, details of clusters, networking setup, current conditions, etc.  Helpful when the calling side has to restart or lose all the information on its side.

After this, another `curl` command can be used to access the origin server via the agent reverse proxy.

```
curl https://agent1.medge.gq/test2
```

The origin server is hosted in kubernetes which exposes the service. The service itself may be behind kubernetes internal load balancer which can direct traffic to multiple instances of app deployment (pods).  If there is a service running on the origin URL, in this case `http://10.101.101.202:8081`, the response from the origin will be returned to the requester.


### Nginx reverse proxy

Nginx container based L7 and L4 proxy support is available at v1/nginx.

For example,

```
curl http://hawkins.mex-gddt.mobiledgex.net:18889/v1/nginx -d '{"message":"add","name":"test1","ports":[{"mexproto":"LProtoHTTP","external":"8888","internal":"8888","origin":"127.0.0.1:8888","path":"/hello"},{"mexproto":"LProtoTCP","external":"7777","origin":"127.0.0.1:777"},{"mexproto":"LProtoUDP","external":"6666","origin":"127.0.0.1:6666"}]}'
```

adds one HTTP proxy which is terminated at port 8888 on the rootLB TLS. Users will access the service at https://example.com:8888. It also adds TCP proxy at 7777 and UDP proxy at 6666.

```
curl http://hawkins.mex-gddt.mobiledgex.net:18889/v1/nginx -d '{"message":"list"}'
```

Lists  currently available nginx proxy container instances.

```
curl http://hawkins.mex-gddt.mobiledgex.net:18889/v1/nginx -d '{"message":"delete","name":"test1"}'
```

Deletes the nginx proxy instance named tested1.
