# Load Balancer API

## Background

When Kubernetes load balancers are created and deleted by the system
or by user's applications, the infrastructure platform may need to
take some action. For example, an external load balancer may need
to be created, or an VIP address may need to be allocated and
applied to the Kubernetes load balancer service.

## Goals

- Allow for infrastructure-specific code to be run when Kubernetes
load balancers are created and deleted
- Allow for IPs to be allocated transactionally from a cloudlet IP pool,
to share IP Address Management across multiple clusters in the cloudlet.
- Keep infra-specific code separate from common code

## Limitations

- Currently, we only support load balancers created via our platform.
We do not support load balancers created directly via kubectl to the
cluster.
- Only CCRM-based platforms are supported. CRM-based platforms (where
the CRM runs on the cloudlet itself) are not supported.

## Background

We have some implementation of this already. For VM-based platforms
like Openstack or VSphere, we detect load balancer services and patch the
external IP address of the load balancer service with the cluster's master
node IP address. The drawback of this approach is there is no HA, if the
master node goes down, so does the data plane traffic. Instead, we want
to be able to take advantage of newer services like KubeVip and MetalLB
that provide HA capability. For this implementaton we do not change the
existing behavior for VM-based platforms.

## Implementation

The implementation is conceptually split into two parts, an infra
specific Load Balancer API that is called whenever Kubernetes load
balancer services are created/deleted, and a common set of support code
for allocating cloudlet IPs transactionally that is needed for the
clusterapi infra platform.

The load balancer API is defined in
[platform.go](../pkg/platform/platform.go), and is modeled after the
[Kubernetes cloud-provider API](https://github.com/kubernetes/cloud-provider/blob/master/cloud.go).

The AccessAPI interface, also defined in platform.go, now includes two
functions to allocate and free IPs for a load balancer object. These
will call into the Controller/CCRM to allocate IPs transactionally.

The Controller now tracks per-cloudlet IP allocations in a CloudletIPs
object defined in [refs.proto](../api/edgeproto/refs.proto). This tracks
a control plane IP which applies to the Kubernetes API endpoint,
typically port 6443, and per-load balancer IPs. The functions for managing
these IPs are in a separate [cloudletips package](../pkg/cloudletips),
which is implemented by both the Controller and the CCRM, since both
must satisfy the AccessAPI interface for
[vaultclients](../pkg/accessapi/vaultclient.go).

The general idea is that whenever creating an AppInst also creates
load balancer services, we call the Load Balancer API for each service,
which allows the infra-specific platform code to handle whatever it
needs to do to support the kubernetes load balancer.

In the case of the clusterapi platform, we need to allocate an IP
address from an IP pool that is shared across all clusters in the cloudlet.
The call flow can be pretty tricky due to interfaces, so it is outlined
below for the clusterapi case of deploying an AppInst:

- Controller handles AppInst create in [appinst_api.go](../pkg/controller/appinst_api.go)
- Controller calls to the CCRM [ApplyAppInst](../pkg/ccrm/ccrm_appinst.go) via GRPC
- CCRM runs the common [controller-data](../pkg/crmutil/controller-data.go) 
AppInstChanged function, which loads the infrastructure-specific platform
code and runs the platform's CreateAppInst function.
- For [clusterapi](../pkg/platform/clusterapi/), this is implemented by the
[K8sPlatformMgr](../pkg/k8spm/k8spm.go) as initialized in the
[managed K8S common code](../pkg/platform/common/managedk8s/mk8s-provider.go).
The mk8s-provider casts the clusterapi provider to the load balancer
interface and passes it to the K8sPlatformMgr.
- The K8sPlatformMgr's CreateAppInst function runs and deploys the
application instance, then runs
[CreateAppDNSAndPatchKubeSvc](../pkg/platform/common/infracommon/dns.go).
The goal of this function is to create DNS entries for the application's
load balancer IP addresses. In this case, it will first run the load
balancer API's EnsureLoadBalancer function for each load balancer service
that it detects is associated with the application instance.
- That calls clusterapi's EnsureLoadBalancer function from
[clusterapi-cluster.go](../pkg/platform/clusterapi/clusterapi-cluster.go).
Clusterapi just wants to allocate an IP address. It calls the AccessAPI
function ReserveLoadBalancerIP function. On the CCRM, this is implemented
by the vaultClient set up in [ccrm_handler.go](../pkg/ccrm/ccrm_handler.go).
- [vaultClient](../pkg/accessapi/vaultclient.go) uses the
[cloudletIPs](../pkg/cloudletips/cloudletips.go) object to transactionally
allocate an IP address by checking free addresses against used addresses
tracked in Etcd.
- The clusterapi's EnsureLoadBalancer function then applies the IP to the
load balancer by setting an annotation that KubeVip will detect. Other
infra platforms may use different approaches to set the IP, but Kubernetes
itself will not advertise the IP, so some infra-specific approach is
needed (KubeVip, MetalLB, etc).

## Notes on Interfaces

The call flow is complicated by several interfaces that make it hard to
directly track via static analysis. As a reminder, the motivations for
the interfaces are noted below.

[Platform](../pkg/platform/platform.go) interface: Abstracts an
infrastructure platform. The infra may be VM-based (Openstack/VSphere)
or may be Kubernetes Based (Azure/GCP/AWS-EKS/OSMano/k8ssite) or may
be bare metal based (clusterapi). It is a general interface used for
calling into infra-specific code to create clusters and deploy applications.

[AccessAPI](../pkg/platform/platform.go) interface: Allows for
infra-specific platform code to call back to the Controller to
access secrets or perform actions that require heightened permissions.
This allows on-cloudlet CRMs to have very limited and specific access
to secrets and other functions, like allocating DNS entries. It is not
neccessary for the off-cloudlet CCRM instances.

[Managed K8S provider](../pkg/platform/common/managedk8s/mk8s-provider.go):
The managed k8s provider provides common functions for an infra platform
that only cares about Kubernetes, and does not support VM/docker deployments.
It provides a wrapper around the k8s-specific infra platform, implementing
many of the Platform interface's APIs that are not relevant or are common
across all the k8s providers.

[Load Balancer API](../pkg/platform/platform.go): Provides an interface
for taking actions when Kubernetes load balancers are created and deleted.
This should be implemented by the infra-specific platform code.

## Alternative Implementation

One drawback of the current implementation is that it only works for
load balancers detected during AppInst create. If in the future users are
allowed to create load balancers directly via kubectl, those load balancers
will not trigger the Load Balancer API and no IP or external LB will be
allocated.

A more general solution is the
[Kubernetes cloud controller](https://kubernetes.io/docs/concepts/architecture/cloud-controller/)
approach, where a service running on the cluster is notified of
load balancer changes, and then calls back to a central cloud
provider. We could have a cloud-provider service running on the cluster
which is given the AccessAPI credentials (much like a CRM), and can
call back to the Controller/CCRM.

This is a more complex solution with more moving parts, and a few open
questions on how to implement:

- This now exposes credentials to the cluster needed to access the Controller/CCRM. We may need to introduce new cluster-specific credentials to
limit the scope of exposure and permissions and allow for cluster-specific
credential revocation.
- This requires managing the lifecycle (install/upgrade) of a service
on every cluster that needs to be kept in sync with our platform
services version.
- Some open questions about where the platform-specific code should
live: we probably don't want the cloud-provider service running on the
cluster to be platform-specific, so it is generic and just calls
Load Balancer APIs to the Controller/CCRM. Given that the implementation
of the Load Balancer APIs are infra-platform-specific, this should go
to the CCRM which handles all the platform-specific code. But currently
the CCRM is not set up to receive API calls from the cloudlet, outside
of the ansible endpoint. This would probably be a new endpoint that
would need to be added, requiring changes to the kubernetes operator used
to deploy our system.

Because of the added complexity and additional changes needed, and the
lack of need for the added functionality, we leave this alternative
implementation as a potential future roadmap item if the need arises.

## Why not let MetalLB do the IP management?

MetalLB can do IP address management and allocation for us, but it
requires us to dedicate an IP pool to the cluster. In a multi-cluster
environment, this would require splitting the cloudlet's IP pool
into smaller per-cluster pools that would tie up the IP addresses
even if they weren't use in. Instead, we want to allocate IPs to
load balancers across multiple clusters from a single IP pool.
So we cannot use MetalLB to do the IP address management.
