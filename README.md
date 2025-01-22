# Edge-Cloud Platform

The Edge-Cloud Platform is a set of services that allow for distributed and secure management of edge sites ("cloudlets"), featuring deployment of workloads, one-touch provisioning of new cloudlets, monitoring, metrics, alerts, events, and more.

The platform is intended to satisfy the architecture of an Operator Platform as described in the GSMA document, [Operator Platform Telco Edge Proposal](https://www.gsma.com/futurenetworks/wp-content/uploads/2020/10/GSMA-Operator-Platform-Proposal-Oct-2020.pdf), and adhere to standardized interfaces developed by [CAMARA](https://camaraproject.org/).

## Services

- The **Controller** provides the API endpoint for, and manages creating, updating, deleting, and showing application definitions, cloudlets, clusters, application instances, policies, etc. It manages object dependencies and validation, stores objects in Etcd, and distributes objects to other services that need to be notified of data changes.

- The **Cloudlet Resource Manager (CRM)** manages infrastructure on a cloudlet site, calling the underlying infrastruture APIs to instantiate virtual machines, docker containers, kubernetes clusters, or kubernetes applications, depending on what the actual infrastructure type supports.

- The **Central Cloudlet Resource Manager (CCRM)** manages the lifecycle of CRMs deployed on edge sites.

- The **Distrbuted Matching Engine (DME)** provides the API endpoint for mobile device clients to discover existing application instances, provide operator-specific services like location APIs, and push notifications to mobile devices via a persistent connection.

- The **ClusterSvc** service automatically deploys additional applications to clusters to enable monitoring, metrics, and storage.

- The **EdgeTurn** service is much like a TURN server, providing secure console and shell access to virtual machines and containers deployed on cloudlets.

- **Shepherd** deploys alongside the CRM (Cloudlet Resource Manager) on cloudlet infrastructure for advanced metrics and alerts.

- The **AutoProv** service monitors auto-provision policies and automatically deploys and undeploys application instances based on client demand.

# Edge-Cloud Infrastructure Platform Code

Infrastructure specific code is packaged under an interface to allow for new infrastructures to be supported without needing to modify the edge-cloud platform code.

## Currently supported infrastructures are:

### VM-Based:

- Openstack
- VMWare VSphere
- VMWare Cloud Director (VCD)
- VMPool (a bunch of VMs)
- Amazon Web Services (AWS) EC2

### Kubernetes Based:

- Amazon Web Services (AWS) EKS
- Google Cloud Platform (GCP) GKE
- K8S Bare Metal (primarily but not limited to Google Anthos)
- Microsoft Azure Kubernetes Service (AKS)

# Compiling

To build the platform services, you will need [Go](https://www.golang.org/) and [protoc](https://grpc.io/docs/protoc-installation/) installed. Please see [go.mod](go.mod) for the correct version of golang to install. Ensure that your [GOPATH](https://golang.org/doc/code.html#GOPATH) is set.

You will need to build the tools once first:

``` shell
make tools
```

You will need to have the [edge-proto repo](https://github.com/edgexr/edge-proto) checked out adjacent to this repo.

Then to compile the services:

``` shell
make
```

# Testing

There are an extensive set of unit tests. Some unit tests depend on local installations of supporting open source projects and databases. You will need to install [docker](https://www.docker.com/), [certstrap](https://github.com/square/certstrap), [Etcd](https://etcd.io/), [Redis](https://redis.io/), [Vault](https://www.vaultproject.io/), and [Influxdb](https://www.influxdata.com/). See the [test setup script](test/test_setup.sh).

``` shell
make unit-test
```

# Building Images

Scripts for building container images are in `/build/docker`. You will need to have [docker](https://www.docker.com/) installed on your machine. You may need to set the `REGISTRY` environment variable to the registry and parent path to push to, i.e.

```shell
export REGISTRY=ghcr.io/edgexr
```

``` shell
cd build/docker
make build-platform
```

To build without pushing:
``` shell
make build-platform-local
```

# Development

Please see [README_dev.md](./README_dev.md) for getting started
on understanding the code and contributing improvements.
