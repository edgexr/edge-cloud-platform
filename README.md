# Edge-Cloud Platform

The Edge-Cloud Platform is a set of services that allow for distributed and secure management of edge sites ("cloudlets"), featuring deployment of workloads, one-touch provisioning of new cloudlets, monitoring, metrics, alerts, events, and more.

## Services

- The **Controller** provides the API endpoint for, and manages creating, updating, deleting, and showing application definitions, cloudlets, clusters, application instances, policies, etc. It manages object dependencies and validation, stores objects in Etcd, and distributes objects to other services that need to be notified of data changes.

- The **Cloudlet Resource Manager (CRM)** manages infrastructure on a cloudlet site, calling the underlying infrastruture APIs to instantiate virtual machines, docker containers, kubernetes clusters, or kubernetes applications, depending on what the actual infrastructure type supports.

- The **Distrbuted Matching Engine (DME)** provides the API endpoint for mobile device clients to find existing application instances, provide operator-specific services like location APIs, and pushes notifications to mobile devices via a persistent connection.

- The **ClusterSvc** service automatically deploys additional applications to clusters to enable monitoring, metrics, and storage.

- The **EdgeTurn** service is much like a TURN server, providing secure console and shell access to virtual machines and containers deployed on cloudlets.

- The **Master Controller** provides user management, RBAC, and region management. The Controller's APIs are exposed with authorization based on permissions by organization, and support for multiple regions.

- **Shepherd** deploys alongside the CRM (Cloudlet Resource Manager) on cloudlet infrastructure for advanced metrics and alerts.

- The **AutoProv** service monitors auto-provision policies and automatically deploys and undeploys application instances based on client demand.

## Checking Out Code and Building

Please see [Getting Started](https://mobiledgex.atlassian.net/wiki/spaces/SWDEV/pages/22478869/Getting+Started).

## Running unit tests

``` shell
make unit-test
```

## Running e2e (end-to-end) tests

Make sure you have installed required third party services as noted in the getting started guide. This runs the above services, and any required third party services locally, and stimuates the platform via the public APIs to do end-to-end testing.

``` shell
make test
```
or, to stop on error:

``` shell
make test-debug
```

## Running local KIND test

This is similar to the e2e test above, except instead of fake cloudlet platforms, it uses a KIND (Kubernetes IN Docker) cluster to simulate a cloudlet with a single Kubernetes cluster locally. There are two commands, one to start the local processes, and one to stop.

``` shell
# start processes
make test-kind-start
# stop processes
make test-kind-stop
```
# Edge-Cloud Infrastructure Platform Code

Infrastructure specific code is packaged under a plugin to allow for new infrastructures to be supported without needing to modify the edge-cloud platform code.

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
