# Edge-Cloud Infrastructure Platform Code

This repository provides infrastructure and platform specific code for managing virtual machines, Kubernetes clusters, and containers based on the APIs provided by the cloudlet's infrastructure platform.

Additionally, advanced platform features are also relegated to this repository, such as auto-provisioning, user management and RBAC, and billing.

## Plugin Model

In order to separate out platform support which is intended to be closed-source from the Edge-Cloud services that may one day be open-sourced, we use go plugins to dynamically load platform support code into the Edge-Cloud services. This approach also allows external customers and developers to develop their own infrastructure-specific support, without requiring modification of the Edge-Cloud platform code.

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

## Additional Edge-Cloud Services

- The **Master Controller** provides user management, RBAC, and region management. The Controller's APIs are exposed with authorization based on permissions by organization, and support for multiple regions.

- **Shepherd** deploys alongside the CRM (Cloudlet Resource Manager) on cloudlet infrastructure for advanced metrics and alerts.

- The **AutoProv** service monitors auto-provision policies and automatically deploys and undeploys application instances based on client demand.
