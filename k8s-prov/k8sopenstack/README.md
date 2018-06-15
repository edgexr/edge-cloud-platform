# K8s provisioning on openstack

k8sopenstack package provides APIs to allow instantiating a kubernetes cluster on openstack.

The API requires platform environment to be setup.

The file `install-env-files.sh` shows example of copying various files to `$HOME` directory to be used.
The `_k8sopenstack.env` is used to set up environment variables used by the API.
The `_k8sopenstack.toml` is used to configure the default values and configuration for the API.
The `_k8sopenstack.os.env` is used to set up environment variables for the openstack platform being used.
The `_k8sopenstack.userdata` is used by API when creating VM instances for use with `cloud-init`.

The API is mainly used by `openstack-tenant/agent` server which runs on the controller machine of the openstack based cloudlet.
