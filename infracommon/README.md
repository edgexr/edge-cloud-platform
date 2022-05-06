# edge-cloud-infra interface

`mexos` package contains a library abstraction of interacting with different underlying cloudlet platforms as well as different target cluster/app deployment variants

Below is a high level overview of the organization of the code here.

   - `cloudletinfra.go` - contains a set of functions to initialize and manage different cloudlet infra. The cloudlet we deal with is described in edgeproto.CloudletInfraProperties. It provides the abstraction for the different platforms(azure, gcp, dind, etc) on which mobiledgex cloudlet is deployed
   - `appinst.go` - add/delete app apis for the different underlying cluster types(helm, k8s, kvm, etc.)
   - `cluster.go` - abstraction for creation/deletion of cluster instances based on the platform(k8s, gcp, azure, swarm(future), etc)
   - `const.go` - common names and other constants. In particular it contains names for the supported edgeproto.ConfigFile.Kind strings. Currently supported:
      - `AppConfigHemYaml` - yaml file with helm chart customizations
      - `AppConfigEnvYaml` - yaml file with environment variables that need to be added to the application that will be deployed. For example if a deployment that is expected of this application is Kubernetes the structure of this yaml file is assumed to be an array of k8s.io/api/core/v1.EnvVar objects.

## NOTE
This organization of the `mexos` package has grown organically, hence there is a fair bit of redundant code. Hence a refactor will eventually need to happen which will affect the content of this README