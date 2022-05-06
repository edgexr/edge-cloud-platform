# What is the base VM image

The base VM image is used on VM-based cloudlets like Openstack, VMWare VCD, etc. The Edge Cloud platform will deploy one VM initially, which will run the CRM and Shepherd. For cloudlets that do not make the VM orchestrator API publicly reachable, the Edge Cloud platform will generate a Heat stack which the operator can use to deploy the initial VM with the CRM and Shepherd. The CRM will then deploy other VMs to run load balancers, clusters, and customer applications.

All VMs that the Edge Cloud platform deploys are instances of the base VM image, tailored at runtime via cloudinit configurations.

# Build the mobiledgex debian package

We use a debian package to include any software and scripts that need to be added to the vanilla ubuntu VM image. This package must be built first and uploaded to an artifactory respository. Adjust `edge-cloud-infra/openstack-tenant/packages/build.sh` to change where the debian package is uploaded to.

On Macos, install dpkg.
```
brew install dpkg
```
Build the mobiledgex debian package. The mobiledgex debian package version determines the base image version, so update it if needed.
```
cd edge-cloud-infra/openstack-tenant/packages/mobiledgex
vi Makefile         # Update the "VERSION"
vi dependencies     # If you need to update package dependencies
make clean
make
```

If you do not have your artifactory credentials in the file ~/.artifactory.creds, "make" will prompt you to enter your username and password.
Also, make will fail to publish the package if a package of the same version is already present in Artifactory.  Normally, this means you need to update the VERSION in Makefile, but just in case you are republishing the same package (because you rebuilt it with different dependencies, for instance), then delete the old package version ("mobiledgex_XXX_amd64.deb") manually from packages/pool in Artifactory before running make again.

# Building a base VM image using packer

## Prerequisites

First, install `packer` from hashicorp. https://www.packer.io/docs/install/index.html

Second, make sure you have a working openstack cluster and the openstack client installed. The build scripts pull the Ubuntu image from this glance, and also publishes the new image to the same place. The build script pulls a vanilla Ubuntu image (`ubuntu-18.04-server-cloudimg-amd64.img`) so that image must exist in glance, or the build.sh script needs to be updated with the correct image. More images can be found at https://cloud-images.ubuntu.com.

Openstack client install for Macos:

```
pip3 install python-openstackclient

## If you get an error like: `ERROR: Cannot uninstall 'six'. It is a distutils`, try:
pip3 install python-openstackclient --ignore-installed six --user
pip3 install python-heatclient
pip3 install gnocchiclient
```

To check out what images are currently available in openstack glance, do 
```
openstack image list
```

## Build and publish base VM

Run the build script passing your artifactory username and the version of the mobiledgex package built in the previous step. For example:
```
cd edge-cloud-infra/openstack-tenant/packer
./build.sh -u venky.tumkur -t 3.0.0
```

This will take some time to build, at the end of which, the new base image will be available in glance. The script will also publish the base image to Artifactory.

Note: Publishing the base image involves downloading the base image from glance to your local workstation, and then uploading it to Artifactory. If your local internet connection is a bottleneck, you can skip this step (or abort it while it is running) and do the glance download and Artifactory upload from a VM in the cloud or a cloud shell.

## Build the Base Image for other platform flavors

Repeat the previous step passing the following additional arguments to build.sh:

```
$ ./build.sh -u venky.tumkur -t 3.0.0 -p vcd
...
 
$ ./build.sh -u venky.tumkur -t 3.0.0 -p vsphere
...
```

## Update the Chef Policy

If the APT repo snapshot has changed, update the chef recipe which updates the mobiledgex package.

```
$ cd edge-cloud-infra/chef
 
### Update the APT URL in the "apt_repository bionic" chef cookbook task
$ vi cookbooks/upgrade_mobiledgex_package/recipes/default.rb
### Eg: https://apt.mobiledgex.net/cirrus/2021-02-01
 
### Update the cookbook "version"
$ vi cookbooks/upgrade_mobiledgex_package/metadata.rb
 
### Upload updated cookbook
$ knife upload --chef-repo-path $PWD cookbooks/upgrade_mobiledgex_package
 
### Verify that the updated cookbook is present in the server
$ knife cookbook show upgrade_mobiledgex_package
 
### Update the "upgrade_mobiledgex_package" cookbook version in the "base.rb" policy
$ vi policyfiles/base.rb
 
### Regenerate the lock file
$ rm policyfiles/base.lock.json
$ chef install policyfiles/base.rb
```

# !!! Push the updated policy ONLY AFTER all the supporting code has been rolled out !!!
* Make sure any relevant platform updates are complete
* Push the policy to the specific group ("main", "stage", "qa", or "dev")
  * `chef push $POLICY_GROUP policyfiles/base.lock.json`

# Code Changes

Update the base image version in `vmlayer/props.go`.

# Troubleshooting

Build fails with package dependency issues
```
openstack: The following packages have unmet dependencies:
openstack:  mobiledgex : Depends: kubeadm (= 1.16.2-00) but 1.16.3-00 is to be installed
openstack:               Depends: kubectl (= 1.16.2-00) but 1.16.3-00 is to be installed
openstack:               Depends: kubelet (= 1.16.2-00) but 1.16.3-00 is to be installed
openstack: E: Unable to correct problems, you have held broken packages.
```
This indicates that the dependencies in the mobiledgex package need to be updated. Rebuild the mobiledgex package with updated dependencies.
