# initializing mobiledgex qcow2 kvm image runtime

The mobiledgex-16.04.qcow2 image is built from ubuntu-16.04 server ISO image 
to be runnable on Openstack.
This image is stored on the packer.net machine under /opt/stack/ dir.
This image can be added to glance and used to create VM instances that can
be reasonably provisioned.

Because of various bugs with `cloud-init` we are leveraging a part of
the cloud-init feature that works, along with `config-drive` feature.

The `mobiledgex.service` is installed into systemd so that the
service will run at boot time to mount the config drive.

The `userdata.txt` content is available under `config-drive` thus mounted.

The script  `mobiledgex-init.sh` is install in /usr/local/bin/.  It is
run by the `mobiledgex.service` at boot time. This script mounts the `config-drive`.

The contents of interest are:

```
# ls -R /mnt/mobiledgex-config/openstack/latest
/mnt/mobiledgex-config/openstack/latest:
meta_data.json  network_data.json  user_data  vendor_data2.json  vendor_data.json
```

The `mobiledgex-init.sh` script uses data from meta_data.json, network_data.json
and user_data to initialize the runtime of the KVM instance.

This allows customization of the KVM runtime instance which is run as an example,

```
openstack server create --image mobiledgex-16.04 --flavor m1.large --user-data userdata.txt  --nic net-id=630a8e5e-6031-4d1a-a16c-314c893f009d,v4-fixed-ip=172.24.4.23 --config-drive true --file edgeconfig=/tmp/edgeconfig  --property edgeproxy=172.24.4.1  public-3
```

The `net-id` is as printed by `openstack network list`. One of the neutron networks created.

The `v4-fixed-ip` is IP you want the KVM instance to be. 

The `property` is the host side IP where the edge proxy resides.

The `user-data` is the for the `cloud-init` but it is not directly used. It is used via `config-drive`. Notice
the `config-drive true`. This allows the visibility of the synthetic config drive feature.
It is mounted via CDROM iso9660 file system on /dev/sr0.

