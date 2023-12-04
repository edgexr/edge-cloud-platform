# Openstack Platform Notes

## IPv6 Dual Stack

### Adding Fixed IP to existing Port does not update ConfigDrive

When enabling IPv6 for existing VM instances, we add a new fixed IP to the existing
internal port for the VM servers.

For ubuntu based servers, on first boot, ubuntu relies on a ConfigDrive based source
for cloud-init, which mounts a special drive from Openstack which contains the 
configuration for the server, including network and fixed IP information.
When a new fixed IPv6 IP is added to the port, the config drive information is not
updated. So even if the server's cloud-init is reset and re-run, it does not pick up
any new networking info for the new port.

This issue only affects VM-AppInst based instances, as other VMs are our own Ubuntu
base image under our control, so we can ssh in and update the netplan configuration
programmatically.

VM-AppInst instances need to be updated manually by the developer who owns the VM.
They can find the new configuration by querying from the VM the special endpoint
`curl http://169.254.169.254/openstack/latest/network_data.json`

### DHCPv6 and our Single Internal Network

Our network topology is to use a single internal network to connect all load balancers
and tenant VMs. We segment the network by subnets. This is designed to work for IPv4,
but does not work well in IPv6. In IPv4, network configuration can be set per server
by DHCP. However, in IPv6, the DHCP procotol no longer specifies the default gateway.

That functionality has been moved to radvd (router advertisement daemon), and this
daemon is the basis for SLAAC based auto-configuration of network IP, gateway, etc.
Becuase it is stateless, SLAAC does not provide for per-server MAC Address based
configuration, so cannot segment a single network. In this case, any LB on the shared
internal network that is configured with radvd will advertise for the entire network.
So a single shared LB and multiple dedicated LBs will have conflicting advertisements.
So we cannot use radvd in our current network topology.