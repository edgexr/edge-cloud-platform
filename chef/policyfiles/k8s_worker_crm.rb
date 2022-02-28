# worker nodes for k8s containers to setup cloudlet services

# A name that describes what the system you're building with Chef does.
name 'k8s_worker_crm'

# Where to find external cookbooks:
default_source :chef_server, "https://chef.mobiledgex.net/organizations/mobiledgex"

# run_list: chef-client will run these recipes in the order specified.
run_list 'chef_client_updater::default', 'recipe[runstatus_handler]', 'recipe[setup_infra]', 'recipe[preflight_crm_checks]',  'recipe[setup_services::k8s-worker]', 'recipe[chef_client_updater]', 'recipe[set_security_policies]', 'recipe[setup_teleport]'

# Specify a custom source for a single cookbook:
cookbook 'runstatus_handler', '= 1.0.0'
cookbook 'setup_infra', '= 1.0.0'
cookbook 'preflight_crm_checks', '= 1.0.0'
cookbook 'setup_services', '= 1.3.4'
cookbook 'chef_client_updater', '= 3.11.0'
cookbook 'set_security_policies', '= 1.0.0'
cookbook 'setup_teleport', '= 1.1.0'

# Set chef-client version
# IMP: Version of chef client here needs to match the version in the base image.
#      See "openstack-tenant/packages/mobiledgex/dependencies"
default['chef_client_updater']['version'] = '17.6.18'
