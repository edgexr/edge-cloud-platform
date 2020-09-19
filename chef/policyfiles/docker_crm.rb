# Uses docker containers to setup cloudlet services

# A name that describes what the system you're building with Chef does.
name 'docker_crm'

# Where to find external cookbooks:
default_source :chef_server, "https://chef.mobiledgex.net/organizations/mobiledgex"

# run_list: chef-client will run these recipes in the order specified.
run_list 'recipe[runstatus_handler]', 'recipe[setup_infra]', 'recipe[preflight_crm_checks]', 'recipe[setup_services::docker]', 'recipe[setup_vault_ssh]'

# Specify a custom source for a single cookbook:
cookbook 'runstatus_handler', '= 1.0.0'
cookbook 'setup_infra', '= 1.0.0'
cookbook 'preflight_crm_checks', '= 1.0.0'
cookbook 'setup_services', '= 1.0.11'
cookbook 'docker', '= 6.0.3'
cookbook 'setup_vault_ssh', '= 1.0.0'

# Set edgeCloudVersion (i.e. edge-cloud docker base image version) for all the cloudlets
override['main']['edgeCloudVersion'] = '2020-08-11'
# By default, commercialCerts is not on. Hence add override to turn it on for all the cloudlets
override['main']['crmserver']['args']['commercialCerts'] = ""
