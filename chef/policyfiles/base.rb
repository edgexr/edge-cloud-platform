# Base role for common recipes to be executed

# A name that describes what the system you're building with Chef does.
name 'base'

# Where to find external cookbooks:
default_source :chef_server, "https://chef.mobiledgex.net/organizations/mobiledgex" 

# run_list: chef-client will run these recipes in the order specified.
run_list 'recipe[runstatus_handler]', 'recipe[copy_resource_tracker]', 'recipe[upgrade_mobiledgex_package]'

# Specify a custom source for a single cookbook:
cookbook 'runstatus_handler', '= 1.0.0'
cookbook 'copy_resource_tracker', '= 1.0.1'
cookbook 'upgrade_mobiledgex_package', '= 1.0.4'
