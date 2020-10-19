# Used to manage cloudlets not brought up by chef

# A name that describes what the system you're building with Chef does.
name 'debug_crm'

# Where to find external cookbooks:
default_source :chef_server, "https://chef.mobiledgex.net/organizations/mobiledgex"

# run_list: chef-client will run these recipes in the order specified.
run_list 'recipe[runstatus_handler]', 'recipe[run_cmd]', 'recipe[run_diagnostics]'

# Specify a custom source for a single cookbook:
cookbook 'runstatus_handler', '= 1.0.0'
cookbook 'run_cmd', '= 1.0.0'
cookbook 'run_diagnostics', '= 1.0.0'
