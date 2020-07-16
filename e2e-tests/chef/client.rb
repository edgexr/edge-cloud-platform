current_dir       = File.expand_path(File.dirname(__FILE__)) 
log_level         :info
log_location      STDOUT
file_cache_path   "/tmp"
cookbook_path     "#{current_dir}/../../chef/cookbooks"
client_key        "/tmp/chef_client_key.pem"
validation_key    "/tmp/validation_key.pem"
chef_server_url   "http://127.0.0.1:8889/organizations/mobiledgex"
