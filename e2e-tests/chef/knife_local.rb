current_dir = File.dirname(__FILE__)
chef_server_url   "http://127.0.0.1:8889/organizations/mobiledgex"
client_key	  "#{current_dir}/dummy_key.pem"
cookbook_path     [ "#{current_dir}/../../chef/cookbooks" ]
