ruby_block "Fetch network interfaces' name" do
    block do
      Chef::Resource::RubyBlock.send(:include, Chef::Mixin::ShellOut)
      ext_cmd = "route | grep '^default' | grep -o '[^ ]*$'"
      ext_iface_out = shell_out(ext_cmd)
      node.run_state['external_ifname'] = ext_iface_out.stdout.chomp
      int_cmd = "ifconfig | grep ens.* | awk '{print $1}' | grep -v #{node.run_state['external_ifname']}"
      int_iface_out = shell_out(int_cmd)
      node.run_state['internal_ifname'] = int_iface_out.stdout.chomp
    end
    action :create
end

iptables_rule 'Masquerade rule match' do
  action :create
  table :nat
  chain :POSTROUTING
  ip_version :ipv4
  jump 'MASQUERADE'
  out_interface lazy { node.run_state['external_ifname'] }
end

iptables_rule 'Forward external rule match' do
  action :create
  table :filter
  chain :FORWARD
  ip_version :ipv4
  jump 'ACCEPT'
  match 'state'
  extra_options '--state RELATED,ESTABLISHED'
  in_interface lazy { node.run_state['external_ifname'] }
  out_interface lazy { node.run_state['internal_ifname'] }
end

iptables_rule 'Forward internal rule match' do
  action :create
  table :filter
  chain :FORWARD
  ip_version :ipv4
  jump 'ACCEPT'
  in_interface lazy { node.run_state['internal_ifname'] }
end

# Commit iptable rules
execute "Commit iptables" do
  command "iptables-restore < /etc/iptables/rules.v4"
  action :run
end

