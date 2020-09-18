bash 'setup vault SSH' do
  Chef::Log.info("Setting up vault SSH from https://vault-#{node.policy_group}.mobiledgex.net")
  user 'root'
  code <<-EOH
  curl https://vault-#{node.policy_group}.mobiledgex.net/v1/ssh/public_key | tee /etc/ssh/trusted-user-ca-keys.pem
  grep "ssh-rsa" /etc/ssh/trusted-user-ca-keys.pem
  [[ $? -ne 0 ]] && exit 1
  isInFile=$(cat /etc/ssh/sshd_config | grep -c "TrustedUserCAKeys")
  if [ $isInFile -eq 0 ]; then
    echo 'TrustedUserCAKeys /etc/ssh/trusted-user-ca-keys.pem' | tee -a /etc/ssh/sshd_config
    systemctl reload ssh
  fi
  EOH
end

