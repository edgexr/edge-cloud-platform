unified_mode true
resource_name :teleport
provides :teleport

property :node_name, String, name_property: true
property :initial_token, String, default: ''
property :operator, String, default: 'ops'

property :teleport_url, String, default: 'https://apt:AP2XYr1wBzePUAiKENupjzzB9ki@artifactory.mobiledgex.net/artifactory/downloads/teleport/v8.2.0/teleport'
property :teleport_checksum, String, default: 'ed2e0d6282597a1aa4d8963a2bd3ed9a270d6f177108087eb5b962d249dbdfa5'
property :teleport_auth_server, String, default: 'teleport.mobiledgex.net:443'
property :teleport_diag_port, Fixnum, default: 31701

# Install and configure the teleport service
action :setup do

    # Install teleport
    remote_file '/usr/local/bin/teleport' do
        source      new_resource.teleport_url
        checksum    new_resource.teleport_checksum
        mode        '0755'
        action      :create
    end

    # Write the teleport initial token to a file
    file '/etc/teleport.token' do
        content new_resource.initial_token
        mode    '0400'
        owner   'root'
        group   'root'

        notifies :restart, "teleport[#{new_resource.node_name}]", :delayed
    end

    # Set up systemd service
    systemd_unit 'teleport.service' do
        content({
            Unit: {
                Description: "Teleport SSH service for #{new_resource.operator}",
                After: 'network.target',
            },
            Service: {
                Type: 'simple',
                Restart: 'on-failure',
                ExecStart: "/usr/local/bin/teleport start --roles=node --nodename=#{new_resource.node_name} --labels=env=ops,operator=#{new_resource.operator} --token=/etc/teleport.token --auth-server=#{new_resource.teleport_auth_server} --diag-addr=127.0.0.1:#{new_resource.teleport_diag_port}",
                ExecReload: '/bin/kill -HUP $MAINPID',
                PIDFile: '/run/teleport.pid',
            },
            Install: {
                WantedBy: 'multi-user.target',
            }
        })
        action [:create, :enable, :start]
    end

    # Set up healthcheck cronjob
    cron 'teleport_healthcheck' do
        command "curl -s http://127.0.0.1:#{new_resource.teleport_diag_port}/readyz | grep -q '\"ok\"' || systemctl restart teleport"
        minute  '*/5'
    end

end

# Restart the teleport service
action :restart do

    systemd_unit 'teleport.service' do
        action :restart
    end

end

action :destroy do

    # Disable healthcheck cronjob
    cron 'teleport_healthcheck' do
        action :delete
    end

    # Remove systemd service
    systemd_unit 'teleport.service' do
        action [:stop, :disable, :delete]
    end

    # Delete teleport config directory
    directory '/var/lib/teleport' do
        action      :delete
        recursive   true
    end

    # Delete teleport initial token file
    file '/etc/teleport.token' do
        action :delete
    end

    # Delete teleport binary
    file '/usr/local/bin/teleport' do
        action :delete
    end

end
