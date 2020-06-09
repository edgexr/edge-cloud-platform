execute("Verify controller's notify port is reachable") do
  action "run"
  retries 3
  retry_delay 10
  addrParts = node['notifyAddrs'].split(':')
  command "nc #{addrParts[0]} #{addrParts[1]} -z -w 10"
  returns 0
end

if node.key?("infraApiAddr")
  execute("Verify API endpoint is reachable") do
    action "run"
    retries 3
    retry_delay 10
    command "nc #{node['infraApiAddr']} #{node['infraApiPort']} -z -w 10"
    returns 0
  end
end
