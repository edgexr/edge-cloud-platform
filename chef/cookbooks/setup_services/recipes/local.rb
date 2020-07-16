require 'json'

services = Hash["crmserver" => crmserver_cmd, "shepherd" => shepherd_cmd]
services.each { |service,service_cmd|
  cKey = JSON.parse(node[service]['args']['cloudletKey'])
  cKeyStr = cKey["name"] + "." + cKey["organization"]

  Chef::Log.info("Starting #{service} #{cKey}")
  envvars = {}
  node[service]['env'].each { |envvar|
    keyval = envvar.split('=')
    envvars[keyval[0]] = keyval[1]
  }
  Chef::Log.info("Using envvars #{envvars}")

  cmd = service_cmd
  bash service do
    code <<-EOH
      nohup #{cmd} </dev/null >/tmp/#{cKeyStr}.#{service}.log 2>&1 &
    EOH
    environment envvars
  end
}
