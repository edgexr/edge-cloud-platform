# controller notify address
ctrlNotifyAddrs = node.normal['crmserver']['args']['notifyAddrs']
ctrlAddr = ctrlNotifyAddrs.split(':')[0]
# access API address
accessApiAddr = ctrlAddr + ':41001'

services = ['crmserver', 'shepherd']
services.each { |service|
  # Set ES_SERVER_URLS environment variable
  deployTag = node.normal[service]['args']['deploymentTag']
  unless node.normal[service]['env'].any? { |s| s.include?('ES_SERVER_URLS') }
    Chef::Log.info("Setting ES_SERVER_URLS env var for #{service} belonging to #{deployTag} setup...")
    if deployTag == "main"
      node.normal[service]['env'].append("ES_SERVER_URLS=https://events.es.mobiledgex.net/")
    else
      node.normal[service]['env'].append("ES_SERVER_URLS=https://events-#{deployTag}.es.mobiledgex.net/")
    end
  end

  # Set accessApiAddr attribute for all the services
  unless node.normal[service]['args'].any? { |s| s.include?('accessApiAddr') }
    Chef::Log.info("Setting accessApiAddr attribute var for #{service} to #{accessApiAddr}...")
    node.normal[service]['args']['accessApiAddr'] = accessApiAddr
  end

  # Set useVaultPki attribute for all the services
  unless node.normal[service]['args'].any? { |s| s.include?('useVaultPki') }
    Chef::Log.info("Setting useVaultPki flag for #{service}...")
    node.normal[service]['args']['useVaultPki'] = ""
  end

  # Set cacheDir attribute for crmserver
  if service == "crmserver"
    unless node.normal[service]['args'].any? { |s| s.include?('cacheDir') }
      Chef::Log.info("Setting cacheDir for #{service}...")
      node.normal[service]['args']['cacheDir'] = "/root/crm_cache"
    end
  end

  # Set commercialCerts attribute for crmserver
  if service == "crmserver"
    unless node.normal[service]['args'].any? { |s| s.include?('commercialCerts') }
      Chef::Log.info("Setting commericalCerts flag for #{service}...")
      node.normal[service]['args']['commercialCerts'] = ""
    end
  end

  # Set MEX_RELEASE_VERSION attribute for crmserver
  if service == "crmserver" && node.normal[service]['env'] != nil
    releaseMaps = data_bag_item('mex_releases', node['edgeCloudVersion'])
    if releaseMaps != nil
      releaseVers = "#{releaseMaps['release']}"
      if releaseVers != nil
        envVar = "MEX_RELEASE_VERSION=#{releaseVers}"
        unless node.normal[service]['env'].any? { |v| v =~ /MEX_RELEASE_VERSION=/ }
          Chef::Log.info("Setting #{envVar} env var for #{service}...")
          node.normal[service]['env'] << envVar
        else
          unless node.normal[service]['env'].any? { |v| v == envVar }
            Chef::Log.info("Updating #{envVar} env var for #{service}...")
            node.normal[service]['env'].delete_if { |v| v =~ /MEX_RELEASE_VERSION=/ }
            node.normal[service]['env'] << envVar
          end
        end
      end
    end
  end
}

# Set /var/tmp volume mount for cloudletPrometheus service
service = "cloudletPrometheus"
oldTmpMnt = "/tmp:/tmp"
varTmpMnt = "/var/tmp:/var/tmp"
unless node.normal[service]['volume'].any? { |s| s.include?(varTmpMnt) }
  Chef::Log.info("Setting #{varTmpMnt} volume mount for #{service}...")
  node.normal[service]['volume'].delete_if { |s| s.include?(oldTmpMnt) }
  node.normal[service]['volume'] << varTmpMnt
end
oldPromMnt = "/tmp/prometheus.yml:/etc/prometheus/prometheus.yml"
promMnt = "/var/tmp/prometheus.yml:/etc/prometheus/prometheus.yml"
unless node.normal[service]['volume'].any? { |s| s.include?(promMnt) }
  Chef::Log.info("Setting #{promMnt} volume mount for #{service}...")
  node.normal[service]['volume'].delete_if { |s| s.include?(oldPromMnt) }
  node.normal[service]['volume'] << promMnt
end
