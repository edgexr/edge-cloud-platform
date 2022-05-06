# Copyright 2022 MobiledgeX, Inc
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

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
    mexReleases = data_bag('mex_releases')
    if mexReleases.include?(node['edgeCloudVersion'])
      releaseMaps = data_bag_item('mex_releases', node['edgeCloudVersion'])
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

  # Set appDNSRoot attribute for all the services
  appDNSRoot = "mobiledgex.net"
  if deployTag == "qa" || deployTag == "dev"
    appDNSRoot = "mobiledgex-#{deployTag}.net"
  end
  unless node.normal[service]['args']['appDNSRoot'] == appDNSRoot
    Chef::Log.info("Setting appDNSRoot for #{service} to #{appDNSRoot}...")
    node.normal[service]['args']['appDNSRoot'] = appDNSRoot
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
