# Set ES_SERVER_URLS environment variable
services = ['crmserver', 'shepherd']
services.each { |service|
  deployTag = node.normal[service]['args']['deploymentTag']
  unless node.normal[service]['env'].any? { |s| s.include?('ES_SERVER_URLS') }
    Chef::Log.info("Setting ES_SERVER_URLS env var for #{service} belonging to #{deployTag} setup...")
    if deployTag == "main"
      node.normal[service]['env'].append("ES_SERVER_URLS=https://events.es.mobiledgex.net/")
    else
      node.normal[service]['env'].append("ES_SERVER_URLS=https://events-#{deployTag}.es.mobiledgex.net/")
    end
  end
}
