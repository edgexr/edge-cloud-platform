remote_file '/etc/THIRD-PARTY-NOTICES' do
  source 'https://apt:AP2XYr1wBzePUAiKENupjzzB9ki@artifactory.mobiledgex.net/artifactory/downloads/THIRD-PARTY-NOTICES'
  mode '0444'
  action :create
end
