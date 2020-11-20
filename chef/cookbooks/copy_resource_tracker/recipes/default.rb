if node.name.include? "mex-docker-vm"
  remote_file '/usr/local/bin/resource-tracker' do
    source 'https://apt:AP2XYr1wBzePUAiKENupjzzB9ki@artifactory.mobiledgex.net/artifactory/downloads/resource-tracker/v1.0.0/resource-tracker'
    checksum '703f3cf91d4fd777e620f8b3100e682bed24b84b2a348c4cb208e15d5b11e0d9'
    mode '0771' # executable
    action :create
  end
end
