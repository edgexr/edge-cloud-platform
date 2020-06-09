# Add route if required to make sure API endpoint is reachable
# This is mostly required for GDDT environments
if node.key?("infraApiGw")
  route 'Add API Endpoint Route' do
    gateway "#{node['infraApiGw']}"
    target "#{node['infraApiAddr']}/32"
  end
end
