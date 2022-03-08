default['upgrade_mobiledgex_package']['cert_validation'] = true

curSemver = Gem::Version.new(node['mobiledgeXPackageVersion'])
certValSemver = Gem::Version.new("4.7.0")
if curSemver < certValSemver
  default['upgrade_mobiledgex_package']['cert_validation'] = false
end
