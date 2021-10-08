# MobiledgeX package version
defaultMobiledgeXPackageVersion = '4.7.0'

node.default["aptCertValidation"] = false
if node.attribute?("mobiledgeXPackageVersion")
  curSemver = Gem::Version.new(node["mobiledgeXPackageVersion"])
  certValSemver = Gem::Version.new("4.7.0")
  if curSemver >= certValSemver
    node.default["aptCertValidation"] = true
  end
end

if node.normal['tags'].include?('vmtype/rootlb')
  if !node.attribute?("mobiledgeXPackageVersion") || node.normal["mobiledgeXPackageVersion"] != defaultMobiledgeXPackageVersion
    node.normal["mobiledgeXPackageVersion"] = defaultMobiledgeXPackageVersion
  end
end
