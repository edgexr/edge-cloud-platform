# MobiledgeX package version
defaultMobiledgeXPackageVersion = '4.3.4'

if node.normal['tags'].include?('vmtype/rootlb')
  if !node.attribute?("mobiledgeXPackageVersion") || node.normal["mobiledgeXPackageVersion"] != defaultMobiledgeXPackageVersion
    node.normal["mobiledgeXPackageVersion"] = defaultMobiledgeXPackageVersion
  end
end
