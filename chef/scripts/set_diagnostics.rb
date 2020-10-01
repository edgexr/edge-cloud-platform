if ARGV.length != 5
  puts "Insufficient args, requires:"
  puts "knife exec set_diagnostics.rb <node-name> <tar-file-name> <artifactory-token>"
  exit
end

nodes.find(:name => "#{ARGV[2]}") { |node|
  node.normal['artifactoryPath'] = "https://artifactory.mobiledgex.net/artifactory/cloudlet-diagnostics/#{ARGV[3]}"
  node.normal['artifactoryToken'] = "#{ARGV[4]}"
  puts "#{node.name} Done"
  node.save
}
exit 0
