if ARGV.length != 4
  puts "Insufficient args, requires:"
  puts "knife exec run_cmd.rb <node-name> <cmd>"
  exit
end

nodes.find(:name => "#{ARGV[2]}") { |node|
  node.normal['runCmd'] = "#{ARGV[3]}"
  puts "#{node.name} Done"
  node.save
}
exit 0
