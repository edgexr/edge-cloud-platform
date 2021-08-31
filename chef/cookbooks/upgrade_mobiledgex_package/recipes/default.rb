if node.normal['tags'].include?('vmtype/rootlb')
  # Check installed package `dpkg -s mobiledgex | grep Version | awk -F ": " '{print $2}'`
  curTag = shell_out("dpkg -s mobiledgex | grep Version | awk -F \": \" '{printf $2}'").stdout
  # regex to get suffix from curTag(-vcd, -vsphere)
  suffix = (curTag[/(-vcd|-vsphere)$/] || "")
  unless node['mobiledgeXPackageVersion'] == curTag
    # First delete old pin file if it exists
    file '/etc/apt/preferences.d/99mobiledgex' do
      action :delete
      only_if { File.exist? '/etc/apt/preferences.d/99mobiledgex' }
    end
    # Pin mobiledge package version
    apt_preference 'mobiledgex' do
      pin "version #{node['mobiledgeXPackageVersion']}#{suffix}"
      pin_priority '1001'
    end
    # Update /etc/apt/sources.list - empty out and write to /etc/apt/soureces.list.d/ dir
    file "/etc/apt/sources.list" do
      content ""
    end
    # Make sure the apt sources directory is present
    directory "/etc/apt/sources.list.d" do
      owner "root"
      group "root"
      mode "0755"
      action :create
    end
    apt_repository 'bionic' do
      uri 'https://apt.mobiledgex.net/cirrus/2021-08-31'
      distribution 'bionic'
      components ['main']
    end
    apt_repository 'cirrus' do
      uri 'https://artifactory.mobiledgex.net/artifactory/packages'
      distribution 'cirrus'
      components ['main']
    end
    execute('Unhold the mobiledgex package, if held') do
      action "run"
      command "apt-mark unhold mobiledgex"
      returns 0
    end
    apt_update

    bash 'install-mobiledgex-deb-pkg-with-appropriate-kernel' do
      code <<-EOH
        DEBIAN_FRONTEND=noninteractive apt-get install -yq linux-image-virtual mobiledgex --allow-change-held-packages
        if [[ $? -ne 0 ]]; then
          apt --fix-broken install -yq
          if [[ $? -eq 0 ]]; then
            DEBIAN_FRONTEND=noninteractive apt-get install -yq linux-image-virtual mobiledgex --allow-change-held-packages
          fi
        fi
      EOH
    end
  end
end
