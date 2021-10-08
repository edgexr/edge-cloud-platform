# Set up apt cert validation
file '/etc/apt/apt.conf.d/10cert-validation' do
  content "Acquire::https::Verify-Peer \"#{node['aptCertValidation']}\";\n"
  action :create
end

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
      uri 'https://apt.mobiledgex.net/cirrus/2021-10-05'
      distribution 'bionic'
      components ['main']
    end
    apt_repository 'cirrus' do
      uri 'https://artifactory.mobiledgex.net/artifactory/packages'
      distribution 'cirrus'
      components ['main']
    end
    file '/etc/apt/auth.conf.d/mobiledgex.net.conf' do
      content "machine artifactory.mobiledgex.net login apt password mobiledgex\nmachine apt.mobiledgex.net login apt password mobiledgex"
      action :create_if_missing
    end
    bash 'Unhold the mobiledgex package if exists and held' do
      code <<-EOH
        dpkg -l | grep -i mobiledgex
        if [[ $? -eq 0 ]]; then
          apt-mark unhold mobiledgex
        else
          echo "mobiledgex package doesn't exist"
        fi
      EOH
      returns 0
    end
    apt_update
    apt_package 'ca-certificates' do
      action :upgrade
    end

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
