require 'uri'

unified_mode true
resource_name :mobiledgex_apt_repository
provides :mobiledgex_apt_repository

property :cert_validation, [TrueClass, FalseClass], default: true

property :main_repo_url, String, name_property: true
property :main_repo_distribution, String, default: "bionic"
property :main_repo_components, Array, default: ["main"]

property :artifactory_repo_url, String, default: "https://artifactory.mobiledgex.net/artifactory/packages"
property :artifactory_repo_distribution, String, default: "cirrus"
property :artifactory_repo_components, Array, default: ["main"]

# Set up the apt repository
action :setup do

    # Set up apt cert validation
    file '/etc/apt/apt.conf.d/10cert-validation' do
        content "Acquire::https::Verify-Peer \"#{new_resource.cert_validation}\";\n"
        action :create
    end

    # Make sure the source list is empty
    file "/etc/apt/sources.list" do
        content ""
    end

    # Make sure the apt sources directory is present
    directory "/etc/apt/sources.list.d" do
        owner   "root"
        group   "root"
        mode    "0755"
        action  :create
    end

    # Set up credentials for apt repositories
    apt_repo_urls = [ new_resource.main_repo_url, new_resource.artifactory_repo_url ]
    apt_repos = data_bag('apt_repos').sort.map do |r|
        data_bag_item('apt_repos', r) if apt_repo_urls.any? {|u| URI(u).host == r}
    end.compact

    template '/etc/apt/auth.conf.d/mobiledgex.net.conf' do
        source  "apt-auth.erb"
        owner   "root"
        group   "root"
        mode    "0400"
        variables(repos: apt_repos)
    end

    # Set up the main apt repository
    apt_repository new_resource.main_repo_distribution do
        uri             new_resource.main_repo_url
        distribution    new_resource.main_repo_distribution
        components      new_resource.main_repo_components
    end

    # Set up the artifactory apt repository
    apt_repository new_resource.artifactory_repo_distribution do
        uri             new_resource.artifactory_repo_url
        distribution    new_resource.artifactory_repo_distribution
        components      new_resource.artifactory_repo_components
    end

end
