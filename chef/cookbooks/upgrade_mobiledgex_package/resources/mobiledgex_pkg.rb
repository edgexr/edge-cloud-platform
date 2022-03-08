unified_mode true
resource_name :mobiledgex_pkg
provides :mobiledgex_pkg

property :version, String, name_property: true

# Upgrade the mobiledgex package
action :upgrade do

    # Remove holds
    package %w( linux-image-virtual mobiledgex ) do
        action :unlock
    end

    # Pin the package version
    apt_preference 'mobiledgex' do
        pin "version #{new_resource.version}"
        pin_priority '1001'
    end

    # Update packages
    apt_update

    # Fix package database, install updates
    execute 'install mobiledgex' do
        command 'apt --quiet --assume-yes --fix-broken --no-remove install'
    end

    # Upgrade mobiledgex package, if still necessary
    package 'mobiledgex' do
        action :upgrade
    end

end
