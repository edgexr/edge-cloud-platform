class Chef
  class Recipe
    def extract_cmd(service, argsmap, joincmd, skipcmd)
      if skipcmd
        args = []
      else
        args = [service]
      end
      argsmap.keys.each do |x|
        if node[service]["args"].key?(x)
          args += ["--#{x}"]
          if !node[service]["args"][x].empty?
            if joincmd
              args[-1] = args[-1] + "=#{node[service]['args'][x]}"
            else
              args += ["'" + "#{node[service]['args'][x]}" + "'"]
            end
          end
        end
      end
      cmd = args.join(" ") 
      cmd
    end

    def crmserver_cmd()
      # Hash of:
      #   Key = arg name
      #   Value = arg type (false means flag type)
      argsmap = {
        "cloudletKey" => true,
        "notifyAddrs" => true,
        "notifySrvAddr" => true,
        "tls" => true,
        "platform" => true,
        "vaultAddr" => true,
        "physicalName" =>  true,
        "region" => true,
        "span" => true,
        "d" => true,
        "cloudletVMImagePath" => true,
        "vmImageVersion" => true,
        "containerVersion" => true,
        "commercialCerts" => false,
        "useVaultCAs" => false,
        "useVaultCerts" => false,
        "chefServerPath" => true,
        "deploymentTag" => true,
        "upgrade" => false
      }
      cmd = extract_cmd("crmserver", argsmap, false, false) 
      cmd
    end

    def shepherd_cmd()
      # Hash of:
      #   Key = arg name
      #   Value = arg type (false means flag type)
      argsmap = {
        "cloudletKey" => true,
        "notifyAddrs" => true,
        "tls" => true,
        "platform" => true,
        "vaultAddr" => true,
        "physicalName" =>  true,
        "region" => true,
        "span" => true,
        "d" => true,
        "useVaultCAs" => false,
        "useVaultCerts" => false,
        "chefServerPath" => true,
        "deploymentTag" => true
      }
      cmd = extract_cmd("shepherd", argsmap, false, false)
      cmd
    end

    def cloudlet_prometheus_cmd()
      # Hash of:
      #   Key = arg name
      #   Value = arg type (false means flag type)
      argsmap = {
        "config.file" => true,
        "web.listen-address" => true,
        "web.enable-lifecycle" => false,
      }
      cmd = extract_cmd("cloudletPrometheus", argsmap, true, true)
      cmd
    end
  end
end
