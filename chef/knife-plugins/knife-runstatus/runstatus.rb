module MyKnifePlugins

  class NodeRunListStatus < Chef::Knife

    banner "knife node run-list status NODE"

    deps do
      require 'highline'
    end

    def h
      @highline ||= HighLine.new
    end

    def run
      if name_args.size == 1
        role = name_args.first
      else
        ui.fatal "Please provide a node name to get run-list status for"
        exit 1
      end

      node = Chef::Node.load(@node_name)
      if node.nil?
        ui.msg "Could not find a node named #{@node_name}"
        exit 1
      end

      unless node[:runstatus]
        ui.msg "no information found for runstatus on #{@node_name}"
        exit
      end

      # time
      time_entries = header('Status', 'Start Time', 'End Time');

      time_entries << node[:runstatus][:status]
      time_entries << node[:runstatus][:start].to_s
      time_entries << node[:runstatus][:end].to_s
      ui.msg h.list(time_entries, :columns_down, 2)
      ui.msg "\n"

      # resources
      log_entries = header('Recipe', 'Action', 'Resource Type', 'Resource', 'Updated');

      node[:runstatus][:resources].each do |log_entry|
        log_entries << "#{log_entry[:cookbook_name]}::#{log_entry[:recipe_name]}"
        [:action, :resource_type, :resource, :updated].each do |entry|
          log_entries << log_entry[entry].to_s
        end
      end

      ui.msg h.list(log_entries, :uneven_columns_across, 5)
      ui.msg "\n"

      # debug stuff
      debug_entries = []
      debug_entries << h.color('Backtrace', :bold)
      debug_entries << (node[:runstatus][:backtrace] ? node[:runstatus][:backtrace].join("\n") : "none")
      debug_entries << ""

      debug_entries << h.color('Exception', :bold)
      debug_entries << (node[:runstatus][:exception] ? node[:runstatus][:exception].strip : "none")
      ui.msg h.list(debug_entries, :rows)
      ui.msg "\n"
    end
    def header(*args)
        entry = []
        args.each do |arg|
          entry << h.color(arg, :bold)
        end
        entry
    end
  end
end
