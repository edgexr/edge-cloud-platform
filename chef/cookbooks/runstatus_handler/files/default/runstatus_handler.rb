require "chef/log"

class Chef::Handler::RunStatusHandler < Chef::Handler

  def report
    _node = Chef::Node.load(node.name)
    _node.normal[:runstatus] = {}

    _node.normal[:runstatus][:status] = run_status.success? ? 'success' : 'failed'

    _node.normal[:runstatus][:start]   = run_status.start_time
    _node.normal[:runstatus][:end]     = run_status.end_time

    _node.normal[:runstatus][:backtrace] = run_status.backtrace
    _node.normal[:runstatus][:exception] = run_status.exception

    _node.normal[:runstatus][:resources] = []
    Array(run_status.all_resources).each do |resource|
      if resource.action.include?"nothing".to_sym
        next
      end

      if !resource.executed_by_runner
        next
      end

      Chef::Log.info("recipe[#{resource.cookbook_name}::#{resource.recipe_name}] ran '#{resource.action}' on #{resource.resource_name}['#{resource.name}']")

      _node.normal[:runstatus][:resources] << {
        :cookbook_name => resource.cookbook_name,
        :recipe_name   => resource.recipe_name,
        :action        => resource.action,
        :resource      => resource.name,
        :resource_type => resource.resource_name,
	:updated       => resource.updated,
      }
    end

    # Save attributes to node unless overridden runlist has been supplied
    if Chef::Config.override_runlist
      Chef::Log.warn('Skipping final node save because override_runlist was given')
    else
      _node.save
    end
  end
end
