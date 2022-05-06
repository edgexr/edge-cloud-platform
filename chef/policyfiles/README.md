# PolicyFiles

* Defines which recipes (versions), run-lists (list of scripts to be run) will run on node. This file is used to segregate between different setups (prod/dev/qa). It generates a lock file to lock the versions and dependencies 
* Policyfile.lock.json describes:
  * The versions of cookbooks in use
  * A Hash of cookbook content
  * The source for all cookbooks
* A Policyfile.lock.json file is associated with a specific policy group, i.e. is associated with one (or more) nodes that use the same revision of a given policy. This policy group in our case is the deployment tag i.e. prod/dev/qa/staging etc

## Commands
* Any change in policyfile requires us to generate a new lock.json file. Following are steps to generate a new lock.json file:
  * Remove any existing lock.json file
  * Execute `chef install <policyfile.rb>`
* To push/associate a policyfile with a policy group, execute the following command:
  * `chef push <policy-group> <policyfile.rb>`

## Reference
https://docs.chef.io/policyfile/
