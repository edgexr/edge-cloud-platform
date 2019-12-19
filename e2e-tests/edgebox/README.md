Edge-in-box is a deployment scenario for demos and hackathons in which a 
MobiledgeX laptop becomes a cloudlet.   The CRM runs locally on the Mac and 
connects to a central controller.  The standard UI can be used to deploy clusters
and apps on the cloudlet once it is running.  

There are 2 scripts to be used here:
1) edgebox_start.py:  Prompts the user for how to set up the cloudlet, including what
MC and controller to connect to, and details about the cloudlet location, operator, name.

Default values are taken from edgebox_vars.yml and then edgebox_vars.yml is updated and used
as input into e2e-tests in order to do the deployment.

2) edgebox_cleanup.py: Deletes everything both locally and at the central controller related to the cloudlet
