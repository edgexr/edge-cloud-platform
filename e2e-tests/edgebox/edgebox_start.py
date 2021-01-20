#!/usr/bin/env python

import os
import subprocess
import sys

from master_controller import MC

# Handle incompatibility between Pythons 2 and 3
try:
    input = raw_input
except NameError:
    pass

setupfile = "../setups/edgebox.yml"
create_testfile = "../testfiles/edgebox_create.yml"
deploy_testfile = "../testfiles/edgebox_deploy.yml"
varsfile = "./edgebox_vars.yml"

def create_provisioning(mc):
    mc.banner("Provisioning cloudlet")
    cmd = ["e2e-tests", "-testfile", create_testfile, "-setupfile", setupfile,
           "-varsfile", varsfile, "-notimestamp", "-outputdir", mc.outdir]
    p = subprocess.Popen(" ".join(cmd), stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                         shell=True, universal_newlines=True)
    out, err = p.communicate()
    print("Create cloudlet complete: {0}".format(out))
    if p.returncode != 0 or err:
        sys.exit("Error: {0}".format(err))
    if "Failed Tests" in out:
        sys.exit("Error provisioning cloudlet")

def generate_access_key(mc):
    mc.banner("Generating access key")
    accesskey_file = os.path.join(mc.outdir, "accesskey.pem")
    accesskey = mc.get_access_key()
    with open(accesskey_file, "w") as f:
        f.write(accesskey)

def deploy_local_crm(mc):
    mc.banner("Creating local CRM")
    cmd = ["e2e-tests", "-testfile", deploy_testfile, "-setupfile", setupfile,
           "-varsfile", varsfile, "-notimestamp", "-outputdir", mc.outdir]
    p = subprocess.Popen(" ".join(cmd), stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                         shell=True, universal_newlines=True)
    out, err = p.communicate()
    print("Deploy cloudlet complete: {0}".format(out))
    if err:
        sys.exit("Error: {0}".format(err))
    if "Failed Tests" in out:
        sys.exit("Error deploying cloudlet")
   
if __name__ == "__main__":
    mc = MC(varsfile)
    mc.validate()
    mc.save()

    print("\nCreating edgebox cloudlet:")
    print(mc)
    if not mc.confirm_continue():
        sys.exit("Not starting edgebox")

    os.environ["MC_USER"] = mc.username
    os.environ["MC_PASSWORD"] = mc.password

    create_provisioning(mc)
    generate_access_key(mc)
    deploy_local_crm(mc)
