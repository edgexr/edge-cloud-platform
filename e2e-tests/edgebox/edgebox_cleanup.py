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

varsfile = "./edgebox_vars.yml"

def cleanup_docker(mc):
    mc.banner("Cleaning up docker containers")
    p = subprocess.Popen(["docker", "ps", "-a", "-q"], stdout=subprocess.PIPE,
                         universal_newlines=True)
    out, err = p.communicate()
    for container in out.splitlines():
        print("Deleting docker container " + container)
        subprocess.call(["docker", "stop", container])
        subprocess.call(["docker", "rm", container])

    mc.banner("Cleaning up docker networks")
    p = subprocess.Popen(["docker", "network", "list", "--format", "{{.Name}}"],
                         stdout=subprocess.PIPE, universal_newlines=True)
    out, err = p.communicate()
    for network in out.splitlines():
        if "kubeadm" in network:
            print("Deleting docker network " + network)

def cleanup_crm(mc):
    mc.banner("Killing CRM process")
    p = subprocess.Popen(["ps", "-e", "-o", "pid,args"], stdout=subprocess.PIPE,
                         universal_newlines=True)
    out, err = p.communicate()
    for line in out.splitlines():
        (pid, args) = line.split(None, 1)
        if not args.startswith("crmserver "):
            continue
        if '"' + mc.cloudlet + '"' not in args:
            continue
        subprocess.call(["kill", "-9", pid])
        break

if __name__ == "__main__":
    mc = MC(varsfile)
    print("\nClean up edgebox cloudlet:")
    print(mc)
    if not mc.confirm_continue():
        sys.exit("Cleanup aborted")

    # Load user credentials
    mc.username
    mc.password

    for c in mc.get_cluster_instances():
        cluster = c["key"]["cluster_key"]["name"]
        cluster_org = c["key"]["organization"]

        for a in mc.get_app_instances(cluster, cluster_org):
            app_name = a["key"]["app_key"]["name"]
            app_vers = a["key"]["app_key"]["version"]
            app_org = a["key"]["app_key"]["organization"]

            mc.banner("Deleting app {0}@{1}".format(app_name, app_vers))
            mc.delete_app_instance(cluster, cluster_org, app_name, app_org, app_vers)

        mc.banner("Deleting cluster {0}".format(cluster))
        mc.delete_cluster_instance(cluster, cluster_org)

    mc.banner("Deleting cloudlet {0}".format(mc.cloudlet))
    try:
        mc.delete_cloudlet()
    except Exception as e:
        if "not found" in str(e):
            # Cloudlet has already been deleted
            print("Cloudlet does not exist")
        else:
            raise e

    cleanup_docker(mc)
    cleanup_crm(mc)
