import subprocess
import json
import sys
import datetime
import json
import time

# This script requires you are logged in as an admin via mcctl to the
# deployment to check. It also requires that Vault env vars are set
# so that vssh can be used.

# This script is not interactive but the output should be checked.
# There may be failures that only show up in the output but do not
# cause the script to fail.

# Test output for certsDaysLeft func
exampleOutput = """
[check-expiration] Reading configuration from the cluster...
[check-expiration] FYI: You can look at this config file with 'kubectl -n kube-system get cm kubeadm-config -oyaml'

CERTIFICATE                EXPIRES                  RESIDUAL TIME   CERTIFICATE AUTHORITY   EXTERNALLY MANAGED
admin.conf                 Jun 27, 2024 08:22 UTC   364d                                    no
apiserver                  Jun 27, 2024 08:22 UTC   364d            ca                      no
apiserver-etcd-client      Jun 27, 2024 08:22 UTC   364d            etcd-ca                 no
apiserver-kubelet-client   Jun 27, 2024 08:22 UTC   364d            ca                      no
controller-manager.conf    Jun 27, 2024 08:22 UTC   364d                                    no
etcd-healthcheck-client    Jun 27, 2024 08:22 UTC   364d            etcd-ca                 no
etcd-peer                  Jun 27, 2024 08:22 UTC   364d            etcd-ca                 no
etcd-server                Jun 27, 2024 08:22 UTC   364d            etcd-ca                 no
front-proxy-client         Jun 27, 2024 08:22 UTC   364d            front-proxy-ca          no
scheduler.conf             Jun 27, 2024 08:22 UTC   364d                                    no

CERTIFICATE AUTHORITY   EXPIRES                  RESIDUAL TIME   EXTERNALLY MANAGED
ca                      Jun 24, 2032 09:54 UTC   8y              no
etcd-ca                 Jun 24, 2032 09:55 UTC   8y              no
front-proxy-ca          Jun 24, 2032 09:54 UTC   8y              no
"""


def certsDaysLeft(output):
    expiresInDays = 99999
    for line in output.split("\n"):
        parts = line.split()
        dateEnd = 0
        for idx, val in enumerate(parts):
            if val == "UTC":
                dateEnd = idx + 1
                break
        if dateEnd == 0:
            # not a line with an expiration date
            continue
        expiresAtStr = " ".join(parts[1:dateEnd])
        expiresAt = datetime.datetime.strptime(expiresAtStr, "%b %d, %Y %H:%M %Z")
        now = datetime.datetime.now()
        expiresIn = expiresAt - now
        if expiresIn.days < expiresInDays:
            expiresInDays = expiresIn.days
    return expiresInDays


# debug certsDaysLeft func
# daysLeft = certsDaysLeft(exampleOutput)
# print(f"certs expire in {daysLeft} days")
# exit()

if len(sys.argv) < 4:
    print("Must specify domain, cloudlet name, and org")
    print("Example:")
    print("  python3 refresh-k8s-certs.py mydomain.org myCloudlet opOrg")
domain = sys.argv[1]
cloudlet = sys.argv[2]
org = sys.argv[3]
region = "EU"  # change this if needed

addr = f"https://console.{org.lower()}.{domain}"

# Get cloudletinfo
ret = subprocess.run(
    [
        "mcctl",
        "--addr",
        addr,
        "cloudletinfo",
        "show",
        f"cloudlet={cloudlet}",
        f"cloudletorg={org}",
        f"region={region}",
        "--output-format",
        "json",
    ],
    capture_output=True,
    text=True,
)
if ret.stdout == "":
    print(f"cloudlet {cloudlet} {org} in region {region} not found")
    exit()

cloudletList = json.loads(ret.stdout)
if type(cloudletList) is not list:
    print(f"expected list of cloudlets, but is {type(cloudletList)}")
    exit()
if len(cloudletList) != 1:
    print(ret.stdout)
    print(f"expected one cloudlet in response, but got {len(cloudletList)}")
    exit()
cloudletData = cloudletList[0]

# we want to get the IP for the shared rootLB
rootlbIP = ""
resources = cloudletData["resources_snapshot"]
platform_vms = resources["platform_vms"]
if platform_vms is None:
    # May hard-code mapping of cloudlet to rootLB IP if for
    # some reason it's not in the cloudletinfo
    # if cloudlet == "xxx":
    #    rootlbIP = "a.b.c.d"
    # elif cloudlet == "xyz":
    #    rootlbIP = "d.c.b.a"
    print("platform_vms not found")
    exit()
else:
    for vm in platform_vms:
        if vm["type"] == "sharedrootlb":
            for ip in vm["ipaddresses"]:
                if "externalIp" in ip:
                    rootlbIP = ip["externalIp"]
                    break
if rootlbIP == "":
    print(ret.stdout)
    print("Unable to find sharedrootlb IP from cloudletinfo")
    exit()

# Get cluster insts
ret = subprocess.run(
    [
        "mcctl",
        "--addr",
        addr,
        "clusterinst",
        "show",
        f"cloudlet={cloudlet}",
        f"cloudletorg={org}",
        f"region={region}",
        "--output-format",
        "json",
    ],
    capture_output=True,
    text=True,
)
if ret.stdout == "":
    print(f"no clusters on {cloudlet} {org} in region {region}")
    exit()


def runCmd(lbip, masterip, cmd, printOutput=True):
    args = ["vssh", "-j", lbip, masterip, cmd]
    if masterip is None or masterip == "":
        args = ["vssh", lbip, cmd]
    # to be able to copy-and-paste debug output, cmd must be quoted
    print(f"  running: {' '.join(args[:len(args)-1])} \"{cmd}\"")
    ret = subprocess.run(args, capture_output=True, text=True)
    if printOutput:
        print(ret.stdout)
    return ret.stdout


clusterData = json.loads(ret.stdout)
if type(clusterData) is not list:
    print(f"expected list of clusters, but is {type(clusterData)}")
    exit()
for cluster in clusterData:
    deployment = cluster["deployment"]
    if deployment != "kubernetes":
        continue
    dedicated = False
    dedicatedPrint = ""
    if "ip_access" in cluster and cluster["ip_access"] == "Dedicated":
        dedicated = True
        dedicatedPrint = " (dedicated LB)"
    clusterKey = cluster["key"]["cluster_key"]
    clusterName = clusterKey["name"]
    clusterOrg = clusterKey["organization"]
    vms = cluster["resources"]["vms"]
    masterip = ""
    lbip = ""
    # Kubeconfig file used by CRM (yes, org here is the cloudlet org).
    # This matches pkg/k8smgmt/kubenames.go:GetKconfName()
    # we need to make a copy with readable perms since scp can't sudo.
    kubeconfig = f"{clusterName}.{org}.kubeconfig"
    for vm in vms:
        vmtype = vm["type"]
        if vmtype == "cluster-master" or vmtype == "k8s-cluster-master":
            masterip = vm["ipaddresses"][0]["internalIp"]
        if vmtype == "rootlb" or vmtype == "dedicatedrootlb":
            for ip in vm["ipaddresses"]:
                if "externalIp" in ip:
                    lbip = ip["externalIp"]
                    break
    if masterip == "":
        print(f"cluster {clusterName} {clusterOrg} master node not found")
        print(cluster)
        exit()
    if dedicated and lbip == "":
        print(f"cluster {clusterName} {clusterOrg} is dedicated but no rootlb IP found")
        print(cluster)
        exit()
    if not dedicated:
        lbip = rootlbIP
    print(f"Checking cluster {clusterName} {clusterOrg}{dedicatedPrint}")
    cmd = "sudo kubeadm alpha certs check-expiration"
    out = runCmd(lbip, masterip, cmd, printOutput=False)
    daysLeft = certsDaysLeft(out)
    print(f"  certs expire in {daysLeft} days")
    if daysLeft < 120:
        print(f"  renewing certs for {clusterName} {clusterOrg} ")
    else:
        # test that it works
        cmd = f"kubectl --kubeconfig {kubeconfig} get pods"
        runCmd(lbip, None, cmd)
        continue

    timestamp = datetime.datetime.now(datetime.timezone.utc).astimezone().isoformat()

    # renew certs
    cmd = "sudo kubeadm alpha certs renew all"
    runCmd(lbip, masterip, cmd)
    # move out services config to stop them
    cmd = "sudo mkdir -p /etc/kubernetes/manifests.save"
    runCmd(lbip, masterip, cmd)
    cmd = "sudo mv /etc/kubernetes/manifests/*.yaml /etc/kubernetes/manifests.save/"
    runCmd(lbip, masterip, cmd)
    print("  wait 30 sec for kubernetes to stop static services")
    time.sleep(30)
    cmd = "sudo mv /etc/kubernetes/manifests.save/*.yaml /etc/kubernetes/manifests/"
    runCmd(lbip, masterip, cmd)
    print("  wait 30 sec for kubernetes to start static services")
    time.sleep(30)
    cmd = "sudo docker ps"
    runCmd(lbip, masterip, cmd)
    cmd = f"sudo cp /root/.kube/config /root/.kube/config.{timestamp}"
    runCmd(lbip, masterip, cmd)
    cmd = "sudo cp /etc/kubernetes/admin.conf /root/.kube/config"
    runCmd(lbip, masterip, cmd)

    # copy new kubeconfig to LB.
    cmd = f"sudo cp /etc/kubernetes/admin.conf /tmp/{kubeconfig}"
    runCmd(lbip, masterip, cmd)
    cmd = f"sudo chmod a+rw /tmp/{kubeconfig}"
    runCmd(lbip, masterip, cmd)
    print(f"  grabbing {kubeconfig} from master")
    ret = subprocess.run(
        ["vssh", "-s", "-j", lbip, f"{masterip}:/tmp/{kubeconfig}", kubeconfig]
    )
    cmd = f"cp {kubeconfig} {kubeconfig}.{timestamp}"
    runCmd(lbip, None, cmd)

    print(f"  copying {kubeconfig} to lb")
    ret = subprocess.run(["vssh", "-s", kubeconfig, f"{lbip}:{kubeconfig}"])
    cmd = f"sudo rm /tmp/{kubeconfig}"
    runCmd(lbip, masterip, cmd)
    print(f"  removing local copy of {kubeconfig}")
    subprocess.run(["rm", kubeconfig])

    # check again
    cmd = "sudo kubeadm alpha certs check-expiration"
    out = runCmd(lbip, masterip, cmd)
    daysLeft = certsDaysLeft(out)
    print(f"  updated certs now expire in {daysLeft} days")
    # test kubectl
    cmd = f"kubectl --kubeconfig {kubeconfig} get pods"
    runCmd(lbip, None, cmd)
