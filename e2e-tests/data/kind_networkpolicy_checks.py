import os
import sys
import subprocess

failed = 0

def run_curl(target):
    global failed
    cmd = "curl -s http://" + target + "/getdata?numbytes=10"
    exp = "ZZZZZZZZZZ"
    print("Running curl:", cmd)
    run = subprocess.run(cmd.split(), capture_output=True, text=True)
    output = run.stdout
    print("Result:", output)
    if output != exp:
        print("Test failed, expected", exp)
        failed += 1
    else:
        print("Success, got", exp)
    print()

class Pod:
    def __init__(self, name, ip):
        self.name = name
        self.ip = ip
    
def get_pods(namespace):
    cmd = "kubectl --kubeconfig=/tmp/defaultmtclust.dmuus.kubeconfig get pods -n "+namespace+" -o wide --no-headers=true"
    stream = os.popen(cmd)
    output = stream.readlines()
    pods = []
    for line in output:
        line = line.strip()
        fields = line.split()
        if len(fields) < 6:
            continue
        # create new pod with name and ip
        pod = Pod(fields[0], fields[5])
        pods.append(pod)
    return pods

def get_ping_cmd(src_namespace, src_pod_name, dst_ip):
    # Ping 3 times, 0.5s interval, wait 2sec for first response,
    # then wait 2s for the rest of the responses.
    # Pings from within the src pod to the dst ip.
    return "kubectl --kubeconfig=/tmp/defaultmtclust.dmuus.kubeconfig exec -it -n " + src_namespace + " " + src_pod_name + " -- ping " + dst_ip + " -c 3 -i 0.5 -w 2 -W 3"

############################################################
# main

# test pods are reachable from external source
# this goes through envoy proxy -> load balancer service on master -> pod
run_curl("localhost:7777")
run_curl("localhost:10000")

# pod-to-pod connectivity tests
acme_ns = "acmeappco-someapplication1-10-autocluster-someapp1"
user3_ns = "user3org-someappuser3-10-autocluster-autoprov"
acme_pods = get_pods(acme_ns)
user3_pods = get_pods(user3_ns)
# run pings that should succeed
for src in acme_pods:
    for dst in acme_pods:
        cmd = get_ping_cmd(acme_ns, src.name, dst.ip)
        print("Running ping:", cmd)
        run = subprocess.run(cmd.split(), capture_output=True, text=True)
        print("Result:", run.stdout + run.stderr)
        if run.returncode != 0:
            print("Expected ping success, but it failed")
            failed += 1
        else:
            print("Success, able to ping within same namespace")
        print()
# run pings that should fail
for src in acme_pods:
    for dst in user3_pods:
        cmd = get_ping_cmd(acme_ns, src.name, dst.ip)
        print("Running ping:", cmd)
        run = subprocess.run(cmd.split(), capture_output=True, text=True)
        print("Result:", run.stdout + run.stderr)
        if run.returncode == 0:
            print("Expected ping failure, but it worked")
            failed += 1
        else:
            print("Success, cannot ping between namespaces")
        print()
    
if failed > 0:
    print("Some failures")
    sys.exit(1)
else:
    print("Success")
