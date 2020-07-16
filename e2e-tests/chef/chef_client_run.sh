#!/bin/sh

# exit immediately on failure
set -e

ECPATH=$GOPATH/src/github.com/mobiledgex/edge-cloud
ECINFRAPATH=$GOPATH/src/github.com/mobiledgex/edge-cloud-infra
CHEFTESTPATH=$ECINFRAPATH/e2e-tests/chef
CLIENTCFG=$CHEFTESTPATH/client.rb
KNIFECFG=$CHEFTESTPATH/knife_local.rb
TLSPATH=$ECPATH/tls/out/mex-server.crt

REGION="local"
POLICYGROUP="local"
DEPLOYMENT_TYPE="docker"
TEST_MODE="cookbook"

USAGE="usage: $( basename $0 ) <options>

 -c <cloudlet>         Cloudlet Name
 -o <cloudlet-org>     Cloudlet Organization Name
 -t <deployment-type>  Deployment Type [\"local\", \"docker\"] (default: \"$DEPLOYMENT_TYPE\")
 -r <region>           Region (default: \"$REGION\")
 -p <registry-pwd>     Password to access docker registry
 -m <mode>             Test Mode [\"cookbook\", \"policy\"] (default: \"$TEST_MODE\")

 -h                    Display this help message
"

while getopts ":hc:o:t:r:p:m:" OPT; do
        case "$OPT" in
        h) echo "$USAGE"; exit 0 ;;
        c) CLOUDLET="$OPTARG" ;;
        o) CLOUDLET_ORG="$OPTARG" ;;
        t) DEPLOYMENT_TYPE="$OPTARG" ;;
        r) REGION="$OPTARG" ;;
        p) REGISTRY_PASS="$OPTARG" ;;
        m) TEST_MODE="$OPTARG" ;;
        esac
done
shift $(( OPTIND - 1 ))

die() {
        echo "ERROR: $*" >&2
        exit 2
}

[[ -z $CLOUDLET ]] && die "Missing argument '-c'"
[[ -z $CLOUDLET_ORG ]] && die "Missing argument '-o'"

CLIENT_NAME="$POLICYGROUP-$REGION-$CLOUDLET-$CLOUDLET_ORG-pf"
CLIENT_KEY_PATH="/tmp/$CLOUDLET.$CLOUDLET_ORG.pem"

if [[ "$DEPLOYMENT_TYPE" == "docker" ]]; then

  ECVERS=$(knife exec -E "nodes.find('name:$CLIENT_NAME') {|n| puts n.normal['edgeCloudVersion']}" -c $KNIFECFG)
  [[ -z $ECVERS ]] && die "Missing edge-cloud version, make sure 'containerversion' is passed as part of CreateCloudlet"

  if [[ -z $REGISTRY_PASS ]]; then
    echo -n Password for docker registry:
    read -s REGISTRY_PASS
    echo
  fi

  [[ -z $REGISTRY_PASS ]] && die "No password given for docker registry access"

  cat > /tmp/reg_pass.json <<EOF
{
  "id": "docker_registry",
  "mex_docker_username": "mobiledgex",
  "mex_docker_password": "$REGISTRY_PASS"
}
EOF
  # Create data bag secrets for chef-client to access image from docker registry
  knife data bag create mexsecrets -c $KNIFECFG
  knife data bag from file mexsecrets /tmp/reg_pass.json -c $KNIFECFG
  rm /tmp/reg_pass.json

  # From docker container, host's 127.0.0.1 is not reachable use host.docker.internal instead
  knife exec -E "nodes.find('name:$CLIENT_NAME') {|n| n.normal['crmserver']['args']['notifyAddrs'] = 'host.docker.internal:37001'; n.save }" -c $KNIFECFG
else
  # Set TLS path to local file
  knife exec -E "nodes.find('name:$CLIENT_NAME') {|n| n.normal['crmserver']['args']['tls']='$ECPATH/tls/out/mex-server.crt'; n.save }" -c $KNIFECFG
  knife exec -E "nodes.find('name:$CLIENT_NAME') {|n| n.normal['shepherd']['args']['tls']='$ECPATH/tls/out/mex-server.crt'; n.save }" -c $KNIFECFG
  knife exec -E "nodes.find('name:$CLIENT_NAME') {|n| n.normal['crmserver']['args']['notifyAddrs'] = '127.0.0.1:37001'; n.save }" -c $KNIFECFG
fi

# Fetch client key for the node
edgectl --tls $ECPATH/tls/out/mex-client.crt controller ShowCloudlet cloudlet=$CLOUDLET cloudlet-org=$CLOUDLET_ORG --output-format json | jq -r '.[] | "\(.chef_client_key[])"' > $CLIENT_KEY_PATH
[[ $? -ne 0 ]] && die "Failed to fetch client key: cloudlet=$CLOUDLET, cloudlet-org=$CLOUDLET_ORG"

if [[ "$TEST_MODE" == "cookbook" ]]; then
  # Set run_list and skip using policyfile for testing
  knife node run_list set $CLIENT_NAME "recipe[runstatus_handler]" "recipe[setup_infra]" "recipe[preflight_crm_checks]" "recipe[setup_services::$DEPLOYMENT_TYPE]" -c $KNIFECFG
  [[ $? -ne 0 ]] && die "Failed to set run_list: client-name=$CLIENT_NAME"
else
  policyGroup="local"
  policyFile="$ECINFRAPATH/chef/policyfiles/local_crm.lock.json"
  echo "Generate lock file for $policyFile"
  ( cd $ECINFRAPATH/chef/policyfiles ; rm $policyFile; chef install $policyFile -c $KNIFECFG )
  echo "Upload policy $policyFile to group $policyGroup"
  ( cd $ECINFRAPATH/chef/policyfiles ; chef push $policyGroup $policyFile -c $KNIFECFG )
  [[ $? -ne 0 ]] && die "Failed to push policyfile $policyFile to policy group $policyGroup"

  knife node policy set $CLIENT_NAME "local" "local_crm" -c $KNIFECFG
  [[ $? -ne 0 ]] && die "Failed to set run_list: client-name=$CLIENT_NAME"

  if [[ "$DEPLOYMENT_TYPE" == "local" ]]; then
    NAMEDRUNLIST="--named-run-list local"
  fi
fi

# Start chef-client run
chef-client --node-name $CLIENT_NAME --client_key $CLIENT_KEY_PATH $NAMEDRUNLIST -c $CLIENTCFG


echo
echo "Notes:"
echo "======"
echo "* Use 'knife node run-list status $CLIENT_NAME -c $KNIFECFG' to get status of chef-client run'"
if [[ "$DEPLOYMENT_TYPE" == "docker" ]]; then
  echo "* Don't forget to remove docker containers started by chef-client when done !"
fi
echo
