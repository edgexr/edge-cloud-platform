#!/bin/sh

die() {
        echo "ERROR: $*"
        exit 2
}

# Make sure required binaries exists
type chef-client > /dev/null
[[ $? -ne 0 ]] && die "Missing 'chef-client'. Install chef workstation from https://downloads.chef.io/chef-workstation"
type knife > /dev/null
[[ $? -ne 0 ]] && die "Missing 'knife'. Install chef workstation from https://downloads.chef.io/chef-workstation"
type chef-zero > /dev/null
[[ $? -ne 0 ]] && die "Missing 'chef-zero'. Install it using 'chef gem install chef-zero'"

ROOTPATH=$GOPATH/src/github.com/mobiledgex/edge-cloud-infra
CHEFPATH=$ROOTPATH/chef
CHEFTESTPATH=$ROOTPATH/e2e-tests/chef
KNIFECFG=$CHEFTESTPATH/knife_local.rb
VALIDATIONKEY=/tmp/validation_key.pem

# Apply following patch as policyFiles doesn't work with chef-zero without this fix
# Will remove it, once it is part of next chef release
# Refer this issue: https://github.com/chef/chef-cli/issues/111
CHEFLIBPATH=$(knife exec -E 'puts $LOAD_PATH' | grep "chef-1.*" | uniq)
[[ -z $CHEFLIBPATH ]] && die "Missing chef lib path, make sure chef is installed properly"
PATCHOK=$(cat $CHEFLIBPATH/chef/http/authenticator.rb | grep 'DEFAULT_SERVER_API_VERSION = "2".freeze')
[[ -z $PATCHOK ]] && die "Please execute following command to patch a fix for tests to work:\nsudo sed -i -e 's/DEFAULT_SERVER_API_VERSION = \"1\".freeze/DEFAULT_SERVER_API_VERSION = \"2\".freeze/g' $CHEFLIBPATH/chef/http/authenticator.rb"

# https://github.com/chef/cookbook-omnifetch/issues/30
CHEFOMNIPATH=$(knife exec -E 'puts $LOAD_PATH' | grep "cookbook-omnifetch" | uniq)
[[ -z $CHEFOMNIPATH ]] && die "Missing chef cookbook-omnifetch, make sure chef is installed properly"
PATCHOK=$(cat $CHEFOMNIPATH/cookbook-omnifetch/metadata_based_installer.rb | grep 'all_files')
[[ -z $PATCHOK ]] && die "Please execute following command to patch a fix for tests to work:\ncd $CHEFOMNIPATH/cookbook-omnifetch/; sudo patch -p1 < $CHEFTESTPATH/omnifetch_patch.diff; cd -"

knife opc org create mobiledgex MobiledgeX Org --filename $VALIDATIONKEY -c $KNIFECFG

# Upload dependent cookbooks
for remoteCookbook in "docker 6.0.3" "iptables 7.0.0"; do
  parts=(${remoteCookbook})
  name=${parts[0]}
  version=${parts[1]}
  if [ ! -f /tmp/chef_$name.tar.gz ]; then
    knife supermarket download $name $version -f /tmp/chef_$name.tar.gz
  fi
  tar -xzf /tmp/chef_$name.tar.gz -C /tmp/
  knife cookbook upload $name -c $KNIFECFG --cookbook-path /tmp/
  [[ $? -ne 0 ]] && die "Failed to upload cookbook $name"
  rm -r /tmp/$name
done

# Upload cookbooks from our repository
for cookbook in `ls $CHEFPATH/cookbooks/`
do
  echo "Upload cookbook $cookbook"
  if [ -d "$CHEFPATH/cookbooks/$cookbook" ]; then
    echo "Upload cookbook $cookbook"
    knife cookbook upload $cookbook -c $KNIFECFG
    [[ $? -ne 0 ]] && die "Failed to upload cookbook $cookbook"
  fi
done

policyGroup="local"
policyFile="$CHEFPATH/policyfiles/local_crm.lock.json"
echo "Upload policy $policyFile to group $policyGroup"
( cd $CHEFPATH/policyfiles ; chef push $policyGroup $policyFile -c $KNIFECFG )
[[ $? -ne 0 ]] && die "Failed to push policyfile $policyFile to policy group $policyGroup"

exit 0
