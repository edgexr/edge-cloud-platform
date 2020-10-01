#!/bin/bash

[[ "$TRACE" == yes ]] && set -x

USAGE="usage: $( basename $0 ) <options>

 -p <artifactory-path> Artifactory upload path
 -t <artifactory-api-token> Artifactory API token

 -h                    Display this help message
"
while getopts ":hp:u:t:" OPT; do
        case "$OPT" in
        h) echo "$USAGE"; exit 0 ;;
        p) RTF_PATH="$OPTARG" ;;
        t) RTF_TOKEN="$OPTARG" ;;
        esac
done
shift $(( OPTIND - 1 ))

die() {
        echo "ERROR: $*" >&2
        exit 2
}

print() {
	echo ""
	echo ">> $*"
	echo "-------------------------"
}

[[ -z $RTF_PATH ]] && die "Missing artifactory upload path"
[[ -z $RTF_TOKEN ]] && die "Missing artifactory API token"

TARGET_NAME="chef-diagnostics-$(date +"%d-%m-%YT%H-%M-%S")"
TARGET_PATH="/var/tmp/$TARGET_NAME"
mkdir -p $TARGET_PATH

docker_cmds=(
	"docker ps"
	"docker images"
	"docker inspect crmserver | grep -v 'VAULT_'"
	"docker inspect shepherd | grep -v 'VAULT_'"
)

IFS=""
for cmd in ${docker_cmds[*]}; do
	print $cmd >> $TARGET_PATH/docker.log
	eval $cmd >> $TARGET_PATH/docker.log
done	

docker logs crmserver >& $TARGET_PATH/docker_crmserver.log
docker logs shepherd >& $TARGET_PATH/docker_shepherd.log

sudo cp /var/log/chef/client.log $TARGET_PATH/
sudo cp /var/log/cloud-init.log $TARGET_PATH/
sudo cp /var/log/syslog $TARGET_PATH/

cp /tmp/prom_targets.json $TARGET_PATH/
cp /tmp/rulefile_*.yml $TARGET_PATH/

system_cmds=(
	"ifconfig -a"
	"route -n"
)
IFS=""
for cmd in ${system_cmds[*]}; do
	print $cmd >> $TARGET_PATH/system.log
	eval $cmd >> $TARGET_PATH/system.log
done

print "Compressing logs folder $TARGET_NAME..."
cd /var/tmp
tar czf $TARGET_NAME.tar.gz $TARGET_NAME
[[ $? -eq 0 ]] || die "Failed to create tar file"

print "Uploading to artifactory to ${RTF_PATH}..."
curl -sSL -XPUT -H "Authorization: Bearer ${RTF_TOKEN}" -T "$TARGET_NAME.tar.gz" "${RTF_PATH}"
[[ $? -eq 0 ]] || die "Error uploading image to Artifactory"

rm -rf $TARGET_NAME
rm $TARGET_NAME.tar.gz

print "Done"
