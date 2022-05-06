#!/bin/bash
# Copyright 2022 MobiledgeX, Inc
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.


TMPDIR=$( mktemp -d )
TIMESTAMP="$( date +'%Y%m%d%H%M%S' )"
SRVNAME="cis-benchmark-${TIMESTAMP}"
LOCATION="paradise"
TESTPASS="Hhsbf4qbE5eRdA3G8tsf"

die() {
    echo "ERROR: $*" >&2
    exit 2
}

log() {
    echo
    echo "================================================================================"
    echo "$*"
    echo
}

md5sum_of_image() {
    url="$1"
    curl -sfI -H "X-JFrog-Art-Api:$ARTIFACTORY_APIKEY" "$url" \
        | grep '^X-Checksum-Md5:' \
        | awk '{print $2}' \
        | tr -d "\r\n"
}

openstack_image_by_checksum() {
    image="$1"
    checksum="$2"
    for image_id in $( openstack image list -c ID -c Name -f value \
                      | awk -v img="$image" '$2 == img {print $1}' ); do
        image_sum=$( openstack image show -c checksum -f value "$image_id" 2>/dev/null )
        if [[ "$image_sum" == "$checksum" ]]; then
            echo "$image_id"
            return
        fi
    done
}

download_image() {
    url="$1"
    checksum="$2"
    image="${TMPDIR}/$( basename $url )"
    curl -sf -H "X-JFrog-Art-Api:$ARTIFACTORY_APIKEY" -o "$image" "$url"
    got_checksum=$( md5sum "$image" | awk '{print $1}' )
    if [[ "$got_checksum" != "$checksum" ]]; then
        die "Checksum mismatch: $url (expected: $checksum; got $got_checksum)"
    fi
    echo "$image"
}

upload_to_glance() {
    image="$1"
    image_name=$( basename "$image" .qcow2 )
    openstack image create --disk-format qcow2 --container-format bare \
        --file "$image" "$image_name"
}

get_server_ip() {
    server="$1"
    openstack server show -c addresses -f value "$server" | cut -d= -f2
}

configure_security_group() {
    openstack security group rule create default \
        --remote-ip `curl -s ifconfig.me` --dst-port 22:22 --protocol tcp
}

publish_report() {
    report="$1"
    url="$2"

    curl -H "X-JFrog-Art-Api:$ARTIFACTORY_APIKEY" -T "$report" "$url"
}

cleanup() {
    set -x
    openstack server delete "$SRVNAME"
    ls -l "$TMPDIR"
    rm -rf "$TMPDIR"
}
trap 'cleanup' EXIT

# Main

[[ -z "$BASE_IMAGE_URL" ]] && die "Mandatory parameter: BASE_IMAGE_URL"

. ${HOME}/.cloudlets/${LOCATION}_cloudlet/openrc.mex

IMAGE=$( basename $BASE_IMAGE_URL .qcow2)

log "Fetching image checksum: $BASE_IMAGE_URL"
ARTF_CHECKSUM=$( md5sum_of_image "$BASE_IMAGE_URL" )

log "Looking for image in glance: $IMAGE (MD5: $ARTF_CHECKSUM)"
IMAGE_ID=$( openstack_image_by_checksum "$IMAGE" "$ARTF_CHECKSUM" )
if [[ -z "$IMAGE_ID" ]]; then
    log "Image not found in glance: $IMAGE (MD5: $ARTF_CHECKSUM)"
    DOWNLOAD=$( download_image "$BASE_IMAGE_URL" "$ARTF_CHECKSUM" )
    upload_to_glance "$DOWNLOAD"
    IMAGE_ID=$( openstack_image_by_checksum "$IMAGE" "$ARTF_CHECKSUM" )
    [[ -z "$IMAGE_ID" ]] && die "Failed to publish image to glance: $BASE_IMAGE_URL"
fi

log "Creating server $SRVNAME"
cat >cis-init.yml <<EOT
#cloud-config
ssh_pwauth: True
chpasswd:
  list: |
    ubuntu:${TESTPASS}
  expire: false
EOT
openstack server create \
    --image "$IMAGE_ID" \
    --flavor m4.medium \
    --config-drive true \
    --network external-network-shared \
    --user-data "${PWD}/cis-init.yml" \
    "$SRVNAME"

log "Waiting for server to come up"
COUNTDOWN=60
while [[ "$COUNTDOWN" -gt 0 ]]; do
    sleep 10
    STATUS=$( openstack server show -c status -f value "$SRVNAME" )
    if [[ "$STATUS" == "ACTIVE" ]]; then
        log "Server is up: $SRVNAME"
        break
    fi
    COUNTDOWN=$(( COUNTDOWN - 1 ))
done
[[ "$STATUS" == "ACTIVE" ]] || die "Failed to boot up server: $SRVNAME ($LOCATION)"

log "Configure security group"
configure_security_group

IP=$( get_server_ip "$SRVNAME" )

# Give the VM some time to bring SSH up
sleep 30

# Download list of installed packages
COUNT=10
PKGLIST="$TMPDIR/pkglist.txt"
while (( COUNT > 0 )); do
	sshpass -p "$TESTPASS" ssh -o "UserKnownHostsFile=/dev/null" \
		-o "StrictHostKeyChecking=no" ubuntu@${IP} \
		apt list --installed >"$PKGLIST"
	[[ $? -eq 0 ]] && break

	rm -f "$PKGLIST"
	COUNT=$(( COUNT - 1 ))
	sleep 5
done
[[ -f "$PKGLIST" ]] || die "Failed to get package list"

PKGLIST_URL="$( dirname $BASE_IMAGE_URL )/pkglists/$( basename $BASE_IMAGE_URL .qcow2 ).txt"

log "Publish package list to Artifactory: $PKGLIST_URL"
publish_report "$PKGLIST" "$PKGLIST_URL"

cd "$HOME/Assessor-CLI"
cat >config/sessions.properties <<EOT
session.1.type=ssh
session.1.host=${IP}
session.1.user=ubuntu
session.1.cred=${TESTPASS}
session.1.port=22
session.1.tmp=/var/tmp
EOT

log "Launching CIS assessment"
REPORT_DIR="${WORKSPACE}/cis-reports"
mkdir -p "$REPORT_DIR"
sh ./Assessor-CLI.sh \
    --benchmark benchmarks/CIS_Ubuntu_Linux_18.04_LTS_Benchmark_v1.0.0-xccdf.xml \
    --profile xccdf_org.cisecurity.benchmarks_profile_Level_1_-_Server \
    --reports-dir "$REPORT_DIR" \
    --report-prefix "$SRVNAME" \
    -vvv

REPORT_URL="$( dirname $BASE_IMAGE_URL )/reports/$( basename $BASE_IMAGE_URL .qcow2 )/${TIMESTAMP}.html.bz2"
REPORT=$( ls "${REPORT_DIR}/${SRVNAME}"*.html )
bzip2 --keep "$REPORT"

log "Publishing report to Artifactory: $REPORT_URL"
publish_report "${REPORT}.bz2" "$REPORT_URL"
