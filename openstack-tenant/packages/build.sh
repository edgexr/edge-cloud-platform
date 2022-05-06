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


: ${SECTION:='misc'}
: ${PRIORITY:='optional'}
: ${ARCH:='amd64'}

MAINTAINER='MobiledgeX'
MAINTAINER_EMAIL='mobiledgex.ops@mobiledgex.com'
ARTIFACTORY_REPO='packages'
ARTIFACTORY_PATH="https://artifactory.mobiledgex.net/artifactory/${ARTIFACTORY_REPO}/pool"
DESC_FILE="description"
DEPS_FILE="dependencies"

if [[ $# -lt 4 ]]; then
	echo "usage: $( basename $0 ) <pkgname> <version> <distribution> <component>" >&2
	exit 1
fi

PKGNAME="$1"
VERSION="$2"
DISTRIB="$3"
COMPONENT="$4"

set -e

PKGDIR="${PKGNAME}_${VERSION}"
DEBDIR="${PKGDIR}/DEBIAN"
CTRLFILE="${DEBDIR}/control"
DEBFILE="${PKGDIR}.deb"

if [[ -f "$DEPS_FILE" ]]; then
	DEPS=$( grep -v '^#' "$DEPS_FILE" \
		| awk '{ printf("%s (%s), \n", $1, $2) }' \
		| tr -d "\n" \
		| sed 's/, $//' )
fi
DESC=$( cat "$DESC_FILE" )

mkdir -p "$DEBDIR"
cat >"$CTRLFILE" <<EOT
Package: $PKGNAME
Version: $VERSION
Section: $SECTION
Priority: $PRIORITY
Architecture: $ARCH
Depends: $DEPS
Maintainer: $MAINTAINER <${MAINTAINER_EMAIL}>
Description: $DESC
EOT

for SCRIPT in preinst postinst prerm postrm; do
	if [[ -f "$SCRIPT" ]]; then
		echo "Installing $SCRIPT script"
		cp "$SCRIPT" "$DEBDIR"
		chmod +x "${DEBDIR}/${SCRIPT}"
	fi
done

dpkg-deb --build "$PKGDIR"
dpkg-deb --info "$DEBFILE"
echo

read -p "Publish to Artifactory? (yN) " RESP
case "$RESP" in
	y*|Y*)	true ;;
	*)	echo "Package NOT published to Artifactory"; exit 0 ;;
esac

set +e

ARTIFACTORY_CREDS_FILE="${HOME}/.artifactory.creds"
[[ -f "$ARTIFACTORY_CREDS_FILE" ]] \
	&& ARTIFACTORY_CREDS=$( head -n1 "$ARTIFACTORY_CREDS_FILE" )
[[ -z "$ARTIFACTORY_CREDS" ]] && read -p "Artifactory user: " ARTIFACTORY_CREDS

ARTF_PKG_PATH="${ARTIFACTORY_PATH}/${PKGDIR}_${ARCH}.deb"
echo; echo "Checking to see if package already present in Artifactory..."
curl -f -u "$ARTIFACTORY_CREDS" -I "$ARTF_PKG_PATH"
if [[ $? -eq 0 ]]; then
	echo "Package present in Artifactory" >&2
	exit 2
fi

echo; echo "Publishing to Artifactory: $ARTF_PKG_PATH ..."
SHA1SUM=$( sha1sum "$DEBFILE" | awk '{print $1}' )
MD5SUM=$( md5sum "$DEBFILE" | awk '{print $1}' )
curl -u "$ARTIFACTORY_CREDS" -XPUT \
	-H "X-Checksum-MD5: $MD5SUM" \
	-H "X-Checksum-Sha1: $SHA1SUM" \
	"${ARTF_PKG_PATH};deb.distribution=${DISTRIB};deb.component=${COMPONENT};deb.architecture=${ARCH}" \
	-T "$DEBFILE"
