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


USAGE="usage: $0 <environment> <downgrade-workspace> <edge-cloud-version> <console-version>

  Commands needs a workspace cloned to the release/commit that needs to be used
  for the downgrade.  Ansible playbooks are used from that workspace to do the
  reinstall of the older build.

example: $0 staging ~/src/edge-cloud-2.4.1 2021-04-15-1 v2.4.11"

if [[ $# -lt 4 ]]; then
	echo "$USAGE" >&2
	exit 1
fi

SETUP="$1"; shift
REINSTALL_WORKSPACE="$1"; shift
EDGE_CLOUD_VERSION="$1"; shift
CONSOLE_VERSION="$1"; shift

if [[ "$SETUP" != staging ]]; then
	echo "Downgrade is primarily designed for the staging setup"
	read -p "Are you sure you want to downgrade \"$SETUP\"? (yN) " RESP
	case "$RESP" in
		y*|Y*) true ;;
		*) echo "Aborting..." >&2; exit 2 ;;
	esac
fi

if [[ ! -d "${REINSTALL_WORKSPACE}/ansible" ]]; then
	echo "$REINSTALL_WORKSPACE/ansible not found" >&2
	exit 2
fi

WS_DESC=$( git -C "$REINSTALL_WORKSPACE" describe --tags 2>/dev/null )
WS_LOG=$( git -C "$REINSTALL_WORKSPACE" log --graph --pretty=format:'%h -%d %s (%cr) <%an>' -n 1 2>/dev/null )
if [[ -z "$WS_DESC" || -z "$WS_LOG" ]]; then
	echo "Error using git workspace: $REINSTALL_WORKSPACE" >&2
	exit 2
fi

cat <<EOT

Re-install workspace: $REINSTALL_WORKSPACE
Workspace commit level: $WS_DESC
Newest commit:
$WS_LOG

Downgrading \"$SETUP\" to:
- Edge-cloud version: $EDGE_CLOUD_VERSION
- Console version: $CONSOLE_VERSION

EOT

read -p "Continue with the downgrade? (yN) " RESP
case "$RESP" in
	y*|Y*) true ;;
	*) echo "Aborting..."; exit 2 ;;
esac

set -ex
CURRENT_WORKSPACE="$PWD"
./deploy.sh -p destroy-setup.yml "$SETUP"

cd "$REINSTALL_WORKSPACE/ansible"
./deploy.sh -V "$EDGE_CLOUD_VERSION" -C "$CONSOLE_VERSION" "$SETUP"

cd "$CURRENT_WORKSPACE"
./deploy.sh -p initialize.yml "$SETUP"
