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


if [[ $# -lt 2 ]]; then
	echo "usage: $0 <openrc-file> <cloudlet-name>" >&2
	exit 1
fi

OPENRC="$1"
CLOUDLETNAME="$2"

# exit immediately on failure
set -e

# Set up secrets engine
if ! vault secrets list | grep '^secret/' >/dev/null 2>&1; then
	echo "Setting up secrets engine"
	vault secrets enable -path=secret kv
fi

TMPFILE=$( mktemp )
trap 'rm -f "$TMPFILE"' EXIT

env - bash -c "source $OPENRC && $( dirname $0 )/openrc-to-json.py" >"$TMPFILE"
if [[ ! -s "$TMPFILE" ]]; then
	echo "Failed to generate openrc json" >&2
	exit 2
fi

vault kv put secret/cloudlet/openstack/${CLOUDLETNAME}/openrc.json @$TMPFILE
