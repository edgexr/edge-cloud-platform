#!/bin/sh
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


export ETCDCTL_API=3
ENDPOINTS="http://mex-etcd-0.mex-etcd:2379,http://mex-etcd-1.mex-etcd:2379,http://mex-etcd-2.mex-etcd:2379"

echo "==== BEFORE COMPACTION ===="
etcdctl --endpoints="$ENDPOINTS" endpoint status -w table

REV=$( etcdctl --endpoints="$ENDPOINTS" get abc123 -w json | sed -n 's/.*"revision":\([0-9]*\).*/\1/p' )
echo "Current revision: $REV"

COMPREV=$(( REV - 5000 ))
echo "Compacting to $COMPREV"
OUT=$( etcdctl --endpoints="$ENDPOINTS" compact "$COMPREV" 2>&1; ); RC=$?

if [[ "$RC" != 0 ]]; then
        if echo "$OUT" | grep "required revision has been compacted" >/dev/null 2>&1; then
                echo "Compaction not necessary"
                exit 0
        fi

        # Unknown error during compaction; abort
        echo "$OUT" >&2
        exit "$RC"
fi

echo "Defragging"
etcdctl --endpoints="$ENDPOINTS" defrag

echo "==== AFTER COMPACTION ===="
etcdctl --endpoints="$ENDPOINTS" endpoint status -w table
