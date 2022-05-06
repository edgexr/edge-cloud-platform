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


function isNum() {
  re='^[0-9]+$'
  if [[ ! $1 =~ $re ]] ; then
    return 1
  fi
  return 0
}

# Total RAM
totalMemMB=0
for memSizeMB in $(dmidecode -t memory | grep "Size:" | awk '{print $2}'); do
  if isNum $memSizeMB; then
    let totalMemMB+=$memSizeMB
  fi
done

# Number of vCPUs
vcpus=$(grep -c processor /proc/cpuinfo)

# Total disk size
totalDiskSectors=0
for block in $(ls -l /sys/block/ | grep -v "devices/virtual" | awk '{print $9}'); do
  if [[ ! -z $block ]]; then
    if [[ -f /sys/block/$block/size ]]; then
      sectors=$(cat /sys/block/$block/size)
      if isNum $sectors; then
        let totalDiskSectors+=$sectors
      fi
    fi
  fi
done
# assume sector size is always 512 bytes
let diskGB=$totalDiskSectors*512/1024/1024/1024

# Report system resource info
echo "$totalMemMB,$vcpus,$diskGB"
