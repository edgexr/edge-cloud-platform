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

set -x
dir=~/src/github.com/mobiledgex/edge-cloud-infra/k8s-prov
dest=registry.mobiledgex.net:files-repo/mobiledgex
for f in   install-k8s-*.sh; do
    scp $dir/$f $dest
done
scp ~/src/github.com/mobiledgex/edge-cloud-infra/openstack-tenant/qcow2/mobiledgex-16.04-qcow2/mobiledgex-init.sh $dest
# examples deployed. Change to production when ready.
dir=~/src/github.com/mobiledgex/edge-cloud-infra/deployments/examples
for d in application cluster platform kustomize; do
    scp -r $dir/$d $dest
done

