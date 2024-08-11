// Copyright 2022 MobiledgeX, Inc
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package cloudcommon

const (
	CRMCompatibilityAutoReservableCluster uint32 = 1
	CRMCompatibilitySharedRootLBFQDN      uint32 = 2
	CRMCompatibilityNewAppInstKey         uint32 = 3
)

// GetCRMCompatibilityVersion always return the highest compatibility version
func GetCRMCompatibilityVersion() uint32 {
	return CRMCompatibilityNewAppInstKey
}

// AppInsts created before certain upgrades have generated names
// (like namespaces, infra-specific objects etc) that are based on
// the older version of the AppInst. To maintain backwards
// compatibility even after upgrading the AppInst object, these
// dynamically generated names must be generated the same way as before.
const (
	AppInstCompatibilityInitial             uint32 = 0
	AppInstCompatibilityUniqueNameKey       uint32 = 1
	AppInstCompatibilityUniqueNameKeyConfig uint32 = 2
)

// GetAppInstCompatibilityVersion always return the highest compatibility version
func GetAppInstCompatibilityVersion() uint32 {
	return AppInstCompatibilityUniqueNameKeyConfig
}

// ClusterInst compatibility versions, same as above for AppInsts.
const (
	ClusterInstCompatibilityInitial          uint32 = 0
	ClusterInstCompatibilityUniqueKubeconfig uint32 = 1
)

// GetClusterInstCompatibilityVersion always return the highest compatibility version
func GetClusterInstCompatibilityVersion() uint32 {
	return ClusterInstCompatibilityUniqueKubeconfig
}
