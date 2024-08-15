// Copyright 2024 EdgeXR, Inc
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package edgeproto

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/require"
)

type AppInstV2 struct {
	Key AppInstKeyV2 `protobuf:"bytes,2,opt,name=key,proto3" json:"key"`
}

func TestBindJSONAppInstV2CloudletKey(t *testing.T) {
	// oldInst is the older format
	oldInst := AppInstV2{
		Key: AppInstKeyV2{
			Name:         "myappinst",
			Organization: "myorg",
			CloudletKey: CloudletKey{
				Name:         "mycloudlet",
				Organization: "myoper",
			},
		},
	}
	// curInst is the current format
	curInst := AppInst{
		Key: AppInstKey{
			Name:         oldInst.Key.Name,
			Organization: oldInst.Key.Organization,
		},
		CloudletKey: oldInst.Key.CloudletKey,
	}
	// both objects should be able to marshal to JSON and then
	// unmarshal to the current struct.
	for ii, obj := range []any{&oldInst, &curInst} {
		jsonData, err := json.Marshal(obj)
		require.Nil(t, err, "test %d", ii)
		// unmarshal with backwards compatibility
		aiOut := AppInst{}
		err = json.Unmarshal(jsonData, &aiOut)
		require.Nil(t, err, "test %d", ii)
		err = BindJSONAppInstV2(&aiOut, jsonData)
		require.Nil(t, err, "test %d", ii)
		// unmarshaled inst should match current format
		require.Equal(t, curInst, aiOut, "test %d", ii)
	}
}

var testClusterInstKeyV2 = ClusterInstKeyV2{
	ClusterKey: ClusterKey{
		Name:         "myclusterinst",
		Organization: "myorg",
	},
	CloudletKey: CloudletKey{
		Name:         "mycloudlet",
		Organization: "myoper",
	},
}

type ClusterInstV2 struct {
	Key ClusterInstKeyV2 `protobuf:"bytes,2,opt,name=key,proto3" json:"key"`
}

func TestBindJSONClusterInstV2CloudletKey(t *testing.T) {
	// oldInst is the older format
	oldInst := ClusterInstV2{
		Key: testClusterInstKeyV2,
	}
	// curInst is the current format
	curInst := ClusterInst{
		Key:         testClusterInstKeyV2.ClusterKey,
		CloudletKey: testClusterInstKeyV2.CloudletKey,
	}
	// both objects should be able to marshal to JSON and then
	// unmarshal to the current struct.
	for ii, obj := range []any{&oldInst, &curInst} {
		jsonData, err := json.Marshal(obj)
		require.Nil(t, err, "test %d", ii)
		// unmarshal with backwards compatibility
		ciOut := ClusterInst{}
		err = json.Unmarshal(jsonData, &ciOut)
		require.Nil(t, err, "test %d", ii)
		err = BindJSONClusterInstV2(&ciOut, jsonData)
		require.Nil(t, err, "test %d", ii)
		// unmarshaled inst should match current format
		require.Equal(t, curInst, ciOut, "test %d", ii)
	}
}

// This represents the old ClusterInstInfo and ClusterRefs objects.
type ClusterInstInfoV2 struct {
	Key ClusterInstKeyV2 `protobuf:"bytes,2,opt,name=key,proto3" json:"key"`
}

func TestBindJSONObjectWithClusterInstKeyV2(t *testing.T) {
	oldInfo := ClusterInstInfoV2{
		Key: testClusterInstKeyV2,
	}
	curInfo := ClusterInstInfo{
		Key: testClusterInstKeyV2.ClusterKey,
	}
	// old json data should fill in the key and
	// extract the cloudlet key.
	jsonData, err := json.Marshal(oldInfo)
	require.Nil(t, err)
	// unmarshal with backwards compatibility
	ciOut := ClusterInstInfo{}
	err = json.Unmarshal(jsonData, &ciOut)
	require.Nil(t, err)
	cloudletKey, err := bindJSONObjectWithClusterInstKeyV2(&ciOut.Key, jsonData)
	require.Nil(t, err)
	// unmarshaled inst should match current format
	require.Equal(t, curInfo, ciOut)
	require.Equal(t, oldInfo.Key.CloudletKey, *cloudletKey)
}
