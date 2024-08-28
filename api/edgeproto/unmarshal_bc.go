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
	strings "strings"

	"github.com/edgexr/jsonparser"
)

// Support for unmarshaling older-object formatted JSON into current
// objects for backwards compatibility. These functions are used in
// upgrading old data in etcd to the newer format.

func BindJSONAppInstV2(ai *AppInst, jsonData []byte) error {
	if ai.CloudletKey.IsEmpty() {
		// read the cloudlet key from the old location that
		// was part of the key
		out, _, _, err := jsonparser.Get(jsonData, "key", "cloudlet_key")
		if err == nil {
			// data was found, unmarshal it
			err = json.Unmarshal(out, &ai.CloudletKey)
			if err != nil {
				return err
			}
		}
	}
	return nil
}

func BindJSONClusterInstV2(ci *ClusterInst, jsonData []byte) error {
	if ci.CloudletKey.IsEmpty() {
		// read the cloudlet key from the old location that
		// was part of the key
		out, _, _, err := jsonparser.Get(jsonData, "key", "cloudlet_key")
		if err == nil {
			// data was found, unmarshal it
			err = json.Unmarshal(out, &ci.CloudletKey)
			if err != nil {
				return err
			}
		}
	}
	if ci.Key.IsEmpty() {
		// read the cluster key from the old location that
		// was part of the key
		out, _, _, err := jsonparser.Get(jsonData, "key", "cluster_key")
		if err == nil {
			// data was found, unmarshal it
			err = json.Unmarshal(out, &ci.Key)
			if err != nil {
				return err
			}
		}
	}
	return nil
}

func BindJSONClusterInstInfoV2(info *ClusterInstInfo, jsonData []byte) (*CloudletKey, error) {
	return bindJSONObjectWithClusterInstKeyV2(&info.Key, jsonData)
}

func BindJSONClusterRefsV2(refs *ClusterRefs, jsonData []byte) (*CloudletKey, error) {
	return bindJSONObjectWithClusterInstKeyV2(&refs.Key, jsonData)
}

// Note here that it assumed the objKey is a child field "key" in
// the parent object, and the jsonData corresponds to the parent.
// Examples of this are ClusterInstInfo, ClusterRefs.
func bindJSONObjectWithClusterInstKeyV2(objKey *ClusterKey, jsonData []byte) (*CloudletKey, error) {
	// read the cluster key from the old location
	out, _, _, err := jsonparser.Get(jsonData, "key", "cluster_key")
	if err == nil {
		// data was found, unmarshal it
		err = json.Unmarshal(out, objKey)
		if err != nil {
			return nil, err
		}
	}
	cloudletKey := CloudletKey{}
	out, _, _, err = jsonparser.Get(jsonData, "key", "cloudlet_key")
	if err == nil {
		// data was found, unmarshal it
		err = json.Unmarshal(out, &cloudletKey)
		if err != nil {
			return nil, err
		}
	}
	return &cloudletKey, nil
}

// BindJSONAppInstKeyV2 reads jsonData corresponding to either
// AppInstKey or AppInstKeyV2. If the jsonData is AppInstKeyV2,
// it returns both AppInstKey and AppInstKeyV2. If the jsonData
// is from AppInstKey, only AppInstKey is returned.
func BindJSONAppInstKeyV2(jsonData []byte) (*AppInstKey, *AppInstKeyV2, error) {
	// Note that Name, Organization are in the same places
	// between AppInstKeyV2 and AppInstKey, so we can directly
	// unmarshal into the latest version. We just extract the
	// cloudlet key info seperately.
	key := AppInstKey{}
	if strings.Contains(string(jsonData), `"cloudlet_key":{`) {
		v2 := AppInstKeyV2{}
		err := json.Unmarshal(jsonData, &v2)
		if err != nil {
			return nil, nil, err
		}
		key.Name = v2.Name
		key.Organization = v2.Organization
		return &key, &v2, nil
	} else {
		err := json.Unmarshal(jsonData, &key)
		if err != nil {
			return nil, nil, err
		}
		return &key, nil, nil
	}
}

func (s *CloudletKey) IsEmpty() bool {
	return s.Name == "" && s.Organization == ""
}

func (s *ClusterKey) IsEmpty() bool {
	return s.Name == "" && s.Organization == ""
}

func (s *AppInstKey) IsEmpty() bool {
	return s.Name == "" && s.Organization == ""
}
