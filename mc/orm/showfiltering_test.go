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

package orm

import (
	"testing"

	"github.com/jinzhu/gorm"
	"github.com/edgexr/edge-cloud-infra/mc/ormapi"
	"github.com/stretchr/testify/require"
)

func TestJsonToDbNames(t *testing.T) {
	// test valid conversion
	in := map[string]interface{}{
		"Name":             "Joe",
		"PassCrackTimeSec": 3.14,
		"EnableTOTP":       false,
		"Iter":             22,
	}
	out, err := jsonToDbNames(in, &ormapi.User{})
	require.Nil(t, err)
	exp := map[string]interface{}{
		"name":                "Joe",
		"pass_crack_time_sec": 3.14,
		"enable_totp":         false,
		"iter":                22,
	}
	require.Equal(t, exp, out)

	// test invalid field
	in = map[string]interface{}{
		"Foo": "foo",
	}
	out, err = jsonToDbNames(in, &ormapi.User{})
	require.NotNil(t, err)
	require.Contains(t, err.Error(), "Foo not found in database object User")

	// test valid conversion with embedded struct
	in = map[string]interface{}{
		"Name":             "Joe",
		"Email":            "joe@joe.com",
		"PassCrackTimeSec": 3.14,
		"org":              "org1",
		"role":             "DeveloperContributor",
	}
	out, err = jsonToDbNames(in, &ormapi.ShowUser{})
	require.Nil(t, err)
	exp = map[string]interface{}{
		"name":                "Joe",
		"email":               "joe@joe.com",
		"pass_crack_time_sec": 3.14,
		"org":                 "org1",
		"role":                "DeveloperContributor",
	}
	require.Equal(t, exp, out)

	// test invalid conversion due to json tag specifying lower case
	in = map[string]interface{}{
		"Org": "org1",
	}
	out, err = jsonToDbNames(in, &ormapi.User{})
	require.NotNil(t, err)
	require.Contains(t, err.Error(), "Org not found in database object User")
}

func TestShowUserNoFilterKeys(t *testing.T) {
	// Make sure keys in global map are valid
	scope := &gorm.Scope{}
	scope = scope.New(&ormapi.ShowUser{})
	valid := make(map[string]struct{})
	for _, field := range scope.GetModelStruct().StructFields {
		valid[field.DBName] = struct{}{}
	}
	for _, name := range UserIgnoreFilterKeys {
		_, ok := valid[name]
		require.True(t, ok, "check that %s is valid", name)
	}
}
