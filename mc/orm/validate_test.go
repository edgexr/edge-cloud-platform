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

	"github.com/stretchr/testify/require"
)

func TestValidName(t *testing.T) {
	var err error

	// Artifactory repo name uses orgName currently with a prefix "repo-"$orgName
	// Total limit for artifactory name is 64 bytes. Work backwards to max orgName of 59 chars
	var NameMax59Chars = "12345678901234567890123456789012345678901234567890123456789"

	gname := GitlabGroupSanitize("atlantic, inc.")
	require.Equal(t, "atlantic--inc", gname)

	err = ValidName(".orgname_123.dev")
	require.NotNil(t, err, "invalid org name")

	err = ValidName("-orgname_123.dev")
	require.NotNil(t, err, "invalid org name")

	err = ValidName("orgname_123.dev.")
	require.NotNil(t, err, "invalid org name")

	err = ValidName("orgname_123dev-cache")
	require.NotNil(t, err, "invalid org name")

	err = ValidName("orgname_123dev.git")
	require.NotNil(t, err, "invalid org name")

	err = ValidName("orgname_123dev.atom")
	require.NotNil(t, err, "invalid org name")

	err = ValidName("orgname_123dev test")
	require.NotNil(t, err, "invalid org name")

	err = ValidName("orgname_123dev,test")
	require.NotNil(t, err, "invalid org name")

	err = ValidName("username_123dev::test")
	require.NotNil(t, err, "invalid user name")

	err = ValidName("username_123dev&test")
	require.NotNil(t, err, "invalid user name")

	err = ValidName(NameMax59Chars + "1")
	require.NotNil(t, err, "invalid org name")

	err = ValidName(NameMax59Chars)
	require.Nil(t, err)

}
