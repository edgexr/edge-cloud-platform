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
	fmt "fmt"
	"testing"

	"github.com/edgexr/edge-cloud-infra/mc/ormapi"
	"github.com/stretchr/testify/require"
)

func addNewTestOrgCloudletPool(data *[]ormapi.OrgCloudletPool, i int, typ string) {
	decision := ""
	if typ == ormapi.CloudletPoolAccessDecisionAccept || typ == ormapi.CloudletPoolAccessDecisionReject {
		decision = typ
		typ = ormapi.CloudletPoolAccessResponse
	}
	op := ormapi.OrgCloudletPool{
		Org:             fmt.Sprintf("testocp-org%d", i),
		Region:          "USA",
		CloudletPool:    fmt.Sprintf("testocp-pool%d", i),
		CloudletPoolOrg: fmt.Sprintf("testocp-poolorg%d", i),
		Type:            typ,
		Decision:        decision,
	}
	*data = append(*data, op)
}

func addOldTestOrgCloudletPool(data *[]OrgCloudletPool, i int) {
	op := OrgCloudletPool{
		Org:             fmt.Sprintf("testocp-org%d", i),
		Region:          "USA",
		CloudletPool:    fmt.Sprintf("testocp-pool%d", i),
		CloudletPoolOrg: fmt.Sprintf("testocp-poolorg%d", i),
	}
	*data = append(*data, op)
}

func TestGetAccessGrantedPending(t *testing.T) {
	addNew := addNewTestOrgCloudletPool

	// Data with some OrgCloudletPools with matching invitations and
	// confirmations, and some without matching, in random order.
	data := []ormapi.OrgCloudletPool{}
	addNew(&data, 7, ormapi.CloudletPoolAccessDecisionAccept)
	addNew(&data, 1, ormapi.CloudletPoolAccessInvitation)
	addNew(&data, 1, ormapi.CloudletPoolAccessDecisionAccept)
	addNew(&data, 2, ormapi.CloudletPoolAccessInvitation)
	addNew(&data, 3, ormapi.CloudletPoolAccessDecisionAccept)
	addNew(&data, 4, ormapi.CloudletPoolAccessInvitation)
	addNew(&data, 6, ormapi.CloudletPoolAccessInvitation)
	addNew(&data, 5, ormapi.CloudletPoolAccessDecisionAccept)
	addNew(&data, 4, ormapi.CloudletPoolAccessDecisionAccept)
	addNew(&data, 7, ormapi.CloudletPoolAccessInvitation)
	addNew(&data, 8, ormapi.CloudletPoolAccessInvitation)
	addNew(&data, 8, ormapi.CloudletPoolAccessDecisionReject)
	addNew(&data, 9, ormapi.CloudletPoolAccessInvitation)
	addNew(&data, 10, ormapi.CloudletPoolAccessDecisionReject)
	addNew(&data, 10, ormapi.CloudletPoolAccessInvitation)
	// Expect to only get single instances of the matching ones,
	// with no type set.
	expected := []ormapi.OrgCloudletPool{}
	addNew(&expected, 1, "")
	addNew(&expected, 4, "")
	addNew(&expected, 7, "")
	actual := getAccessGranted(data)
	require.Equal(t, expected, actual)

	// Expect only invitations without confirmation/rejection
	expected = []ormapi.OrgCloudletPool{}
	addNew(&expected, 2, "")
	addNew(&expected, 6, "")
	addNew(&expected, 9, "")
	actual = getAccessPending(data)
	require.Equal(t, expected, actual)
}
