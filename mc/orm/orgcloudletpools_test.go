package orm

import (
	fmt "fmt"
	"testing"

	"github.com/mobiledgex/edge-cloud-infra/mc/ormapi"
	"github.com/stretchr/testify/require"
)

func addNewTestOrgCloudletPool(data *[]ormapi.OrgCloudletPool, i int, typ string) {
	op := ormapi.OrgCloudletPool{
		Org:             fmt.Sprintf("testocp-org%d", i),
		Region:          "USA",
		CloudletPool:    fmt.Sprintf("testocp-pool%d", i),
		CloudletPoolOrg: fmt.Sprintf("testocp-poolorg%d", i),
		Type:            typ,
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

func TestGetAccessGranted(t *testing.T) {
	addNew := addNewTestOrgCloudletPool

	// Data with some OrgCloudletPools with matching invitations and
	// confirmations, and some without matching, in random order.
	data := []ormapi.OrgCloudletPool{}
	addNew(&data, 7, ormapi.CloudletPoolAccessConfirmation)
	addNew(&data, 1, ormapi.CloudletPoolAccessInvitation)
	addNew(&data, 1, ormapi.CloudletPoolAccessConfirmation)
	addNew(&data, 2, ormapi.CloudletPoolAccessInvitation)
	addNew(&data, 3, ormapi.CloudletPoolAccessConfirmation)
	addNew(&data, 4, ormapi.CloudletPoolAccessInvitation)
	addNew(&data, 5, ormapi.CloudletPoolAccessConfirmation)
	addNew(&data, 6, ormapi.CloudletPoolAccessInvitation)
	addNew(&data, 4, ormapi.CloudletPoolAccessConfirmation)
	addNew(&data, 7, ormapi.CloudletPoolAccessInvitation)
	// Expect to only get single instances of the matching ones,
	// with no type set.
	expected := []ormapi.OrgCloudletPool{}
	addNew(&expected, 1, "")
	addNew(&expected, 4, "")
	addNew(&expected, 7, "")

	actual := getAccessGranted(data)
	require.Equal(t, expected, actual)
}
