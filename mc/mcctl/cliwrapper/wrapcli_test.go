package cliwrapper

import (
	"sort"
	"testing"

	"github.com/mobiledgex/edge-cloud-infra/mc/mcctl/ormctl"
	"github.com/mobiledgex/edge-cloud-infra/mc/ormapi"
	"github.com/mobiledgex/edge-cloud/cli"
	edgeproto "github.com/mobiledgex/edge-cloud/edgeproto"
	"github.com/stretchr/testify/require"
)

func TestObjToArgs(t *testing.T) {
	var obj interface{}
	var args []string

	obj = &ormapi.User{
		Name:     "user1",
		Email:    "user1@email.com",
		Passhash: "user1password",
	}
	args = []string{"name=user1", "email=user1@email.com",
		"passhash=user1password"}
	testObjToArgs(t, obj, args)

	obj = &ormapi.CreateUser{
		User: ormapi.User{
			Name:     "user2",
			Email:    "user2@email.com",
			Passhash: "user2password",
		},
		Verify: ormapi.EmailRequest{
			OperatingSystem: "mac osx",
			CallbackURL:     "http://foo",
			ClientIP:        "10.10.10.10",
		},
	}
	args = []string{"user.name=user2", "user.email=user2@email.com",
		"user.passhash=user2password", "verify.operatingsystem=\"mac osx\"",
		"verify.callbackurl=http://foo", "verify.clientip=10.10.10.10"}
	testObjToArgs(t, obj, args)

	obj = nil
	args = []string{}
	testObjToArgs(t, obj, args)

	obj = &ormapi.RegionCloudlet{
		Region: "local",
		Cloudlet: edgeproto.Cloudlet{
			IpSupport: edgeproto.IpSupport_IP_SUPPORT_DYNAMIC,
		},
	}
	args = []string{"region=local", "cloudlet.ipsupport=Dynamic"}
	testObjToArgs(t, obj, args)
}

func testObjToArgs(t *testing.T, obj interface{}, expected []string) {
	args, err := cli.MarshalArgs(obj, nil, nil)
	require.Nil(t, err)
	sort.Strings(args)
	sort.Strings(expected)
	require.Equal(t, expected, args)
}

func TestCliPath(t *testing.T) {
	NewClient()
}

func TestInjectRequiredArgs(t *testing.T) {
	cmd := *ormctl.MustGetCommand("CreateUser")
	// add some more required args to cover different types,
	// so we cover string, int, float, bool.
	cmd.RequiredArgs = "name email iter passcracktimesec enabletotp"
	cmd.AliasArgs += " iter=user.iter passcracktimesec=user.passcracktimesec"

	args := []string{}
	expectedArgs := append(args, `name=""`, `email=""`, `iter=0`, `passcracktimesec=0`, `enabletotp=false`)
	actualArgs := injectRequiredArgs(args, &cmd)
	require.Equal(t, expectedArgs, actualArgs)

	args = []string{"email=foobar", "passcracktimesec=1"}
	expectedArgs = append(args, `name=""`, `iter=0`, `enabletotp=false`)
	actualArgs = injectRequiredArgs(args, &cmd)
	require.Equal(t, expectedArgs, actualArgs)
}
