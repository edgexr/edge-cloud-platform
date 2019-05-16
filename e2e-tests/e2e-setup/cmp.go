package e2esetup

import (
	"log"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/mobiledgex/edge-cloud-infra/mc/ormapi"
	"github.com/mobiledgex/edge-cloud/cloudcommon"
	dmeproto "github.com/mobiledgex/edge-cloud/d-match-engine/dme-proto"
	"github.com/mobiledgex/edge-cloud/edgeproto"
	"github.com/mobiledgex/edge-cloud/setup-env/util"
)

// go-cmp Options
var IgnoreAdminRole = cmpopts.AcyclicTransformer("removeAdminRole", func(roles []ormapi.Role) []ormapi.Role {
	// remove automatically created admin role
	newroles := make([]ormapi.Role, 0)
	for _, role := range roles {
		if role.Username == "mexadmin" {
			continue
		}
		newroles = append(newroles, role)
	}
	return newroles
})

var IgnoreAdminUser = cmpopts.AcyclicTransformer("removeAdminUser", func(users []ormapi.User) []ormapi.User {
	// remove automatically created super user
	newusers := make([]ormapi.User, 0)
	for _, user := range users {
		if user.Name == "mexadmin" {
			continue
		}
		newusers = append(newusers, user)
	}
	return newusers
})

var IgnoreAppInstUri = cmpopts.AcyclicTransformer("removeAppInstUri", func(inst edgeproto.AppInst) edgeproto.AppInst {
	// Appinstance URIs usually not provisioned, as they are inherited
	// from the cloudlet. However they are provioned for the default
	// appinst. So we cannot use "nocmp". Remove the URIs for
	// non-defaultCloudlets.
	out := inst
	if out.Key.ClusterInstKey.CloudletKey != cloudcommon.DefaultCloudletKey {
		out.Uri = ""
	}
	return out
})

//compares two yaml files for equivalence
//TODO need to handle different types of interfaces besides appdata, currently using
//that to sort
func CompareYamlFiles(firstYamlFile string, secondYamlFile string, fileType string) bool {
	var err1 error
	var err2 error
	var y1 interface{}
	var y2 interface{}
	copts := []cmp.Option{}

	if fileType == "mcdata" {
		var a1 ormapi.AllData
		var a2 ormapi.AllData

		err1 = util.ReadYamlFile(firstYamlFile, &a1)
		err2 = util.ReadYamlFile(secondYamlFile, &a2)

		copts = []cmp.Option{
			cmpopts.IgnoreTypes(time.Time{}, dmeproto.Timestamp{}),
			IgnoreAdminRole,
			IgnoreAppInstUri,
		}
		copts = append(copts, edgeproto.IgnoreTaggedFields("nocmp")...)
		copts = append(copts, edgeproto.CmpSortSlices()...)

		y1 = a1
		y2 = a2
	} else if fileType == "mcusers" {
		// remove roles
		var a1 []ormapi.User
		var a2 []ormapi.User

		err1 = util.ReadYamlFile(firstYamlFile, &a1)
		err2 = util.ReadYamlFile(secondYamlFile, &a2)

		copts = []cmp.Option{
			cmpopts.IgnoreTypes(time.Time{}),
			IgnoreAdminUser,
		}
		y1 = a1
		y2 = a2
	} else {
		return util.CompareYamlFiles(firstYamlFile,
			secondYamlFile, fileType)
	}

	util.PrintStepBanner("running compareYamlFiles")
	log.Printf("Comparing yamls: %v  %v\n", firstYamlFile, secondYamlFile)

	if err1 != nil {
		log.Printf("Error in reading yaml file %v -- %v\n", firstYamlFile, err1)
		return false
	}
	if err2 != nil {
		log.Printf("Error in reading yaml file %v -- %v\n", secondYamlFile, err2)
		return false
	}

	if !cmp.Equal(y1, y2, copts...) {
		log.Println("Comparison fail")
		log.Printf(cmp.Diff(y1, y2, copts...))
		return false
	}
	log.Println("Comparison success")
	return true
}
