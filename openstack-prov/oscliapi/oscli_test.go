package oscli

import (
	"fmt"
	"os"
	"testing"

	log "github.com/sirupsen/logrus"
)

var mexTestInfra2 = os.Getenv("MEX_TEST_INFRA")

// The order of tests are important here. Also 'source openrc' or the equivalent to set up
// the OS_XXX env variables before running this.
// There is no mock for this for now.
// For CICD, either create a real live test cluster for that use, or
// write a bunch of fake mock returns -- will not do this here.
// During development, each of the tests were run individually against a live cluster.

var testServerName = "go-test1"
var testImageName = "mobiledgex-16.04-2"
var testFlavor = "m4.small"
var testUserData = "userdata.txt"
var testNetwork = "test-external-network-shared"
var testSubnet = "test-internal-network"
var testRange = "10.102.102.0/24"
var testGateway = "10.102.102.1"
var testRouter = "test-router-1"

func TestInit(t *testing.T) {
	if mexTestInfra2 == "" {
		return
	}
	log.SetLevel(log.DebugLevel)
}

func TestGetLimits(t *testing.T) {
	if mexTestInfra2 == "" {
		return
	}
	out, err := GetLimits()
	if err != nil {
		t.Errorf("cannot GetLimits, %v", err)
	} else {
		fmt.Println(out)
	}
}

func TestListServers(t *testing.T) {
	if mexTestInfra2 == "" {
		return
	}
	out, err := ListServers()
	if err != nil {
		t.Errorf("cannot ListServers, %v", err)
	} else {
		fmt.Println(out)
	}
}

func TestListImages(t *testing.T) {
	if mexTestInfra2 == "" {
		return
	}
	out, err := ListImages()
	if err != nil {
		t.Errorf("cannot ListImages, %v", err)
	} else {
		fmt.Println(out)
	}
}

func TestListNetworks(t *testing.T) {
	if mexTestInfra2 == "" {
		return
	}
	out, err := ListNetworks()
	if err != nil {
		t.Errorf("cannot ListNetworks, %v", err)
	} else {
		fmt.Println(out)
	}
}

func TestListFlavors(t *testing.T) {
	if mexTestInfra2 == "" {
		return
	}
	out, err := ListFlavors()
	if err != nil {
		t.Errorf("cannot ListFlavors, %v", err)
	} else {
		fmt.Println(out)
	}
}

func TestCreateServer(t *testing.T) {
	if mexTestInfra2 == "" {
		return
	}
	opts := &ServerOpt{
		Name:       testServerName,
		Image:      testImageName,
		Flavor:     testFlavor,
		UserData:   testUserData,
		NetIDs:     []string{testNetwork},
		Properties: []string{},
	}
	err := CreateServer(opts)
	if err != nil {
		t.Errorf("%v", err)
	} else {
		fmt.Println("created", opts)
	}

	opts = &ServerOpt{
		Name:       testServerName,
		Image:      testImageName,
		Flavor:     testFlavor,
		UserData:   testUserData,
		NetIDs:     []string{testNetwork},
		Properties: []string{},
	}
	err = CreateServer(opts)
	if err != nil {
		fmt.Println("correctly failed to create", opts)
	} else {
		t.Errorf("should have failed to create server with the same name")
	}
}

func TestGetServerDetails(t *testing.T) {
	if mexTestInfra2 == "" {
		return
	}
	sd, err := GetServerDetails(testServerName)
	if err != nil {
		t.Errorf("server show err, %v", err)
		return
	}
	fmt.Println("server", sd)

	_, err = GetServerDetails(testServerName + "xxx")
	if err == nil {
		t.Errorf("should have failed")
		return
	}
	fmt.Println("correctly failed to get details for bogus server name")
}

func TestDeleteServer(t *testing.T) {
	if mexTestInfra2 == "" {
		return
	}
	sd, err := GetServerDetails(testServerName)
	if err != nil {
		t.Errorf("cannot show server %s, %v", testServerName, err)
	}

	if sd.Name != testServerName { //Xxx never happen
		t.Errorf("name mismatch")
	}

	log.Debugln("delete server %s %s", sd.Name, sd.ID)

	err = DeleteServer(sd.ID)
	if err != nil {
		t.Errorf("cannot delete server %s %s, %v", sd.Name, sd.ID, err)
	} else {
		fmt.Println("server", sd.Name, "deleted ok")
	}
}

func TestCreateNetwork(t *testing.T) {
	if mexTestInfra2 == "" {
		return
	}
	err := CreateNetwork(testNetwork)
	if err != nil {
		t.Errorf("cannot create network, %v", err)
		return
	}
	fmt.Println("network", testNetwork, "created")

	err = CreateNetwork(testNetwork)
	if err == nil {
		t.Errorf("should have failed to create network with existing name")
		return
	}
	fmt.Println("correctly failed to create network with duplicate name")
}

func TestCreateSubnet(t *testing.T) {
	if mexTestInfra2 == "" {
		return
	}
	err := CreateSubnet(testRange, testNetwork, testGateway, testSubnet, false)
	if err != nil {
		t.Errorf("cannot create subnet, %v", err)
		return
	}
	fmt.Println("created subnet ", testSubnet)

	err = CreateSubnet(testRange, testNetwork, testGateway, testSubnet, false)
	if err == nil {
		t.Errorf("should have failed to create subnet with duplicate name")
		return
	}
	fmt.Println("correctly failed to create duplicate subnet")
}

func TestCreateRouter(t *testing.T) {
	if mexTestInfra2 == "" {
		return
	}
	err := CreateRouter(testRouter)
	if err != nil {
		t.Errorf("can't create router, %v", err)
		return
	}
	fmt.Println("created router ", testRouter)

	err = CreateRouter(testRouter)
	if err == nil {
		t.Errorf("should have failed to create duplicate router")
		return
	}
	fmt.Println("correctly failed to create dup router")
}

func TestSetRouter(t *testing.T) {
	if mexTestInfra2 == "" {
		return
	}
	err := SetRouter(testRouter, testNetwork)
	if err != nil {
		fmt.Printf("can't set router, %v", err)
		fmt.Printf("not an error.")
		//because testNetwork is not a real external network
		return
	}
	fmt.Printf("set router %s in net %s\n", testRouter, testNetwork)

	err = SetRouter(testRouter, testNetwork)
	if err == nil {
		t.Errorf("should have failed to set router again")
		return
	}
	fmt.Printf("correctly failed to set router again")
}

func TestAddRouterSubnet(t *testing.T) {
	if mexTestInfra2 == "" {
		return
	}
	err := AddRouterSubnet(testRouter, testSubnet)
	if err != nil {
		t.Errorf("can't add router to subnet, %v", err)
		return
	}
	fmt.Printf("added router %s to subnet %s\n", testRouter, testSubnet)

	err = AddRouterSubnet(testRouter, testSubnet)
	if err == nil {
		t.Errorf("should have failed to add dup router to subnet")
		return
	}
	fmt.Printf("correctly failed to add dup router to subnet")
}

func TestListSubnets(t *testing.T) {
	if mexTestInfra2 == "" {
		return
	}
	subnets, err := ListSubnets("") //list all
	if err != nil {
		t.Errorf("can't list subnets, %v", err)
		return
	}
	fmt.Printf("subnets %v\n", subnets)
}

func TestListRouters(t *testing.T) {
	if mexTestInfra2 == "" {
		return
	}
	routers, err := ListRouters()
	if err != nil {
		t.Errorf("can't list routers, %v", err)
		return
	}
	fmt.Printf("routers %v\n", routers)
}

// The order of the following sequence of tests are particularly important
// For example, it is good idea to remove the router assigned to a subnet
// before removing subnet.

func TestRemoveRouterSubnet(t *testing.T) {
	if mexTestInfra2 == "" {
		return
	}
	err := RemoveRouterSubnet(testRouter, testSubnet)
	if err != nil {
		t.Errorf("can't remove router from subnet, %v", err)
		return
	}
	fmt.Printf("removed router %s from subnet %s\n", testRouter, testSubnet)

	err = RemoveRouterSubnet(testRouter, testSubnet)
	if err == nil {
		t.Errorf("should have failed to remove router from subnet again")
		return
	}
	fmt.Printf("correctly failed to remove the router from subnet again")
}

func TestDeleteRouter(t *testing.T) {
	if mexTestInfra2 == "" {
		return
	}
	err := DeleteRouter(testRouter)
	if err != nil {
		t.Errorf("can't delete router, %v", err)
		return
	}
	fmt.Println("deleted router ", testRouter)

	err = DeleteRouter(testRouter)
	if err == nil {
		t.Errorf("should have failed to delete router again")
		return
	}
	fmt.Println("correctly failed to remove router again")

}
func TestDeleteSubnet(t *testing.T) {
	if mexTestInfra2 == "" {
		return
	}
	err := DeleteSubnet(testSubnet)
	if err != nil {
		t.Errorf("cannot delete subnet , %v", err)
		return
	}
	fmt.Println("deleted subnet s", testSubnet)

	err = DeleteSubnet(testSubnet)
	if err == nil {
		t.Errorf("should have failed to delete subnet again")
		return
	}
	fmt.Println("correctly failed to remove subnet again")
}

func TestDeleteNetwork(t *testing.T) {
	if mexTestInfra2 == "" {
		return
	}
	err := DeleteNetwork(testNetwork)
	if err != nil {
		t.Errorf("cannot delete network, %v", err)
		return
	}
	fmt.Println("deleted network ", testNetwork)

	err = DeleteNetwork(testNetwork)
	if err == nil {
		t.Errorf("should have failed to delete network again")
		return
	}
	fmt.Println("correctly failed to remove the network again")
}

// The orders are not preserved here. The server should be running.
// But it won't be when we run tests serially.

var testImage = "test-image-1"

// TestCreateImage is kind of `snapshotting` the running KVM image into glance
func TestCreateImage(t *testing.T) {
	if mexTestInfra2 == "" {
		return
	}
	err := CreateImage(testServerName, testImage)
	if err != nil {
		t.Errorf("cannot create image , %v", err)
		return
	}
	fmt.Println("created image", testImage)

	err = CreateImage(testServerName, testImage)
	if err == nil {
		t.Errorf("should have failed to create image again")
		return
	}
	fmt.Println("correctly failed to create image again")
}

var saveImageFile = "test-save-image.qcow2" // will be created locally. Potentially very large.

//Saving image that has been tagged into glance with a name before. The saving is
// actually retrieving the image over network from cloudlet, into local storage.
// It can take some time and storage.
func TestSaveImage(t *testing.T) {
	if mexTestInfra2 == "" {
		return
	}
	//This can take a while
	err := SaveImage(saveImageFile, testImage)
	if err != nil {
		t.Errorf("cannot save image , %v", err)
		return
	}
	fmt.Println("saved image", testImage+"XXX")

	err = SaveImage(saveImageFile, testImage)
	if err == nil {
		t.Errorf("should have failed to save bogus image locally")
		return
	}
	fmt.Println("correctly failed to save bogus image")

	//TODO: it is possible for the platform to refuse this request when
	// the platform is slow and the tasks ongoing are queued for whatever reason, such
	// as slow storage. So we can test for retries and legit fails. But we don't for now.
}

func TestDeleteImage(t *testing.T) {
	if mexTestInfra2 == "" {
		return
	}
	err := DeleteImage(testImage)
	if err != nil {
		t.Errorf("cannot delete image , %v", err)
		return
	}
	fmt.Println("deleted image", testImage)

	err = DeleteImage(testImage)
	if err == nil {
		t.Errorf("should have failed to delete non existing image")
		return
	}
	fmt.Println("correctly failed to delete non existing image")
}

var testExternalNetwork = "external-network-shared"

func TestGetExternalGateway(t *testing.T) {
	if mexTestInfra2 == "" {
		return
	}
	eg, err := GetExternalGateway(testExternalNetwork)
	if err != nil {
		t.Errorf("can't get external gateway for %s, %v", testExternalNetwork, err)
		return
	}

	fmt.Println("external gateway for", testExternalNetwork, eg)
}

func TestSetServerProperty(t *testing.T) {
	if mexTestInfra2 == "" {
		return
	}
	nm := os.Getenv("MEX_TEST_MN")

	err := SetServerProperty(nm, "mex-flavor=x1.medium")
	if err != nil {
		t.Error(err)
	}
}
