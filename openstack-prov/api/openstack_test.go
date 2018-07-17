package mexosapi

import (
	"io/ioutil"
	"os"
	"testing"

	log "github.com/bobbae/logrus"
)

var myRegion string

func TestInit(t *testing.T) {
	log.SetLevel(log.DebugLevel)
}

func TestInternOSEnvAAABBB(t *testing.T) {
	home := os.Getenv("HOME")
	err := InternOSEnv(home + "/os.env")
	if err != nil {
		t.Errorf("cannot intern OS env %v", err)
	}
	myRegion = os.Getenv("OS_REGION_NAME")
}

func TestGetOSClient(t *testing.T) {
	tables := []struct {
		Region  string
		Success bool
	}{
		{myRegion, true},
		{"RegionTwo", false},
	}

	for _, entry := range tables {
		client, err := GetOSClient(entry.Region)
		if err != nil {
			log.Println(entry, err)
			t.Errorf("failed to get Openstack client, %v", err)
		} else {
			log.Println("got client handle", client)
		}
		if entry.Success && err != nil {
			t.Errorf("err %v, entry %v", err, entry)
		}
	}
}

func TestGetLimits(t *testing.T) {
	client, err := GetOSClient(myRegion)
	if err != nil {
		t.Errorf("cannot get client, %v", err)
		return
	}

	limits, err := GetLimits(client)

	if err != nil {
		t.Errorf("can't get limits, %v", err)
	}

	log.Println("limits", limits)
}

func TestListServers(t *testing.T) {
	client, err := GetOSClient(myRegion)
	if err != nil {
		t.Errorf("cannot get client, %v", err)
		return
	}

	servers, err := ListServers(client, &NovaListArgs{})

	if err != nil {
		t.Errorf("can't list servers, %v", err)
	}

	log.Println("list servers", servers)
}

func TestListImages(t *testing.T) {
	client, err := GetOSClient(myRegion)
	if err != nil {
		t.Errorf("cannot get client, %v", err)
		return
	}

	images, err := ListImages(client, &ImageListArgs{})

	if err != nil {
		t.Errorf("can't list images, %v", err)
	}

	log.Println("list images", images)
}

func TestListFlavors(t *testing.T) {
	client, err := GetOSClient(myRegion)
	if err != nil {
		t.Errorf("cannot get client, %v", err)
		return
	}

	flavors, err := ListFlavors(client)

	if err != nil {
		t.Errorf("can't list flavors, %v", err)
	}

	log.Println("list flavors", flavors)
}

func TestListNetworks(t *testing.T) {
	client, err := GetOSClient(myRegion)
	if err != nil {
		t.Errorf("cannot get client, %v", err)
		return
	}

	networks, err := ListNetworks(client)

	if err != nil {
		t.Errorf("can't list networks, %v", err)
	}

	log.Println("list networks", networks)
}

func TestCreateServerAAA(t *testing.T) {
	var True, False bool
	True = true
	False = false

	client, err := GetOSClient(myRegion)
	if err != nil {
		t.Errorf("cannot get client, %v", err)
		return
	}
	images, err := ListImages(client, &ImageListArgs{})

	if err != nil {
		t.Errorf("can't list images, %v", err)
	}

	var testImageID string

	for _, img := range images {
		if img.Name == "mobiledgex-16.04" {
			testImageID = img.ID
		}
	}

	log.Println("testImageID", testImageID)
	if testImageID == "" {
		t.Errorf("mobiledgex-16.04 image not found")
	}

	var testNetworkID string

	networks, err := ListNetworks(client)

	if err != nil {
		t.Errorf("can't list networks, %v", err)
	}

	for _, network := range networks {
		if network.Label == "public" {
			testNetworkID = network.ID
		}
	}

	log.Println("testNetworkID", testNetworkID)

	var testFlavorID string

	flavors, err := ListFlavors(client)

	if err != nil {
		t.Errorf("can't list flavors, %v", err)
	}

	for _, flavor := range flavors {
		if flavor.Name == "m1.large" {
			testFlavorID = flavor.ID
		}
	}

	log.Println("testFlavorID", testFlavorID)

	tables := []struct {
		Arg     NovaArgs
		Success bool
	}{
		{
			NovaArgs{
				myRegion,
				"nova", // zone: not internal.
				"tenant-1",
				"test-1",
				testImageID,
				testFlavorID, //m1.large
				testNetworkID,
				"172.24.4.23",
				map[string]string{"edgeproxy": "172.24.4.1", "role": "k8s-master", "k8smaster": "172.24.4.23"},
				[]byte{},
				&True,
			},
			true,
		},
		{
			NovaArgs{
				myRegion,
				"nova", // zone: not internal.
				"tenant-1",
				"test-2",
				testImageID,
				testFlavorID, //m1.large
				testNetworkID,
				"172.24.4.24",
				map[string]string{"edgeproxy": "172.24.4.1", "role": "k8s-node", "k8smaster": "172.24.4.23"},
				[]byte{},
				&True,
			},
			true,
		},
		{
			NovaArgs{
				myRegion,
				"nova", // zone: not internal.
				"tenant-1",
				"test-3",
				testImageID,
				testFlavorID, //m1.large
				testNetworkID,
				"172.24.4.25",
				map[string]string{"edgeproxy": "172.24.4.1", "role": "k8s-node", "k8smaster": "172.24.4.23"},
				[]byte{},
				&True,
			},
			true,
		},
		{
			NovaArgs{
				"RegionOneFail", "internal", "tenant-1-fail",
				"test-1-fail", "mobiledgex-16.04-none", "m1.largestintheworld",
				"630a8e5e-6031-4d1a-a16c-314c893f009d", "172.24.4.123",
				map[string]string{"edgeproxy": "172.24.4.1", "invalid": "none"},
				[]byte{},
				&False,
			},
			false,
		},
	}

	dat, err := ioutil.ReadFile("userdata.txt")
	if err != nil {
		t.Errorf("can't read userdata.txt")
	}
	if len(dat) < 1 {
		t.Errorf("userdata too short")
	}

	log.Println("userdata", string(dat))
	log.Println("client", client)

	for _, entry := range tables {
		entry.Arg.UserData = dat //Auto converted to base64
		err := CreateServer(client, &entry.Arg)
		if err != nil {
			log.Println("create server error", entry.Arg, err)
		} else {
			log.Println("created server", entry.Arg, entry)
		}
		if entry.Success && err != nil {
			t.Errorf("failed to create server, %v", err)
		}
	}
}

func TestDeleteServerBBB(t *testing.T) {
	client, err := GetOSClient(myRegion)
	if err != nil {
		t.Errorf("cannot get client, %v", err)
		return
	}

	servers, err := ListServers(client, &NovaListArgs{})

	if err != nil {
		t.Errorf("can't list servers, %v", err)
	}

	var testServerID, testServerID2, testServerID3 string

	for _, srv := range servers {
		if srv.Name == "test-1.tenant-1.mobiledgex.com" {
			testServerID = srv.ID
		}
		if srv.Name == "test-2.tenant-1.mobiledgex.com" {
			testServerID2 = srv.ID
		}
		if srv.Name == "test-3.tenant-1.mobiledgex.com" {
			testServerID3 = srv.ID
		}
	}

	log.Println("testServerID", testServerID)

	tables := []struct {
		ID      string
		Success bool
	}{
		{testServerID, true},
		{testServerID2, true},
		{testServerID3, true},
		{"57db4ce9-7e68-4507-9aa4-ba569a4a79bb", false},
	}

	for _, entry := range tables {
		err := DeleteServer(client, entry.ID)
		if err != nil {
			log.Println("server delete fail", entry.ID, err)
		} else {
			log.Println("server deleted ok", entry.ID, entry)
		}

		if entry.Success && err != nil {
			t.Errorf("can't delete server %v,%v", entry, err)
		}
	}
}
