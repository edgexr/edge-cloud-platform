package ccrm

import (
	"context"
	"crypto/md5"
	_ "embed"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	dme "github.com/edgexr/edge-cloud-platform/api/dme-proto"
	"github.com/edgexr/edge-cloud-platform/api/edgeproto"
	"github.com/edgexr/edge-cloud-platform/pkg/cloudcommon"
	"github.com/edgexr/edge-cloud-platform/pkg/cloudcommon/node"
	"github.com/edgexr/edge-cloud-platform/pkg/log"
	"github.com/edgexr/edge-cloud-platform/pkg/mc/ormutil"
	"github.com/edgexr/edge-cloud-platform/pkg/platform/common/confignode"
	"github.com/stretchr/testify/require"
)

var testFlags = Flags{
	Region:                        "test-region",
	AppDNSRoot:                    "app.test.domain",
	DnsZone:                       "test.domain",
	CloudletRegistryPath:          "ghcr.io/company/crm-image",
	CloudletVMImagePath:           "https://console.test.domain/storage/v1/artifacts/edgecloudorg",
	VersionTag:                    "1234-99-XX",
	ControllerNotifyAddr:          "controller.default:4444",
	ControllerPublicNotifyAddr:    "tr.ctrl.test.domain",
	ControllerPublicAccessApiAddr: "tr.ctrl.test.domain:40000",
	AnsibleListenAddr:             "0.0.0.0:80",
	AnsiblePublicAddr:             "https://ansible.test.domain",
	ThanosRecvAddr:                "thanos-addr",
	DebugLevels:                   "api,infra,notify",
}

func getTestCloudlet() edgeproto.Cloudlet {
	return edgeproto.Cloudlet{
		Key: edgeproto.CloudletKey{
			Organization: "testoper",
			Name:         "New York Site",
		},
		IpSupport:     edgeproto.IpSupport_IP_SUPPORT_DYNAMIC,
		NumDynamicIps: 100,
		Location: dme.Loc{
			Latitude:  40.712776,
			Longitude: -74.005974,
		},
		PlatformType: "fake",
		Flavor: edgeproto.FlavorKey{
			Name: "flavor1",
		},
		NotifySrvAddr:                 "127.0.0.1:51002",
		PhysicalName:                  "NewYorkSite",
		Deployment:                    "docker",
		DefaultResourceAlertThreshold: 80,
		EnvVar: map[string]string{
			"FOO":             "foo",
			"BAR_ONLY":        "no-bar",
			"JAEGER_ENDPOINT": "http://jaeger.test.domain:1425",
		},
	}
}

func getTestCloudletNode(cloudletKey edgeproto.CloudletKey) (edgeproto.CloudletNode, string) {
	// test cloudletNode
	node := edgeproto.CloudletNode{}
	node.Key.Name = "mynode"
	node.Key.CloudletKey = cloudletKey
	node.NodeType = cloudcommon.NodeTypePlatformVM.String()
	node.NodeRole = cloudcommon.NodeRoleDockerCrm.String()
	password := string(util.RandAscii(12))
	hash, salt, iter := ormutil.NewPasshash(password)
	node.PasswordHash = hash
	node.Salt = salt
	node.Iter = int32(iter)
	return node, password
}

//go:embed test_node_attributes_exp.yml
var testNodeAttributesExp string

func TestNodeAttributesYaml(t *testing.T) {
	log.SetDebugLevel(log.DebugLevelApi)
	log.InitTracer(nil)
	defer log.FinishTracer()
	//addr := "127.0.0.1:12129"
	ctx := log.StartTestSpan(context.Background())

	nodeMgr := node.NodeMgr{}
	nodeMgr.DeploymentTag = "main"
	nodeMgr.InternalPki.UseVaultPki = true
	cloudletLookup := &node.CloudletCache{}
	cloudletLookup.Init()
	nodeMgr.CloudletLookup = cloudletLookup
	caches := CCRMCaches{}
	caches.Init(ctx, "ccrm", &nodeMgr, nil)
	handler := CCRMHandler{}
	handler.Init(ctx, "ccrm", &nodeMgr, &caches, nil, nil, &testFlags)

	cloudlet := getTestCloudlet()
	baseAttributes, err := handler.getCloudletPlatformAttributes(ctx, &cloudlet)
	require.Nil(t, err)

	node, _ := getTestCloudletNode(cloudlet.Key)
	handler.updateNodeAttributes(ctx, baseAttributes, &node)

	data, ok := handler.nodeAttributesCache.Get(node.Key)
	require.True(t, ok)
	if testNodeAttributesExp != string(data.yamlData) {
		fmt.Println(string(data.yamlData))
	}
	require.Equal(t, testNodeAttributesExp, string(data.yamlData))
	checksum := fmt.Sprintf("%x", md5.Sum([]byte(testNodeAttributesExp)))
	require.Equal(t, checksum, data.checksum)
}

func TestAnsibleServer(t *testing.T) {
	log.SetDebugLevel(log.DebugLevelApi)
	log.InitTracer(nil)
	defer log.FinishTracer()
	//addr := "127.0.0.1:12129"
	ctx := log.StartTestSpan(context.Background())

	badAuthDelay = time.Millisecond

	// set up CCRM
	ccrm := CCRM{
		flags: testFlags,
	}
	ccrm.nodeMgr.InternalPki.UseVaultPki = true
	ccrm.nodeMgr.DeploymentTag = "main"
	cloudletLookup := &node.CloudletCache{}
	cloudletLookup.Init()
	ccrm.nodeMgr.CloudletLookup = cloudletLookup

	ccrmType := "ccrm"
	ccrm.caches.Init(ctx, ccrmType, &ccrm.nodeMgr, nil)
	ccrm.handler.Init(ctx, ccrmType, &ccrm.nodeMgr, &ccrm.caches, nil, nil, &ccrm.flags)
	ccrm.echoServ = ccrm.initAnsibleServer(ctx)

	// test cloudlet
	cloudlet := getTestCloudlet()
	ccrm.caches.CloudletCache.Update(ctx, &cloudlet, 0)

	// test cloudletNode
	node, password := getTestCloudletNode(cloudlet.Key)
	ccrm.caches.CloudletNodeCache.Update(ctx, &node, 0)

	// helper data/funcs
	addr := "http://foo.domain/" + RouteNode
	setAuth := func(req *http.Request) {
		req.Header.Set(confignode.CloudletNameHeader, cloudlet.Key.Name)
		req.Header.Set(confignode.CloudletOrgHeader, cloudlet.Key.Organization)
		req.Header.Set("Authorization", ormutil.EncodeBasicAuth(node.Key.Name, password))
	}

	// get no auth
	req := httptest.NewRequest(http.MethodGet, addr+"/ansible.tar", nil)
	rec := httptest.NewRecorder()
	ccrm.echoServ.ServeHTTP(rec, req)
	require.Equal(t, http.StatusUnauthorized, rec.Result().StatusCode)

	// get but bad auth
	req = httptest.NewRequest(http.MethodGet, addr+"/ansible.tar", nil)
	rec = httptest.NewRecorder()
	setAuth(req)
	req.Header.Set("Authorization", ormutil.EncodeBasicAuth(node.Key.Name, "foo"))
	ccrm.echoServ.ServeHTTP(rec, req)
	require.Equal(t, http.StatusUnauthorized, rec.Result().StatusCode)

	// get but invalid node
	req = httptest.NewRequest(http.MethodGet, addr+"/ansible.tar", nil)
	rec = httptest.NewRecorder()
	setAuth(req)
	req.Header.Set("Authorization", ormutil.EncodeBasicAuth("foo", password))
	ccrm.echoServ.ServeHTTP(rec, req)
	require.Equal(t, http.StatusUnauthorized, rec.Result().StatusCode)

	// get invalid path
	req = httptest.NewRequest(http.MethodGet, addr+"/ansible.tar", nil)
	rec = httptest.NewRecorder()
	setAuth(req)
	ccrm.echoServ.ServeHTTP(rec, req)
	require.Equal(t, http.StatusNotFound, rec.Result().StatusCode)

	// get ansible.tar.gz.md5
	req = httptest.NewRequest(http.MethodGet, addr+"/ansible.tar.gz.md5", nil)
	rec = httptest.NewRecorder()
	setAuth(req)
	ccrm.echoServ.ServeHTTP(rec, req)
	require.Equal(t, http.StatusOK, rec.Result().StatusCode)
	require.Equal(t, "text/plain", rec.Result().Header.Get("Content-Type"))
	blob := []byte(fmt.Sprintf("%s  ansible.tar.gz\n", ansibleArchiveChecksum))
	blobOut, err := io.ReadAll(rec.Result().Body)
	rec.Result().Body.Close()
	require.Nil(t, err)
	require.Equal(t, string(blob), string(blobOut))

	// get vars.yaml.md5
	req = httptest.NewRequest(http.MethodGet, addr+"/vars.yaml.md5", nil)
	rec = httptest.NewRecorder()
	setAuth(req)
	ccrm.echoServ.ServeHTTP(rec, req)
	require.Equal(t, http.StatusOK, rec.Result().StatusCode)
	require.Equal(t, "text/plain", rec.Result().Header.Get("Content-Type"))
	data, ok := ccrm.handler.nodeAttributesCache.Get(node.Key)
	require.True(t, ok)
	blob = []byte(fmt.Sprintf("%s  vars.yaml\n", data.checksum))
	blobOut, err = io.ReadAll(rec.Result().Body)
	rec.Result().Body.Close()
	require.Nil(t, err)
	require.Equal(t, string(blob), string(blobOut))

	// get vars.yaml
	req = httptest.NewRequest(http.MethodGet, addr+"/vars.yaml", nil)
	rec = httptest.NewRecorder()
	setAuth(req)
	ccrm.echoServ.ServeHTTP(rec, req)
	require.Equal(t, http.StatusOK, rec.Result().StatusCode)
	require.Equal(t, "text/plain", rec.Result().Header.Get("Content-Type"))
	data, ok = ccrm.handler.nodeAttributesCache.Get(node.Key)
	require.True(t, ok)
	blob = data.yamlData
	blobOut, err = io.ReadAll(rec.Result().Body)
	rec.Result().Body.Close()
	require.Nil(t, err)
	require.Equal(t, string(blob), string(blobOut))

	// ========================================================
	// Test the whole process. This will run the configurenode
	// script, which makes calls to the web server and then runs
	// ansible. We'll define ansible to just echo instead.
	// We'll use a temp dir for downloading the files.
	tmpdir, err := os.MkdirTemp("", "ccrm-test-ansible-server-unit-test")
	require.Nil(t, err)
	defer os.RemoveAll(tmpdir)

	addr = "127.0.0.1:56811"
	go func() {
		err := ccrm.echoServ.Start(addr)
		if err != http.ErrServerClosed {
			require.Nil(t, err)
		}
	}()
	defer ccrm.echoServ.Close()

	configNode := confignode.ConfigureNodeVars{
		Key:               node.Key,
		Password:          password,
		AnsiblePublicAddr: "http://" + addr,
	}
	// Generate the confignode script
	err = configNode.GenScript()
	require.Nil(t, err)
	fmt.Println("Running script:")
	fmt.Println("=================================================")
	fmt.Println(configNode.ConfigureNodeScript)

	scriptName := tmpdir + "/" + "confignode.sh"
	err = os.WriteFile(scriptName, []byte(configNode.ConfigureNodeScript), 0777)
	require.Nil(t, err)

	// We're going to run the confignode script several times
	ansiblePlaybookBin := ""
	runCmd := func() string {
		cmd := exec.Command("bash", "-c", "./confignode.sh")
		cmd.Dir = tmpdir
		if ansiblePlaybookBin == "" {
			// don't actually run ansible-playbook command
			cmd.Env = append(cmd.Env, "ANSIBLE_PLAYBOOK_BIN=echo")
		} else {
			cmd.Env = append(cmd.Env, "ANSIBLE_PLAYBOOK_BIN="+ansiblePlaybookBin+" --check")
		}
		out, err := cmd.CombinedOutput()
		if err != nil {
			fmt.Println(string(out))
			fmt.Println(err.Error())
		}
		require.Nil(t, err)
		return string(out)
	}

	// Initial run will download all files and run them.
	out := runCmd()
	require.Contains(t, out, "No local ansible.tar.gz")
	require.Contains(t, out, "Downloading ansible.tar.gz")
	require.Contains(t, out, "No local vars.yaml")
	require.Contains(t, out, "Downloading vars.yaml")
	require.Contains(t, out, "Running update")

	// Run again will skip downloads, and skip run
	out = runCmd()
	require.Contains(t, out, "ansible.tar.gz md5 matches, skipping download")
	require.Contains(t, out, "vars.yaml md5 matches, skipping download")
	require.Contains(t, out, "No update needed")

	// Change the cloudletNode config, will cause the update to run.
	// Normally CCRM would be restarted to update the versionTag.
	ccrm.flags.VersionTag = "NewTag"
	ccrm.handler.cloudletChanged(ctx, nil, &cloudlet)
	out = runCmd()
	require.Contains(t, out, "ansible.tar.gz md5 matches, skipping download")
	require.Contains(t, out, "vars.yaml md5 mismatch, will download")
	require.Contains(t, out, "Downloading vars.yaml")
	require.Contains(t, out, "Running update")

	// Run again will skip downloads, and skip run
	out = runCmd()
	require.Contains(t, out, "ansible.tar.gz md5 matches, skipping download")
	require.Contains(t, out, "vars.yaml md5 matches, skipping download")
	require.Contains(t, out, "No update needed")
	require.FileExists(t, tmpdir+"/ansible_run_ok")

	// Change ansible checksum, should trigger update
	ansibleArchiveChecksum = "fooooo"
	// Also set ansible to fail to test rerun
	ansiblePlaybookBin = "falfa"
	out = runCmd()
	require.Contains(t, out, "ansible.tar.gz md5 mismatch, will download")
	require.Contains(t, out, "Downloading ansible.tar.gz")
	require.Contains(t, out, "vars.yaml md5 matches, skipping download")
	require.Contains(t, out, "Running update")
	require.NoFileExists(t, tmpdir+"/ansible_run_ok")

	// Check that ansible will run again because ansible command failed
	ansiblePlaybookBin = ""
	out = runCmd()
	require.Contains(t, out, "Ansible has not succeeded, will run")
	require.Contains(t, out, "Running update")
	require.FileExists(t, tmpdir+"/ansible_run_ok")

	// Finally, if ansible-playbook exists, we can test running
	// the playbooks in check mode. This checks that the tasks
	// and templates are formatted correctly and there are no
	// unresolved variable references.
	bin, err := exec.LookPath("ansible-playbook")
	if err == nil {
		bin, err = filepath.Abs(bin)
		require.Nil(t, err)
		ansiblePlaybookBin = bin

		// trigger update - docker crm role
		ccrm.flags.VersionTag = "NewTag2"
		ccrm.handler.cloudletChanged(ctx, nil, &cloudlet)

		out = runCmd()
		fmt.Println(out)
		require.Contains(t, out, "Running update")
		require.Contains(t, out, "NewTag2")
		require.Contains(t, out, "TASK [dockercrm")

		// switch to base role
		node.NodeRole = cloudcommon.NodeRoleBase.String()
		ccrm.caches.CloudletNodeCache.Update(ctx, &node, 0)

		out = runCmd()
		fmt.Println(out)
		require.Contains(t, out, "Running update")
		require.Contains(t, out, "node_role: base")
		require.Contains(t, out, "TASK [common")
	}
}
