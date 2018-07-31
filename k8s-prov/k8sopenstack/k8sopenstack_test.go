package k8sopenstack

import (
	"os"
	"testing"

	mexosagent "github.com/mobiledgex/edge-cloud-infra/openstack-tenant/agent/api"
	log "github.com/sirupsen/logrus"
)

var mexTestInfra = os.Getenv("MEX_TEST_INFRA")

func TestInit(t *testing.T) {
	if mexTestInfra == "" {
		return
	}
	log.SetLevel(log.DebugLevel)
}

func TestInitOSEnv(t *testing.T) {
	if mexTestInfra == "" {
		return
	}
	if err := initOSEnv(); err != nil {
		t.Errorf("initOSEnv error, %v", err)
	}
}

func TestInitConfig(t *testing.T) {
	if mexTestInfra == "" {
		return
	}
	if err := initConfig(); err != nil {
		t.Errorf("initConfig error, %v", err)
	}

	log.Println("config", Config)
}

func TestReadUserData(t *testing.T) {
	if mexTestInfra == "" {
		return
	}
	dat, err := readUserData()
	if err != nil {
		t.Errorf("readUserData error, %v", err)
	}
	log.Debugln("userdata", string(dat))
}

func TestCreateKubernetesCluster(t *testing.T) {
	if mexTestInfra == "" {
		return
	}
	req := mexosagent.Provision{
		Name:   "test-1",
		Tenant: "tenant-1",
		Kind:   "kubernetes-mini-openstack",
	}
	if err := CreateKubernetesCluster(&req); err != nil {
		t.Errorf("cannot create kubernetes cluster, %v", err)
	}
}

func TestDeleteKubernetesCluster(t *testing.T) {
	if mexTestInfra == "" {
		return
	}
	req := mexosagent.Provision{
		Name:   "test-1",
		Tenant: "tenant-1",
		Kind:   "kubernetes-mini-openstack",
	}
	if err := DeleteKubernetesCluster(&req); err != nil {
		t.Errorf("cannot delete kubernetes cluster, %v", err)
	}
}
