package oscli

import (
	"fmt"
	"github.com/rs/xid"
	"os"
	"strings"
	"testing"
)

var mexTestInfra1 = os.Getenv("MEX_TEST_INFRA")

var tenant = "test-tenant"

var roleAgent = "mex-agent-node" //installs docker
var agentName = ""

func TestCreateMEXAgent(t *testing.T) {
	if mexTestInfra1 == "" {
		return
	}
	guid := xid.New()
	agentName = "mex-agent-test-" + guid.String()

	// XXX 10.101.X.X/24 is not used. Just place-holder for now.
	// id 1 is not used either. DHCP is used.
	err := CreateMEXKVM(agentName, roleAgent, "external-ip,external-network-shared,10.101.X.X/24,dhcp", roleAgent, tenant, 1)
	//XXX use roleAgent as tags, for now

	if err != nil {
		t.Errorf("can't create kvm, %v", err)
		return
	}
	fmt.Println("created kvm")
}

func TestDestroyMEXAgent(t *testing.T) {
	if mexTestInfra1 == "" {
		return
	}
	if agentName == "" {
		sl, err := ListServers()
		if err != nil {
			t.Error(err)
			return
		}
		for _, s := range sl {
			if strings.HasPrefix(s.Name, "mex-agent-test-") {
				agentName = s.Name
			}
		}
	}

	err := DestroyMEXKVM(agentName, roleAgent)
	if err != nil {
		t.Error(err)
		return
	}
}

var roleMaster = "k8s-master" //installs k8s master
var masterName = ""

var test1Tags = "test-1"

func TestCreateKubernetesMaster(t *testing.T) {
	if mexTestInfra1 == "" {
		return
	}
	guid := xid.New()
	masterName := "mex-" + roleMaster + "-" + guid.String()
	//Master always has X.X.X.2
	err := CreateMEXKVM(masterName, roleMaster, "priv-subnet,mex-k8s-net1,10.101.X.0/24", test1Tags, tenant, 1)
	if err != nil {
		t.Errorf("can't create kubernetes master node, %v", err)
		return
	}
	fmt.Println("created k8s-master")
}

var roleNode1 = "k8s-node" //installs kubectl
var node1Name = ""

func TestCreateKubernetesNode1(t *testing.T) {
	if mexTestInfra1 == "" {
		return
	}
	guid := xid.New()
	node1Name := "mex-" + roleNode1 + "-" + guid.String()
	err := CreateMEXKVM(node1Name, roleNode1, "priv-subnet,mex-k8s-net-1,10.101.X.0/24", test1Tags, tenant, 1)
	if err != nil {
		t.Errorf("can't create kubernetes node 1, %v", err)
	}
	fmt.Println("created k8s-node 1")
}

var roleNode2 = "k8s-node"
var node2Name = ""

func TestCreateKubernetesNode2(t *testing.T) {
	if mexTestInfra1 == "" {
		return
	}
	guid := xid.New()
	node2Name := "mex-" + roleNode2 + "-" + guid.String()
	err := CreateMEXKVM(node2Name, roleNode2, "priv-subnet,mex-k8s-net-1,10.101.X.0/24", test1Tags, tenant, 2)
	if err != nil {
		t.Errorf("can't create kubernetes node 2, %v", err)
	}
	fmt.Println("created k8s-node 2")
}

func TestDeleteAgent(t *testing.T) {
	if mexTestInfra1 == "" {
		return
	}
	err := DeleteServer(agentName)
	if err != nil {
		t.Errorf("can't delete agent kvm")
		return
	}

	fmt.Println("delete", agentName)
}

func TestDeleteAgentByRole(t *testing.T) {
	if mexTestInfra1 == "" {
		return
	}
	sl, err := ListServers()
	if err != nil {
		t.Errorf("can't get list of servers, %v", err)
		return
	}
	for _, s := range sl {
		if strings.HasPrefix(s.Name, "mex-") {
			sd, err := GetServerDetails(s.Name)
			if err != nil {
				t.Errorf("can't get server detail for %s, %v", s.Name, err)
				return
			}
			prop := sd.Properties
			props := strings.Split(prop, ",")
			for _, p := range props {
				kv := strings.Split(p, "=")
				if strings.Index(kv[0], "role") >= 0 { // extra space in front
					if strings.Index(kv[1], roleAgent) >= 0 { // single quotes
						err := DeleteServer(s.Name)
						if err != nil {
							t.Errorf("can't delete %s, %v", s.Name, err)
							return
						}
						fmt.Println("delete", s.Name)
					}
				}
			}
		}
	}
}

//because of ephemeral node names these cannot be run individually

//delete all nodes before master
func TestDestroyKubernetesNode1(t *testing.T) {
	if mexTestInfra1 == "" {
		return
	}
	err := DestroyMEXKVM(node1Name, roleNode1)
	if err != nil {
		t.Errorf("can't destroy %s, %v", node1Name, err)
		return
	}
}

func TestDestroyKubernetesNode2(t *testing.T) {
	if mexTestInfra1 == "" {
		return
	}
	err := DestroyMEXKVM(node2Name, roleNode2)
	if err != nil {
		t.Errorf("can't destroy %s, %v", node2Name, err)
		return
	}
}

func TestDestroyKubernetesMaster(t *testing.T) {
	if mexTestInfra1 == "" {
		return
	}
	err := DestroyMEXKVM(masterName, roleMaster)
	if err != nil {
		t.Errorf("can't destroy %s, %v", masterName, err)
		return
	}
}

func TestDestroyKubernetesByTags(t *testing.T) {
	if mexTestInfra1 == "" {
		return
	}
	sl, err := ListServers()
	if err != nil {
		t.Errorf("can't get list of servers, %v", err)
		return
	}
	//really should delete k8s-nodes first and then k8s-master. but since k8s-master
	// are created first this sort of works.
	// maybe fix later TODO
	for _, s := range sl {
		if strings.HasPrefix(s.Name, "mex-k8s-") {
			sd, err := GetServerDetails(s.Name)
			if err != nil {
				t.Errorf("can't get server detail for %s, %v", s.Name, err)
				return
			}
			prop := sd.Properties
			props := strings.Split(prop, ",")
			for _, p := range props {
				kv := strings.Split(p, "=")
				if strings.Index(kv[0], "tags") >= 0 { // extra space in front
					if strings.Index(kv[1], test1Tags) >= 0 { // single quotes
						err := DeleteServer(s.Name)
						if err != nil {
							t.Errorf("can't delete %s, %v", s.Name, err)
							return
						}
						fmt.Println("delete", s.Name)
					}
				}
			}
		}
	}
}

func TestDestroyKubernetesByTenant(t *testing.T) {
	if mexTestInfra1 == "" {
		return
	}
	sl, err := ListServers()
	if err != nil {
		t.Errorf("can't get list of servers, %v", err)
		return
	}
	//really should delete k8s-nodes first and then k8s-master. but since k8s-master
	// are created first this sort of works.
	// maybe fix later TODO
	for _, s := range sl {
		if strings.HasPrefix(s.Name, "mex-k8s-") {
			sd, err := GetServerDetails(s.Name)
			if err != nil {
				t.Errorf("can't get server detail for %s, %v", s.Name, err)
				return
			}
			prop := sd.Properties
			props := strings.Split(prop, ",")
			for _, p := range props {
				kv := strings.Split(p, "=")
				if strings.Index(kv[0], "tenant") >= 0 { // extra space in front
					if strings.Index(kv[1], tenant) >= 0 { // single quotes
						err := DeleteServer(s.Name)
						if err != nil {
							t.Errorf("can't delete %s, %v", s.Name, err)
							return
						}
						fmt.Println("delete", s.Name)
					}
				}
			}
		}
	}
}
