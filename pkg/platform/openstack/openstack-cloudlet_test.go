// Copyright 2024 EdgeXR, Inc
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package openstack

import (
	"context"
	"fmt"
	"os"
	"testing"
	"time"

	distributed_match_engine "github.com/edgexr/edge-cloud-platform/api/distributed_match_engine"
	"github.com/edgexr/edge-cloud-platform/api/edgeproto"
	"github.com/edgexr/edge-cloud-platform/pkg/accessapi"
	"github.com/edgexr/edge-cloud-platform/pkg/cloudcommon"
	"github.com/edgexr/edge-cloud-platform/pkg/cloudcommon/node"
	"github.com/edgexr/edge-cloud-platform/pkg/log"
	"github.com/edgexr/edge-cloud-platform/pkg/platform"
	"github.com/edgexr/edge-cloud-platform/pkg/redundancy"
	yaml "github.com/mobiledgex/yaml/v2"
	"github.com/stretchr/testify/require"
)

// This tests against a real Openstack setup.
// Your shell must have env vars for:
// Openstack credentials (openrc.json)
// Infra-specific env vars (specified during CreateCloudlet)
// This is for manual testing without having to deploy a CRM,
// and is not for unit testing. This requires that the Openstack API
// endpoint is reachable from the test machine.
func TestOpenstackLive(t *testing.T) {
	t.Skip("for debugging")

	cloudletVMImagePath := os.Getenv("CLOUDLET_VM_IMAGE_PATH")
	registryAuthUsername := os.Getenv("REGISTRY_AUTH_USERNAME")
	registryAuthPassword := os.Getenv("REGISTRY_AUTH_PASSWORD")
	flavor := "m4.small"
	//vmimage := "https://cloud-images.ubuntu.com/minimal/releases/mantic/release/ubuntu-23.10-minimal-cloudimg-amd64.img#md5:646d9f302af541a123a6a577da56ad1c"
	vmimage := "https://cloud-images.ubuntu.com/minimal/releases/jammy/release/ubuntu-22.04-minimal-cloudimg-amd64.img#md5:df6be431f5fb2e02408de08ecd7cc75d"
	TESTER_USERNAME := os.Getenv("USER")
	// hash generated via: echo changeme | mkpasswd --method=SHA-512 --rounds=4096 -s
	TESTER_PASSWORD_HASH := "$6$rounds=4096$VoKuflEpc3o3md0$4l9BgAHNxAkKbOugOu.G0PKxJB6KxLNOA1tmGjnZmdmrMEbOGk0Q7ws28ucFdrLBZKft2UazlrZ453.EHl1ag/"
	// if openstack v6 subnet is set to use dhcp, ignore it.
	//os.Setenv("MEX_SUBNETS_IGNORE_DHCP", "externalIPv6-subnet")

	log.SetDebugLevel(log.DebugLevelInfra)

	log.InitTracer(nil)
	defer log.FinishTracer()
	ctx := log.StartTestSpan(context.Background())

	cloudlet := &edgeproto.Cloudlet{
		Key: edgeproto.CloudletKey{
			Name:         "functest",
			Organization: "edgexr",
		},
		Deployment: cloudcommon.DeploymentTypeDocker,
	}

	nodeMgr := &node.NodeMgr{}
	nodeMgr.Debug.Init(nodeMgr)
	cloudletPoolLookup := &node.CloudletPoolCache{}
	cloudletPoolLookup.Init()
	nodeMgr.CloudletPoolLookup = cloudletPoolLookup
	nodeMgr.MyNode.Key.CloudletKey = cloudlet.Key
	accessAPI := &accessapi.TestHandler{
		AccessVars: map[string]string{
			OS_PROJECT_NAME: os.Getenv(OS_PROJECT_NAME),
		},
		RegistryAuth: cloudcommon.RegistryAuth{
			AuthType: cloudcommon.BasicAuth,
			Username: registryAuthUsername,
			Password: registryAuthPassword,
		},
	}

	caches := platform.BuildCaches()
	caches.CloudletCache.Update(ctx, cloudlet, 0)
	haMgr := &redundancy.HighAvailabilityManager{}

	pfConfig := &platform.PlatformConfig{
		CloudletKey:         &cloudlet.Key,
		CacheDir:            "/var/tmp", // must exist locally
		TestMode:            false,
		NodeMgr:             nodeMgr,
		AccessApi:           accessAPI,
		CloudletVMImagePath: cloudletVMImagePath,
		DeploymentTag:       "main",
		AppDNSRoot:          "app.functest.ut",
		RootLBFQDN:          "shared.functest.ut",
	}

	plat := NewPlatform()
	cb := func(updateType edgeproto.CacheUpdateType, value string) {
		fmt.Println(value)
	}
	err := plat.InitCommon(ctx, pfConfig, caches, haMgr, cb)
	require.Nil(t, err)

	err = plat.InitHAConditional(ctx, pfConfig, cb)
	require.Nil(t, err)

	if false {
		// test GetCloudletResources
		res, err := plat.GetCloudletInfraResources(ctx)
		require.Nil(t, err)
		out, err := yaml.Marshal(res)
		require.Nil(t, err)
		fmt.Println(string(out))
	}

	devOrg := os.Getenv("USER")

	dockerApp := &edgeproto.App{
		Key: edgeproto.AppKey{
			Name:         "hello",
			Organization: devOrg,
			Version:      "1",
		},
		Deployment:    cloudcommon.DeploymentTypeDocker,
		ImagePath:     "docker.io/hashicorp/http-echo:0.2.3",
		AccessPorts:   "tcp:5678",
		Command:       "-text=hello-func-test",
		DefaultFlavor: edgeproto.FlavorKey{Name: flavor},
	}
	dockerAppInst := &edgeproto.AppInst{
		Key: edgeproto.AppInstKey{
			Name:         "hello",
			Organization: devOrg,
			CloudletKey:  cloudlet.Key,
		},
		AppKey: dockerApp.Key,
		MappedPorts: []distributed_match_engine.AppPort{{
			Proto:        distributed_match_engine.LProto_L_PROTO_TCP,
			InternalPort: 5678,
			PublicPort:   5678,
			Tls:          true,
		}},
		Uri:                  os.Getenv("USER") + "-functest-dockerapp-uri",
		UniqueId:             os.Getenv("USER") + "-functest-dockerapp-unique-id",
		VmFlavor:             flavor,
		EnableIpv6:           false,
		CompatibilityVersion: cloudcommon.GetAppInstCompatibilityVersion(),
	}

	if false {
		dockerClusterInst := &edgeproto.ClusterInst{
			Key: edgeproto.ClusterInstKey{
				ClusterKey: edgeproto.ClusterKey{
					Name:         "dockerclust",
					Organization: devOrg,
				},
				CloudletKey: cloudlet.Key,
			},
			Deployment: cloudcommon.DeploymentTypeDocker,
			NodeFlavor: flavor,
			IpAccess:   edgeproto.IpAccess_IP_ACCESS_SHARED,
			EnableIpv6: false,
		}
		//err = plat.CreateClusterInst(ctx, dockerClusterInst, cb, 6*time.Minute)
		//err = plat.UpdateClusterInst(ctx, dockerClusterInst, cb)
		err = plat.DeleteClusterInst(ctx, dockerClusterInst, cb)
		if err != nil {
			fmt.Println(err.Error())
		}
		require.Nil(t, err)

		_ = dockerAppInst
		//err = plat.DeleteAppInst(ctx, dockerClusterInst, dockerApp, dockerAppInst, cb)
		//err = plat.UpdateAppInst(ctx, dockerClusterInst, dockerApp, dockerAppInst, &edgeproto.Flavor{}, cb)
		//err = plat.CreateAppInst(ctx, dockerClusterInst, dockerApp, dockerAppInst, &edgeproto.Flavor{}, cb)
		if err != nil {
			fmt.Println(err.Error())
		}
		require.Nil(t, err)
	}
	if false {
		k8sClusterInst := &edgeproto.ClusterInst{
			Key: edgeproto.ClusterInstKey{
				ClusterKey: edgeproto.ClusterKey{
					Name:         "k8sclust",
					Organization: devOrg,
				},
				CloudletKey: cloudlet.Key,
			},
			Deployment: cloudcommon.DeploymentTypeKubernetes,
			NodeFlavor: flavor,
			IpAccess:   edgeproto.IpAccess_IP_ACCESS_SHARED,
			EnableIpv6: false, // TODO: needs new base image
			NumMasters: 1,
			NumNodes:   1,
		}
		//err = plat.CreateClusterInst(ctx, k8sClusterInst, cb, 30*time.Minute)
		err = plat.DeleteClusterInst(ctx, k8sClusterInst, cb)
		//err = plat.UpdateClusterInst(ctx, k8sClusterInst, cb)
		if err != nil {
			fmt.Println(err.Error())
		}
		require.Nil(t, err)

		if false {
			// check getting resources for cluster (IPs, etc).
			res2, err := plat.GetClusterInfraResources(ctx, &k8sClusterInst.Key)
			require.Nil(t, err)
			out, err := yaml.Marshal(res2)
			require.Nil(t, err)
			fmt.Println(string(out))
			return
		}
	}
	if false {
		dockerClusterInstD := &edgeproto.ClusterInst{
			Key: edgeproto.ClusterInstKey{
				ClusterKey: edgeproto.ClusterKey{
					Name:         "dockerclustD",
					Organization: devOrg,
				},
				CloudletKey: cloudlet.Key,
			},
			Deployment:  cloudcommon.DeploymentTypeDocker,
			NodeFlavor:  flavor,
			IpAccess:    edgeproto.IpAccess_IP_ACCESS_DEDICATED,
			Fqdn:        "dockerclustDLB",
			StartupFqdn: "dockerclustDLB", // becomes rootLB name
			EnableIpv6:  false,
		}
		err = plat.CreateClusterInst(ctx, dockerClusterInstD, cb, 6*time.Minute)
		//err = plat.DeleteClusterInst(ctx, dockerClusterInstD, cb)
		//err = plat.UpdateClusterInst(ctx, dockerClusterInstD, cb)
		if err != nil {
			fmt.Println(err.Error())
		}
		require.Nil(t, err)
	}
	if false {
		vmApp := edgeproto.App{
			Key: edgeproto.AppKey{
				Organization: devOrg,
				Name:         "vmapp",
				Version:      "1",
			},
			AccessPorts: "tcp:5677:tls,tcp:5678:tls",
			Deployment:  cloudcommon.DeploymentTypeVM,
			ImagePath:   vmimage,
			ImageType:   edgeproto.ImageType_IMAGE_TYPE_QCOW,
			VmAppOsType: edgeproto.VmAppOsType_VM_APP_OS_LINUX,
			DeploymentManifest: `#cloud-config
groups:
- docker
users:
- default
- name: ` + TESTER_USERNAME + `
  passwd: ` + TESTER_PASSWORD_HASH + `
  lock-passwd: false
  shell: /bin/bash
  sudo: ALL=(ALL) ALL
  groups: users, admin, docker
password: changeme
ssh_pwauth: True
chpasswd: {expire: False}
package_update: true
packages:
- docker.io
- nano
runcmd:
- sed -i.bak -e 's/^[#]Port .*$/Port 5677/' /etc/ssh/sshd_config
- ssh-keygen -A
- mkdir -p /run/sshd
- systemctl restart sshd.service
- docker run --restart=unless-stopped --detach=true -p 5678:5678 hashicorp/http-echo:0.2.3 -text="hello functest"
`,
		}
		appInst := edgeproto.AppInst{
			Key: edgeproto.AppInstKey{
				Name:         "vmapp",
				Organization: devOrg,
				CloudletKey:  cloudlet.Key,
			},
			AppKey:   vmApp.Key,
			Uri:      os.Getenv("USER") + "-functest-vmappinst-uri",       // security group name
			UniqueId: os.Getenv("USER") + "-functest-vmappinst-unique-id", // used for heat stack name
			VmFlavor: flavor,
			MappedPorts: []distributed_match_engine.AppPort{{
				Proto:        distributed_match_engine.LProto_L_PROTO_TCP,
				InternalPort: 5677,
				PublicPort:   5677,
			}, {
				Proto:        distributed_match_engine.LProto_L_PROTO_TCP,
				InternalPort: 5678,
				PublicPort:   5678,
			}},
			CompatibilityVersion: cloudcommon.GetAppInstCompatibilityVersion(),
			EnableIpv6:           true,
		}
		vmClusterInst := edgeproto.ClusterInst{}
		//err = plat.DeleteAppInst(ctx, &vmClusterInst, &vmApp, &appInst, cb)
		err = plat.CreateAppInst(ctx, &vmClusterInst, &vmApp, &appInst, &edgeproto.Flavor{}, cb)
		//err = plat.UpdateAppInst(ctx, &vmClusterInst, &vmApp, &appInst, &edgeproto.Flavor{}, cb)
		if err != nil {
			fmt.Println(err.Error())
		}
		require.Nil(t, err)
	}
}
