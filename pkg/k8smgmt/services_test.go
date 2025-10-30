// Copyright 2025 EdgeXR, Inc
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

package k8smgmt

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/edgexr/edge-cloud-platform/api/edgeproto"
	"github.com/edgexr/edge-cloud-platform/pkg/cloudcommon"
	"github.com/edgexr/edge-cloud-platform/pkg/log"
	"github.com/edgexr/edge-cloud-platform/pkg/platform/pc"
	"github.com/stretchr/testify/require"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

type TestServiceSpec struct {
	Name        string
	Namespace   string
	Ports       []v1.ServicePort
	Type        v1.ServiceType
	ClusterIP   string
	AppInstName string
	AppInstOrg  string
}

func genTestService(spec TestServiceSpec) v1.Service {
	svc := v1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name:      spec.Name,
			Namespace: spec.Namespace,
			Labels:    map[string]string{},
		},
		Spec: v1.ServiceSpec{
			Ports:     spec.Ports,
			Type:      spec.Type,
			ClusterIP: spec.ClusterIP,
		},
	}
	if spec.AppInstName != "" {
		svc.ObjectMeta.Labels[AppInstNameLabel] = spec.AppInstName
		svc.ObjectMeta.Labels[AppInstOrgLabel] = spec.AppInstOrg
	}
	return svc
}

type testServicesClient struct {
	services string
	pc.LocalClient
}

func (s *testServicesClient) Output(command string) (string, error) {
	return s.services, nil
}

func TestGetAppServices(t *testing.T) {
	log.SetDebugLevel(log.DebugLevelApi | log.DebugLevelInfra)
	log.InitTracer(nil)
	defer log.FinishTracer()
	ctx := log.StartTestSpan(context.Background())
	org1 := "devorg1"
	org2 := "devorg2"

	testServices := []v1.Service{
		genTestService(TestServiceSpec{ // app1/org1
			Name:        "app110-tcp",
			Namespace:   "inst1-devorg1",
			Ports:       []v1.ServicePort{{Port: 80}, {Port: 443}},
			Type:        v1.ServiceTypeLoadBalancer,
			ClusterIP:   "1.2.3.4",
			AppInstName: "inst1",
			AppInstOrg:  org1,
		}),
		genTestService(TestServiceSpec{ // app2/org1
			Name:        "app210-tcp",
			Namespace:   "inst2-devorg1",
			Ports:       []v1.ServicePort{{Port: 80}, {Port: 443}},
			Type:        v1.ServiceTypeLoadBalancer,
			ClusterIP:   "1.2.3.4",
			AppInstName: "inst2",
			AppInstOrg:  org1,
		}),
		genTestService(TestServiceSpec{ // app2/org1 UDP
			Name:        "app210-udp",
			Namespace:   "inst2-devorg1",
			Ports:       []v1.ServicePort{{Port: 80, Protocol: v1.ProtocolUDP}, {Port: 443, Protocol: v1.ProtocolUDP}},
			Type:        v1.ServiceTypeLoadBalancer,
			ClusterIP:   "1.2.3.4",
			AppInstName: "inst2",
			AppInstOrg:  org1,
		}),
		genTestService(TestServiceSpec{ // app1/org2 managed namespace
			Name:        "app110-tcp",
			Namespace:   "default",
			Ports:       []v1.ServicePort{{Port: 80}, {Port: 443}},
			Type:        v1.ServiceTypeLoadBalancer,
			ClusterIP:   "1.2.3.4",
			AppInstName: "inst1",
			AppInstOrg:  org2,
		}),
		genTestService(TestServiceSpec{ // app2/org2 managed namespace HTTP
			Name:        "app210-http",
			Namespace:   "default",
			Ports:       []v1.ServicePort{{Port: 80}, {Port: 443}},
			Type:        v1.ServiceTypeClusterIP,
			ClusterIP:   "1.2.3.4",
			AppInstName: "inst2",
			AppInstOrg:  org2,
		}),
		genTestService(TestServiceSpec{
			Name:      "myhelm",
			Namespace: "default",
			Ports:     []v1.ServicePort{{Port: 443}},
			Type:      v1.ServiceTypeClusterIP,
			ClusterIP: "1.2.3.4",
		}),
		// myredis/org1 isolated namespace
		genTestService(TestServiceSpec{
			Name:      "myredis-master",
			Namespace: "myredis-devorg1",
			Ports:     []v1.ServicePort{{Port: 6379}},
			Type:      v1.ServiceTypeClusterIP,
			ClusterIP: "1.2.3.4",
		}),
		genTestService(TestServiceSpec{
			Name:      "myredis-replicas",
			Namespace: "myredis-devorg1",
			Ports:     []v1.ServicePort{{Port: 6379}},
			Type:      v1.ServiceTypeClusterIP,
			ClusterIP: "1.2.3.4",
		}),
		genTestService(TestServiceSpec{
			Name:      "myredis-headless",
			Namespace: "myredis-devorg1",
			Ports:     []v1.ServicePort{{Port: 6379}},
			Type:      v1.ServiceTypeClusterIP,
			ClusterIP: "None",
		}),
		// redis with managed namespace (currently goes to default namespace)
		genTestService(TestServiceSpec{
			Name:      "myredis-master",
			Namespace: "default",
			Ports:     []v1.ServicePort{{Port: 6379}},
			Type:      v1.ServiceTypeClusterIP,
			ClusterIP: "1.2.3.4",
		}),
		genTestService(TestServiceSpec{
			Name:      "myredis-replicas",
			Namespace: "default",
			Ports:     []v1.ServicePort{{Port: 6379}},
			Type:      v1.ServiceTypeClusterIP,
			ClusterIP: "1.2.3.4",
		}),
		genTestService(TestServiceSpec{
			Name:      "myredis-headless",
			Namespace: "default",
			Ports:     []v1.ServicePort{{Port: 6379}},
			Type:      v1.ServiceTypeClusterIP,
			ClusterIP: "None",
		}),
		// system services
		genTestService(TestServiceSpec{
			Name:      "kube-dns",
			Namespace: "kube-system",
			Ports:     []v1.ServicePort{{Port: 53, Protocol: v1.ProtocolUDP}, {Port: 53, Protocol: v1.ProtocolTCP}},
			Type:      v1.ServiceTypeClusterIP,
			ClusterIP: "1.2.3.4",
		}),
		genTestService(TestServiceSpec{
			Name:      "random",
			Namespace: "default",
			Ports:     []v1.ServicePort{{Port: 80}, {Port: 443}},
			Type:      v1.ServiceTypeClusterIP,
			ClusterIP: "1.2.3.4",
		}),
		// operator multi service with isolated namespace
		genTestService(TestServiceSpec{
			Name:      "operator-postgres",
			Namespace: "op1-devorg1",
			Ports:     []v1.ServicePort{{Port: 5432}},
			Type:      v1.ServiceTypeClusterIP,
			ClusterIP: "1.2.3.4",
		}),
		genTestService(TestServiceSpec{
			Name:      "operator-redis",
			Namespace: "op1-devorg1",
			Ports:     []v1.ServicePort{{Port: 6379}},
			Type:      v1.ServiceTypeClusterIP,
			ClusterIP: "1.2.3.4",
		}),
		genTestService(TestServiceSpec{
			Name:      "operator-svc",
			Namespace: "op1-devorg1",
			Ports:     []v1.ServicePort{{Port: 443}},
			Type:      v1.ServiceTypeClusterIP,
			ClusterIP: "1.2.3.4",
		}),
		// operator multi service with managed namespace
		genTestService(TestServiceSpec{
			Name:      "operator-postgres",
			Namespace: "default",
			Ports:     []v1.ServicePort{{Port: 5432}},
			Type:      v1.ServiceTypeClusterIP,
			ClusterIP: "1.2.3.4",
		}),
		genTestService(TestServiceSpec{
			Name:      "operator-redis",
			Namespace: "default",
			Ports:     []v1.ServicePort{{Port: 6379}},
			Type:      v1.ServiceTypeClusterIP,
			ClusterIP: "1.2.3.4",
		}),
		genTestService(TestServiceSpec{
			Name:      "operator-svc",
			Namespace: "default",
			Ports:     []v1.ServicePort{{Port: 443}},
			Type:      v1.ServiceTypeClusterIP,
			ClusterIP: "1.2.3.4",
		}),
	}
	svcsList := v1.ServiceList{
		Items: testServices,
	}
	svcsJson, err := json.Marshal(svcsList)
	require.Nil(t, err)
	client := &testServicesClient{
		services: string(svcsJson),
	}
	tests := []struct {
		desc                    string
		appName                 string
		appOrg                  string
		appInstName             string
		accessPorts             string
		deployment              string
		imagePath               string
		managesOwnNamespace     bool // deploys to default NS if true
		expErr                  string
		expPortsWithoutServices []string
		expSvcs                 []string
	}{{
		desc:        "app1/org1 load balancer",
		appName:     "app1",
		appOrg:      org1,
		appInstName: "inst1",
		accessPorts: "tcp:80,tcp:443:tls",
		deployment:  cloudcommon.DeploymentTypeKubernetes,
		expSvcs:     []string{"app110-tcp/inst1-devorg1"},
	}, {
		desc:        "app2/org1 clusterIP",
		appName:     "app2",
		appOrg:      org1,
		appInstName: "inst2",
		accessPorts: "tcp:80,tcp:443:tls",
		deployment:  cloudcommon.DeploymentTypeKubernetes,
		expSvcs:     []string{"app210-tcp/inst2-devorg1"},
	}, {
		desc:                "app1/org2 load balancer managed namespace, conflicts",
		appName:             "app1",
		appOrg:              org2,
		appInstName:         "inst1",
		accessPorts:         "tcp:80,tcp:443:tls",
		deployment:          cloudcommon.DeploymentTypeKubernetes,
		managesOwnNamespace: true,
		expErr:              "failed to determine service for port, too many services found, please add svcname annotation to App.AccessPorts to resolve (i.e. \"tcp:5432:svcname={{.AppName}}{{.AppVers}}\"): port 443/tcp is served by services app110-tcp/default, myhelm/default, operator-svc/default, random/default; port 80/tcp is served by services app110-tcp/default, random/default",
	}, {
		desc:                "app1/org2 load balancer managed namespace, filtered",
		appName:             "app1",
		appOrg:              org2,
		appInstName:         "inst1",
		accessPorts:         "tcp:80:svcname={{.AppName}}{{.AppVers}},tcp:443:tls:svcname={{.AppName}}{{.AppVers}}",
		deployment:          cloudcommon.DeploymentTypeKubernetes,
		managesOwnNamespace: true,
		expSvcs:             []string{"app110-tcp/default"},
	}, {
		desc:                "app2/org2 clusterIP managed namespace, conflicts",
		appName:             "app2",
		appOrg:              org2,
		appInstName:         "inst2",
		accessPorts:         "http:80,http:443:tls",
		deployment:          cloudcommon.DeploymentTypeKubernetes,
		managesOwnNamespace: true,
		expErr:              "failed to determine service for port, too many services found, please add svcname annotation to App.AccessPorts to resolve (i.e. \"tcp:5432:svcname={{.AppName}}{{.AppVers}}\"): port 443/tcp is served by services app210-http/default, myhelm/default, operator-svc/default, random/default; port 80/tcp is served by services app210-http/default, random/default",
	}, {
		desc:                "app2/org2 clusterIP managed namespace, filtered",
		appName:             "app2",
		appInstName:         "inst2",
		appOrg:              org2,
		accessPorts:         "tcp:80:svcname={{.AppName}}{{.AppVers}},tcp:443:tls:svcname={{.AppName}}{{.AppVers}}",
		deployment:          cloudcommon.DeploymentTypeKubernetes,
		managesOwnNamespace: true,
		expSvcs:             []string{"app210-http/default"},
	}, {
		desc:                    "app2/org2 clusterIP managed namespace, filtered, missing port",
		appName:                 "app2",
		appInstName:             "inst2",
		appOrg:                  org2,
		accessPorts:             "tcp:80:svcname={{.AppName}}{{.AppVers}},tcp:443:tls:svcname={{.AppName}}{{.AppVers}},tcp:8888:svcname={{.AppName}}{{.AppVers}}",
		deployment:              cloudcommon.DeploymentTypeKubernetes,
		managesOwnNamespace:     true,
		expPortsWithoutServices: []string{"8888/tcp"},
		expSvcs:                 []string{"app210-http/default"},
	}, {
		desc:        "helm inst with conflicts",
		appName:     "redis",
		appOrg:      org1,
		appInstName: "myredis",
		accessPorts: "http:6379:tls",
		deployment:  cloudcommon.DeploymentTypeHelm,
		imagePath:   "http://bitnami.charts:8000/redis:bitnami/redis",
		expErr:      "failed to determine service for port, too many services found, please add svcname annotation to App.AccessPorts to resolve (i.e. \"tcp:5432:svcname={{.AppName}}{{.AppVers}}\"): port 6379/tcp is served by services myredis-master/myredis-devorg1, myredis-replicas/myredis-devorg1",
	}, {
		desc:        "helm inst with svcname",
		appName:     "redis",
		appOrg:      org1,
		appInstName: "myredis",
		accessPorts: "http:6379:tls:svcname=master",
		deployment:  cloudcommon.DeploymentTypeHelm,
		imagePath:   "http://bitnami.charts:8000/redis:bitnami/redis",
		expSvcs:     []string{"myredis-master/myredis-devorg1"},
	}, {
		desc:                "helm inst managed namespace with conflicts",
		appName:             "redis",
		appOrg:              org1,
		appInstName:         "myredis",
		accessPorts:         "http:6379:tls",
		deployment:          cloudcommon.DeploymentTypeHelm,
		imagePath:           "http://bitnami.charts:8000/redis:bitnami/redis",
		managesOwnNamespace: true,
		expErr:              "failed to determine service for port, too many services found, please add svcname annotation to App.AccessPorts to resolve (i.e. \"tcp:5432:svcname={{.AppName}}{{.AppVers}}\"): port 6379/tcp is served by services myredis-master/default, myredis-replicas/default",
	}, {
		desc:                "helm inst managed namespace with filter",
		appName:             "redis",
		appOrg:              org1,
		appInstName:         "myredis",
		accessPorts:         "http:6379:tls:svcname=master",
		deployment:          cloudcommon.DeploymentTypeHelm,
		imagePath:           "http://bitnami.charts:8000/redis:bitnami/redis",
		managesOwnNamespace: true,
		expSvcs:             []string{"myredis-master/default"},
	}, {
		desc:        "operator multi-service",
		appName:     "operator",
		appOrg:      org1,
		appInstName: "op1",
		accessPorts: "http:443:tls,http:5432,http:6379",
		deployment:  cloudcommon.DeploymentTypeHelm,
		imagePath:   "http://bitnami.charts:8000/redis:bitnami/redis",
		expSvcs:     []string{"operator-postgres/op1-devorg1", "operator-redis/op1-devorg1", "operator-svc/op1-devorg1"},
	}, {
		desc:                "operator multi-service managed namespace, conflict",
		appName:             "operator",
		appOrg:              org1,
		appInstName:         "op1",
		accessPorts:         "http:443:tls,http:5432,http:6379",
		deployment:          cloudcommon.DeploymentTypeHelm,
		imagePath:           "http://bitnami.charts:8000/redis:bitnami/redis",
		managesOwnNamespace: true,
		expErr:              "failed to determine service for port, too many services found, please add svcname annotation to App.AccessPorts to resolve (i.e. \"tcp:5432:svcname={{.AppName}}{{.AppVers}}\"): port 443/tcp is served by services myhelm/default, operator-svc/default, random/default; port 6379/tcp is served by services myredis-master/default, myredis-replicas/default, operator-redis/default",
	}, {
		desc:                "operator multi-service managed namespace, filtered",
		appName:             "operator",
		appOrg:              org1,
		appInstName:         "op1",
		accessPorts:         "http:443:tls:svcname=operator,http:5432:svcname=operator,http:6379:svcname=operator",
		deployment:          cloudcommon.DeploymentTypeHelm,
		imagePath:           "http://bitnami.charts:8000/redis:bitnami/redis",
		managesOwnNamespace: true,
		expSvcs:             []string{"operator-postgres/default", "operator-redis/default", "operator-svc/default"},
	}}
	for _, test := range tests {
		app := &edgeproto.App{
			Key: edgeproto.AppKey{
				Organization: test.appOrg,
				Name:         test.appName,
				Version:      "1.0",
			},
			Deployment:           test.deployment,
			AccessPorts:          test.accessPorts,
			ManagesOwnNamespaces: test.managesOwnNamespace,
		}
		appmf, err := cloudcommon.GetAppDeploymentManifest(ctx, nil, app)
		require.Nil(t, err, test.desc)
		app.DeploymentManifest = appmf
		app.CompatibilityVersion = cloudcommon.GetAppCompatibilityVersion()

		ai := &edgeproto.AppInst{
			Key: edgeproto.AppInstKey{
				Name:         test.appInstName,
				Organization: test.appOrg,
			},
			AppKey: app.Key,
		}
		ports, err := edgeproto.ParseAppPorts(app.AccessPorts)
		require.Nil(t, err, test.desc)
		err = edgeproto.ResolveAppPortsTemplates(ports, &app.Key)
		require.Nil(t, err, test.desc)
		ai.MappedPorts = ports
		ai.CompatibilityVersion = cloudcommon.GetAppInstCompatibilityVersion()

		names, err := GetKubeNames(&edgeproto.ClusterInst{}, app, ai)
		require.Nil(t, err, test.desc)
		log.SpanLog(ctx, log.DebugLevelApi, "names", "names", names)

		appServices, err := GetAppServices(ctx, client, names, ports)
		if test.expErr != "" {
			require.NotNil(t, err, test.desc)
			require.Contains(t, err.Error(), test.expErr, test.desc)
			continue
		}
		require.Nil(t, err, test.desc)
		if len(test.expPortsWithoutServices) == 0 {
			test.expPortsWithoutServices = []string{}
		}
		require.Equal(t, test.expPortsWithoutServices, appServices.PortsWithoutServices, test.desc)
		svcNames := []string{}
		for _, svc := range appServices.Services {
			svcNames = append(svcNames, svc.Name+"/"+svc.Namespace)
		}
		require.Equal(t, test.expSvcs, svcNames, test.desc)
	}
}
