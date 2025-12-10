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
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	dme "github.com/edgexr/edge-cloud-platform/api/distributed_match_engine"
	"github.com/edgexr/edge-cloud-platform/api/edgeproto"
	"github.com/edgexr/edge-cloud-platform/pkg/log"
	"github.com/edgexr/edge-cloud-platform/pkg/platform/pc"
	"github.com/stretchr/testify/require"
	v1 "k8s.io/api/core/v1"
	"k8s.io/cli-runtime/pkg/printers"
)

func TestGenerateIngressDuplicatePorts(t *testing.T) {
	// This tests that the application can use duplicate port 80
	// HTTP ports to target different services.
	log.SetDebugLevel(log.DebugLevelApi | log.DebugLevelInfra)
	log.InitTracer(nil)
	defer log.FinishTracer()
	ctx := log.StartTestSpan(context.Background())
	org1 := "devorg1"
	namespace := "ns1"
	appInstName := "inst1"

	testServices := []v1.Service{
		genTestService(TestServiceSpec{
			Name:        appInstName,
			Namespace:   namespace,
			Ports:       []v1.ServicePort{{Port: 80}, {Port: 443}},
			Type:        v1.ServiceTypeClusterIP,
			AppInstName: appInstName,
			AppInstOrg:  org1,
		}),
		genTestService(TestServiceSpec{
			Name:        "svc2",
			Namespace:   namespace,
			Ports:       []v1.ServicePort{{Port: 80}, {Port: 443}},
			Type:        v1.ServiceTypeClusterIP,
			AppInstName: appInstName,
			AppInstOrg:  org1,
		}),
	}
	testServicesList := v1.ServiceList{
		Items: testServices,
	}
	testServicesJSON, err := json.Marshal(testServicesList)
	require.Nil(t, err)

	appInst := &edgeproto.AppInst{
		Key: edgeproto.AppInstKey{
			Organization: org1,
			Name:         appInstName,
		},
		Namespace: namespace,
		MappedPorts: []edgeproto.InstPort{{
			Proto:        dme.LProto_L_PROTO_HTTP,
			InternalPort: 80,
			PublicPort:   80,
			Tls:          true,
			ServiceName:  "{{.Name}}",
		}, {
			Proto:        dme.LProto_L_PROTO_HTTP,
			InternalPort: 80,
			PublicPort:   80,
			Tls:          true,
			HostPrefix:   "alt-",
			ServiceName:  "svc2",
		}},
		Uri: "inst1.app.example.org",
	}

	names, err := GetKubeNames(&edgeproto.ClusterInst{}, &edgeproto.App{}, appInst)
	require.Nil(t, err)
	names.InstanceNamespace = namespace

	client := &pc.TestClient{
		OutputResponder: func(cmd string) (string, error) {
			if strings.Contains(cmd, "get svc") {
				return string(testServicesJSON), nil
			} else if strings.Contains(cmd, "get secret") {
				return "", nil
			} else {
				return "", errors.New("unknown test command: " + cmd)
			}
		},
	}

	ingress, err := GenerateIngressManifest(ctx, client, names, appInst, "nginx")
	require.Nil(t, err)
	printer := &printers.YAMLPrinter{}
	buf := bytes.Buffer{}
	err = printer.PrintObj(ingress, &buf)
	require.Nil(t, err)
	contents := buf.String()
	require.Equal(t, ingressExpectedYaml, contents)
}

var ingressExpectedYaml = `apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  labels:
    app.edgexr.org/appinst-name: inst1
    app.edgexr.org/appinst-org: devorg1
    nginx.ingress.kubernetes.io/ssl-redirect: "true"
  name: inst1
spec:
  ingressClassName: nginx
  rules:
  - host: alt-inst1.app.example.org
    http:
      paths:
      - backend:
          service:
            name: svc2
            port:
              number: 80
        path: /
        pathType: Prefix
  - host: inst1.app.example.org
    http:
      paths:
      - backend:
          service:
            name: inst1
            port:
              number: 80
        path: /
        pathType: Prefix
  tls:
  - hosts:
    - alt-inst1.app.example.org
    - inst1.app.example.org
status:
  loadBalancer: {}
`
