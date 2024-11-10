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

// Package nbitest provides data for running NBI unit tests
package nbitest

import (
	"github.com/edgexr/edge-cloud-platform/api/edgeproto"
	"github.com/edgexr/edge-cloud-platform/api/nbi"
	"github.com/edgexr/edge-cloud-platform/pkg/cloudcommon"
)

type AppDataSet struct {
	NBI          *nbi.AppManifest
	Edgeproto    *edgeproto.App
	InstTemplate *nbi.AppInstanceInfo
}

func AppData() []*AppDataSet {
	return []*AppDataSet{{
		NBI: &nbi.AppManifest{ // 0
			Name:        "k8sapp0",
			AppProvider: "devorg1",
			Version:     "1.0.0",
			PackageType: nbi.CONTAINER,
			AppRepo: nbi.AppManifest_AppRepo{
				ImagePath: "ghcr.io/edgexr/http-echo:1.0.0",
				Type:      nbi.PUBLICREPO,
			},
			ComponentSpec: []nbi.AppManifest_ComponentSpec{{
				ComponentName: "comp0",
				NetworkInterfaces: []nbi.AppManifest_ComponentSpec_NetworkInterfaces{{
					InterfaceId:    "port443",
					Port:           443,
					Protocol:       nbi.TCP,
					VisibilityType: nbi.VISIBILITYEXTERNAL,
				}, {
					InterfaceId:    "port7777",
					Port:           7777,
					Protocol:       nbi.UDP,
					VisibilityType: nbi.VISIBILITYEXTERNAL,
				}, {
					InterfaceId:    "port9900",
					Port:           9900,
					Protocol:       nbi.TCP,
					VisibilityType: nbi.VISIBILITYINTERNAL,
				}},
			}},
			RequiredResources: krRR(nbi.KubernetesResources{
				ApplicationResources: nbi.KubernetesResources_ApplicationResources{
					CpuPool: &nbi.KubernetesResources_ApplicationResources_CpuPool{
						NumCPU: 1,
						Memory: 1024,
						Topology: nbi.KubernetesResources_ApplicationResources_CpuPool_Topology{
							MinNodeCpu:       1,
							MinNodeMemory:    1024,
							MinNumberOfNodes: 1,
						},
					},
				},
				IsStandalone: false,
			}),
		},
		Edgeproto: &edgeproto.App{ // 0
			Key: edgeproto.AppKey{
				Name:         "k8sapp0",
				Organization: "devorg1",
				Version:      "1.0.0",
			},
			ImageType:   edgeproto.ImageType_IMAGE_TYPE_DOCKER,
			ImagePath:   "ghcr.io/edgexr/http-echo:1.0.0",
			Deployment:  cloudcommon.DeploymentTypeKubernetes,
			AccessPorts: "tcp:443:tls:id=port443,udp:7777:id=port7777,tcp:9900:tls:intvis:id=port9900",
			KubernetesResources: &edgeproto.KubernetesResources{
				CpuPool: &edgeproto.NodePoolResources{
					TotalVcpus:  *edgeproto.NewUdec64(1, 0),
					TotalMemory: 1024,
					Topology: edgeproto.NodePoolTopology{
						MinNodeVcpus:     1,
						MinNodeMemory:    1024,
						MinNumberOfNodes: 1,
					},
				},
			},
			AllowServerless: true,
			AppAnnotations: map[string]string{
				"NBIAppComponentName": "comp0",
				"NBIAppRepoType":      "NBIAppRepoTypePublic",
			},
		},
		InstTemplate: &nbi.AppInstanceInfo{
			AppProvider: "devorg1",
			ComponentEndpointInfo: &[]nbi.AppInstanceInfo_ComponentEndpointInfo{{
				AccessPoints: nbi.AccessEndpoint{
					Port: 443,
				},
				InterfaceId: "port443",
			}, {
				AccessPoints: nbi.AccessEndpoint{
					Port: 7777,
				},
				InterfaceId: "port7777",
			}, {
				AccessPoints: nbi.AccessEndpoint{
					Port: 9900,
				},
				InterfaceId: "port9900",
			}},
			Status: toPtr(nbi.AppInstanceInfoStatusReady),
		},
	}, {
		NBI: &nbi.AppManifest{ // 1
			Name:        "k8sapp1",
			AppProvider: "devorg1",
			Version:     "1.0.1",
			PackageType: nbi.HELM,
			AppRepo: nbi.AppManifest_AppRepo{
				ImagePath: "https://helm.github.io/examples:examples/hello-world",
				Type:      nbi.PUBLICREPO,
			},
			ComponentSpec: []nbi.AppManifest_ComponentSpec{{
				ComponentName: "comp0",
				NetworkInterfaces: []nbi.AppManifest_ComponentSpec_NetworkInterfaces{{
					InterfaceId:    "web",
					Port:           80,
					Protocol:       nbi.TCP,
					VisibilityType: nbi.VISIBILITYEXTERNAL,
				}},
			}},
			RequiredResources: krRR(nbi.KubernetesResources{
				ApplicationResources: nbi.KubernetesResources_ApplicationResources{
					CpuPool: &nbi.KubernetesResources_ApplicationResources_CpuPool{
						NumCPU: 1,
						Memory: 1024,
						Topology: nbi.KubernetesResources_ApplicationResources_CpuPool_Topology{
							MinNodeCpu:       1,
							MinNodeMemory:    1024,
							MinNumberOfNodes: 1,
						},
					},
				},
				IsStandalone: true,
				Version:      toPtr("1.29"),
			}),
		},
		Edgeproto: &edgeproto.App{ // 1
			Key: edgeproto.AppKey{
				Name:         "k8sapp1",
				Organization: "devorg1",
				Version:      "1.0.1",
			},
			ImageType:   edgeproto.ImageType_IMAGE_TYPE_HELM,
			ImagePath:   "https://helm.github.io/examples:examples/hello-world",
			Deployment:  cloudcommon.DeploymentTypeHelm,
			AccessPorts: "tcp:80:tls:id=web",
			KubernetesResources: &edgeproto.KubernetesResources{
				CpuPool: &edgeproto.NodePoolResources{
					TotalVcpus:  *edgeproto.NewUdec64(1, 0),
					TotalMemory: 1024,
					Topology: edgeproto.NodePoolTopology{
						MinNodeVcpus:     1,
						MinNodeMemory:    1024,
						MinNumberOfNodes: 1,
					},
				},
				MinKubernetesVersion: "1.29",
			},
			AllowServerless: false,
			AppAnnotations: map[string]string{
				"NBIAppComponentName": "comp0",
				"NBIAppRepoType":      "NBIAppRepoTypePublic",
			},
		},
		InstTemplate: &nbi.AppInstanceInfo{
			AppProvider: "devorg1",
			ComponentEndpointInfo: &[]nbi.AppInstanceInfo_ComponentEndpointInfo{{
				AccessPoints: nbi.AccessEndpoint{
					Port: 80,
				},
				InterfaceId: "web",
			}},
			Status: toPtr(nbi.AppInstanceInfoStatusReady),
		},
	}}
}

func krRR(kr nbi.KubernetesResources) nbi.RequiredResources {
	rr := nbi.RequiredResources{}
	err := rr.FromKubernetesResources(kr)
	if err != nil {
		panic(err.Error())
	}
	return rr
}

func toPtr[T any](v T) *T {
	return &v
}
