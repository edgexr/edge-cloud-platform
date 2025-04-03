// Copyright 2022 MobiledgeX, Inc
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
	"testing"

	"github.com/edgexr/edge-cloud-platform/api/edgeproto"
	"github.com/edgexr/edge-cloud-platform/pkg/cloudcommon"
	"github.com/edgexr/edge-cloud-platform/pkg/log"
	"github.com/edgexr/edge-cloud-platform/pkg/platform/pc"
	"github.com/stretchr/testify/require"
)

func TestGetNodeInfos(t *testing.T) {
	log.InitTracer(nil)
	defer log.FinishTracer()
	ctx := log.StartTestSpan(context.Background())

	client := pc.DummyClient{}
	client.Out = getNodesSampleOutput

	nodeInfos, err := GetNodeInfos(ctx, &client, "")
	require.Nil(t, err)

	expNodes := []*edgeproto.NodeInfo{{
		Name: "aks-agentpool-30520393-vmss000000",
		Allocatable: map[string]*edgeproto.Udec64{
			cloudcommon.ResourceVcpus:  edgeproto.NewUdec64(1, 900*edgeproto.DecMillis),
			cloudcommon.ResourceRamMb:  edgeproto.NewUdec64(5368, 0),
			cloudcommon.ResourceDiskGb: edgeproto.NewUdec64(111, 0),
		},
		Capacity: map[string]*edgeproto.Udec64{
			cloudcommon.ResourceVcpus:  edgeproto.NewUdec64(2, 0),
			cloudcommon.ResourceRamMb:  edgeproto.NewUdec64(7961, 0),
			cloudcommon.ResourceDiskGb: edgeproto.NewUdec64(123, 0),
		},
		Gpus:        []*edgeproto.GPUResource{},
		GpuSoftware: &edgeproto.GPUSoftwareInfo{},
	}, {
		Name: "aks-agentpool-30520393-vmss000001",
		Allocatable: map[string]*edgeproto.Udec64{
			cloudcommon.ResourceVcpus:  edgeproto.NewUdec64(1, 900*edgeproto.DecMillis),
			cloudcommon.ResourceRamMb:  edgeproto.NewUdec64(5368, 0),
			cloudcommon.ResourceDiskGb: edgeproto.NewUdec64(111, 0),
		},
		Capacity: map[string]*edgeproto.Udec64{
			cloudcommon.ResourceVcpus:  edgeproto.NewUdec64(2, 0),
			cloudcommon.ResourceRamMb:  edgeproto.NewUdec64(7961, 0),
			cloudcommon.ResourceDiskGb: edgeproto.NewUdec64(123, 0),
		},
		Gpus:        []*edgeproto.GPUResource{},
		GpuSoftware: &edgeproto.GPUSoftwareInfo{},
	}, {
		Name: "aks-agentpool-30520393-vmss000002",
		Allocatable: map[string]*edgeproto.Udec64{
			cloudcommon.ResourceVcpus:  edgeproto.NewUdec64(1, 900*edgeproto.DecMillis),
			cloudcommon.ResourceRamMb:  edgeproto.NewUdec64(5368, 0),
			cloudcommon.ResourceDiskGb: edgeproto.NewUdec64(111, 0),
		},
		Capacity: map[string]*edgeproto.Udec64{
			cloudcommon.ResourceVcpus:  edgeproto.NewUdec64(2, 0),
			cloudcommon.ResourceRamMb:  edgeproto.NewUdec64(7961, 0),
			cloudcommon.ResourceDiskGb: edgeproto.NewUdec64(123, 0),
		},
		Gpus:        []*edgeproto.GPUResource{},
		GpuSoftware: &edgeproto.GPUSoftwareInfo{},
	}}
	require.Equal(t, expNodes, nodeInfos)
}

func TestGetGPUNodeInfos(t *testing.T) {
	log.InitTracer(nil)
	defer log.FinishTracer()
	ctx := log.StartTestSpan(context.Background())

	client := pc.DummyClient{}

	client.Out = gpuNodesSampleOutput

	nodeInfos, err := GetNodeInfos(ctx, &client, "")
	require.Nil(t, err)

	expNodes := []*edgeproto.NodeInfo{{
		Name: "nori",
		Allocatable: map[string]*edgeproto.Udec64{
			cloudcommon.ResourceVcpus:  edgeproto.NewUdec64(2, 0),
			cloudcommon.ResourceRamMb:  edgeproto.NewUdec64(15984, 0),
			cloudcommon.ResourceDiskGb: edgeproto.NewUdec64(70, 0),
		},
		Capacity: map[string]*edgeproto.Udec64{
			cloudcommon.ResourceVcpus:  edgeproto.NewUdec64(2, 0),
			cloudcommon.ResourceRamMb:  edgeproto.NewUdec64(15984, 0),
			cloudcommon.ResourceDiskGb: edgeproto.NewUdec64(74, 0),
		},
		Gpus: []*edgeproto.GPUResource{{
			ModelId: "NVIDIA-A16-4Q",
			Memory:  4,
			Count:   1,
			Vendor:  cloudcommon.GPUVendorNVIDIA,
		}},
		GpuSoftware: &edgeproto.GPUSoftwareInfo{
			DriverVersion:  "550.90.07",
			RuntimeVersion: "12.4",
		},
	}}
	require.Equal(t, expNodes, nodeInfos)
}

// Output of "kubectl get nodes --output=json"
var getNodesSampleOutput = `
{
    "apiVersion": "v1",
    "items": [
        {
            "apiVersion": "v1",
            "kind": "Node",
            "metadata": {
                "annotations": {
                    "node.alpha.kubernetes.io/ttl": "0",
                    "volumes.kubernetes.io/controller-managed-attach-detach": "true"
                },
                "creationTimestamp": "2021-07-18T09:42:46Z",
                "labels": {
                    "agentpool": "agentpool",
                    "beta.kubernetes.io/arch": "amd64",
                    "beta.kubernetes.io/instance-type": "Standard_D2s_v3",
                    "beta.kubernetes.io/os": "linux",
                    "failure-domain.beta.kubernetes.io/region": "southcentralus",
                    "failure-domain.beta.kubernetes.io/zone": "0",
                    "kubernetes.azure.com/node-image-version": "AKSUbuntu-1804gen2-2021.06.12",
                    "kubernetes.azure.com/os-sku": "Ubuntu",
                    "kubernetes.azure.com/role": "agent",
                    "kubernetes.io/arch": "amd64",
                    "kubernetes.io/hostname": "aks-agentpool-30520393-vmss000000",
                    "kubernetes.io/os": "linux",
                    "kubernetes.io/role": "agent",
                    "node-role.kubernetes.io/agent": "",
                    "node.kubernetes.io/instance-type": "Standard_D2s_v3",
                    "storageprofile": "managed",
                    "storagetier": "Premium_LRS",
                    "topology.kubernetes.io/region": "southcentralus",
                    "topology.kubernetes.io/zone": "0"
                },
                "managedFields": [
                    {
                        "apiVersion": "v1",
                        "fieldsType": "FieldsV1",
                        "fieldsV1": {
                            "f:metadata": {
                                "f:labels": {
                                    "f:kubernetes.io/role": {},
                                    "f:node-role.kubernetes.io/agent": {}
                                }
                            }
                        },
                        "manager": "kubectl",
                        "operation": "Update",
                        "time": "2021-07-18T09:43:02Z"
                    },
                    {
                        "apiVersion": "v1",
                        "fieldsType": "FieldsV1",
                        "fieldsV1": {
                            "f:metadata": {
                                "f:annotations": {
                                    ".": {},
                                    "f:volumes.kubernetes.io/controller-managed-attach-detach": {}
                                },
                                "f:labels": {
                                    ".": {},
                                    "f:agentpool": {},
                                    "f:beta.kubernetes.io/arch": {},
                                    "f:beta.kubernetes.io/instance-type": {},
                                    "f:beta.kubernetes.io/os": {},
                                    "f:failure-domain.beta.kubernetes.io/region": {},
                                    "f:failure-domain.beta.kubernetes.io/zone": {},
                                    "f:kubernetes.azure.com/cluster": {},
                                    "f:kubernetes.azure.com/node-image-version": {},
                                    "f:kubernetes.azure.com/os-sku": {},
                                    "f:kubernetes.azure.com/role": {},
                                    "f:kubernetes.io/arch": {},
                                    "f:kubernetes.io/hostname": {},
                                    "f:kubernetes.io/os": {},
                                    "f:node.kubernetes.io/instance-type": {},
                                    "f:storageprofile": {},
                                    "f:storagetier": {},
                                    "f:topology.kubernetes.io/region": {},
                                    "f:topology.kubernetes.io/zone": {}
                                }
                            },
                            "f:spec": {
                                "f:providerID": {}
                            },
                            "f:status": {
                                "f:addresses": {
                                    ".": {},
                                    "k:{\"type\":\"Hostname\"}": {
                                        ".": {},
                                        "f:address": {},
                                        "f:type": {}
                                    },
                                    "k:{\"type\":\"InternalIP\"}": {
                                        ".": {},
                                        "f:address": {},
                                        "f:type": {}
                                    }
                                },
                                "f:allocatable": {
                                    ".": {},
                                    "f:attachable-volumes-azure-disk": {},
                                    "f:cpu": {},
                                    "f:ephemeral-storage": {},
                                    "f:hugepages-1Gi": {},
                                    "f:hugepages-2Mi": {},
                                    "f:memory": {},
                                    "f:pods": {}
                                },
                                "f:capacity": {
                                    ".": {},
                                    "f:attachable-volumes-azure-disk": {},
                                    "f:cpu": {},
                                    "f:ephemeral-storage": {},
                                    "f:hugepages-1Gi": {},
                                    "f:hugepages-2Mi": {},
                                    "f:memory": {},
                                    "f:pods": {}
                                },
                                "f:conditions": {
                                    ".": {},
                                    "k:{\"type\":\"DiskPressure\"}": {
                                        ".": {},
                                        "f:lastHeartbeatTime": {},
                                        "f:lastTransitionTime": {},
                                        "f:message": {},
                                        "f:reason": {},
                                        "f:status": {},
                                        "f:type": {}
                                    },
                                    "k:{\"type\":\"MemoryPressure\"}": {
                                        ".": {},
                                        "f:lastHeartbeatTime": {},
                                        "f:lastTransitionTime": {},
                                        "f:message": {},
                                        "f:reason": {},
                                        "f:status": {},
                                        "f:type": {}
                                    },
                                    "k:{\"type\":\"PIDPressure\"}": {
                                        ".": {},
                                        "f:lastHeartbeatTime": {},
                                        "f:lastTransitionTime": {},
                                        "f:message": {},
                                        "f:reason": {},
                                        "f:status": {},
                                        "f:type": {}
                                    },
                                    "k:{\"type\":\"Ready\"}": {
                                        ".": {},
                                        "f:lastHeartbeatTime": {},
                                        "f:lastTransitionTime": {},
                                        "f:message": {},
                                        "f:reason": {},
                                        "f:status": {},
                                        "f:type": {}
                                    }
                                },
                                "f:config": {},
                                "f:daemonEndpoints": {
                                    "f:kubeletEndpoint": {
                                        "f:Port": {}
                                    }
                                },
                                "f:images": {},
                                "f:nodeInfo": {
                                    "f:architecture": {},
                                    "f:bootID": {},
                                    "f:containerRuntimeVersion": {},
                                    "f:kernelVersion": {},
                                    "f:kubeProxyVersion": {},
                                    "f:kubeletVersion": {},
                                    "f:machineID": {},
                                    "f:operatingSystem": {},
                                    "f:osImage": {},
                                    "f:systemUUID": {}
                                },
                                "f:volumesInUse": {}
                            }
                        },
                        "manager": "kubelet",
                        "operation": "Update",
                        "time": "2021-07-18T12:35:04Z"
                    },
                    {
                        "apiVersion": "v1",
                        "fieldsType": "FieldsV1",
                        "fieldsV1": {
                            "f:metadata": {
                                "f:annotations": {
                                    "f:node.alpha.kubernetes.io/ttl": {}
                                }
                            },
                            "f:spec": {
                                "f:podCIDR": {},
                                "f:podCIDRs": {
                                    ".": {},
                                    "v:\"10.244.1.0/24\"": {}
                                }
                            },
                            "f:status": {
                                "f:conditions": {
                                    "k:{\"type\":\"NetworkUnavailable\"}": {
                                        ".": {},
                                        "f:lastHeartbeatTime": {},
                                        "f:lastTransitionTime": {},
                                        "f:message": {},
                                        "f:reason": {},
                                        "f:status": {},
                                        "f:type": {}
                                    }
                                },
                                "f:volumesAttached": {}
                            }
                        },
                        "manager": "kube-controller-manager",
                        "operation": "Update",
                        "time": "2021-07-18T12:35:36Z"
                    }
                ],
                "name": "aks-agentpool-30520393-vmss000000",
                "resourceVersion": "25296131",
                "selfLink": "/api/v1/nodes/aks-agentpool-30520393-vmss000000",
                "uid": "31af118e-5959-440a-8417-f3abbf6b9ed9"
            },
            "spec": {
                "podCIDR": "10.244.1.0/24",
                "podCIDRs": [
                    "10.244.1.0/24"
                ]
            },
            "status": {
                "addresses": [
                    {
                        "address": "aks-agentpool-30520393-vmss000000",
                        "type": "Hostname"
                    },
                    {
                        "address": "10.240.0.4",
                        "type": "InternalIP"
                    }
                ],
                "allocatable": {
                    "attachable-volumes-azure-disk": "4",
                    "cpu": "1900m",
                    "ephemeral-storage": "119716326407",
                    "hugepages-1Gi": "0",
                    "hugepages-2Mi": "0",
                    "memory": "5497568Ki",
                    "pods": "110"
                },
                "capacity": {
                    "attachable-volumes-azure-disk": "4",
                    "cpu": "2",
                    "ephemeral-storage": "129900528Ki",
                    "hugepages-1Gi": "0",
                    "hugepages-2Mi": "0",
                    "memory": "8152800Ki",
                    "pods": "110"
                },
                "conditions": [
                    {
                        "lastHeartbeatTime": "2021-07-18T09:43:09Z",
                        "lastTransitionTime": "2021-07-18T09:43:09Z",
                        "message": "RouteController created a route",
                        "reason": "RouteCreated",
                        "status": "False",
                        "type": "NetworkUnavailable"
                    },
                    {
                        "lastHeartbeatTime": "2021-10-05T21:53:39Z",
                        "lastTransitionTime": "2021-07-18T09:42:46Z",
                        "message": "kubelet has sufficient memory available",
                        "reason": "KubeletHasSufficientMemory",
                        "status": "False",
                        "type": "MemoryPressure"
                    },
                    {
                        "lastHeartbeatTime": "2021-10-05T21:53:39Z",
                        "lastTransitionTime": "2021-07-18T09:42:46Z",
                        "message": "kubelet has no disk pressure",
                        "reason": "KubeletHasNoDiskPressure",
                        "status": "False",
                        "type": "DiskPressure"
                    },
                    {
                        "lastHeartbeatTime": "2021-10-05T21:53:39Z",
                        "lastTransitionTime": "2021-07-18T09:42:46Z",
                        "message": "kubelet has sufficient PID available",
                        "reason": "KubeletHasSufficientPID",
                        "status": "False",
                        "type": "PIDPressure"
                    },
                    {
                        "lastHeartbeatTime": "2021-10-05T21:53:39Z",
                        "lastTransitionTime": "2021-07-18T09:42:47Z",
                        "message": "kubelet is posting ready status. AppArmor enabled",
                        "reason": "KubeletReady",
                        "status": "True",
                        "type": "Ready"
                    }
                ],
                "config": {},
                "daemonEndpoints": {
                    "kubeletEndpoint": {
                        "Port": 10211
                    }
                },
                "nodeInfo": {
                    "architecture": "amd64",
                    "bootID": "0615c9d0-7dc4-4000-b898-8d434ea2bb14",
                    "containerRuntimeVersion": "docker://19.3.14",
                    "kernelVersion": "5.4.0-1049-azure",
                    "kubeProxyVersion": "v1.18.19",
                    "kubeletVersion": "v1.18.19",
                    "machineID": "aae645a2ac5644fa8edfd13dcc420af4",
                    "operatingSystem": "linux",
                    "osImage": "Ubuntu 18.04.5 LTS",
                    "systemUUID": "5baa476c-6d93-4888-8afc-b5970d23e731"
                }
            }
        },
        {
            "apiVersion": "v1",
            "kind": "Node",
            "metadata": {
                "annotations": {
                    "node.alpha.kubernetes.io/ttl": "0",
                    "volumes.kubernetes.io/controller-managed-attach-detach": "true"
                },
                "creationTimestamp": "2021-07-18T09:43:29Z",
                "labels": {
                    "agentpool": "agentpool",
                    "beta.kubernetes.io/arch": "amd64",
                    "beta.kubernetes.io/instance-type": "Standard_D2s_v3",
                    "beta.kubernetes.io/os": "linux",
                    "failure-domain.beta.kubernetes.io/region": "southcentralus",
                    "failure-domain.beta.kubernetes.io/zone": "1",
                    "kubernetes.azure.com/node-image-version": "AKSUbuntu-1804gen2-2021.06.12",
                    "kubernetes.azure.com/os-sku": "Ubuntu",
                    "kubernetes.azure.com/role": "agent",
                    "kubernetes.io/arch": "amd64",
                    "kubernetes.io/hostname": "aks-agentpool-30520393-vmss000001",
                    "kubernetes.io/os": "linux",
                    "kubernetes.io/role": "agent",
                    "node-role.kubernetes.io/agent": "",
                    "node.kubernetes.io/instance-type": "Standard_D2s_v3",
                    "storageprofile": "managed",
                    "storagetier": "Premium_LRS",
                    "topology.kubernetes.io/region": "southcentralus",
                    "topology.kubernetes.io/zone": "1"
                },
                "managedFields": [
                    {
                        "apiVersion": "v1",
                        "fieldsType": "FieldsV1",
                        "fieldsV1": {
                            "f:metadata": {
                                "f:labels": {
                                    "f:kubernetes.io/role": {},
                                    "f:node-role.kubernetes.io/agent": {}
                                }
                            }
                        },
                        "manager": "kubectl",
                        "operation": "Update",
                        "time": "2021-07-18T09:44:02Z"
                    },
                    {
                        "apiVersion": "v1",
                        "fieldsType": "FieldsV1",
                        "fieldsV1": {
                            "f:metadata": {
                                "f:annotations": {
                                    ".": {},
                                    "f:volumes.kubernetes.io/controller-managed-attach-detach": {}
                                },
                                "f:labels": {
                                    ".": {},
                                    "f:agentpool": {},
                                    "f:beta.kubernetes.io/arch": {},
                                    "f:beta.kubernetes.io/instance-type": {},
                                    "f:beta.kubernetes.io/os": {},
                                    "f:failure-domain.beta.kubernetes.io/region": {},
                                    "f:failure-domain.beta.kubernetes.io/zone": {},
                                    "f:kubernetes.azure.com/cluster": {},
                                    "f:kubernetes.azure.com/node-image-version": {},
                                    "f:kubernetes.azure.com/os-sku": {},
                                    "f:kubernetes.azure.com/role": {},
                                    "f:kubernetes.io/arch": {},
                                    "f:kubernetes.io/hostname": {},
                                    "f:kubernetes.io/os": {},
                                    "f:node.kubernetes.io/instance-type": {},
                                    "f:storageprofile": {},
                                    "f:storagetier": {},
                                    "f:topology.kubernetes.io/region": {},
                                    "f:topology.kubernetes.io/zone": {}
                                }
                            },
                            "f:spec": {
                                "f:providerID": {}
                            },
                            "f:status": {
                                "f:addresses": {
                                    ".": {},
                                    "k:{\"type\":\"Hostname\"}": {
                                        ".": {},
                                        "f:address": {},
                                        "f:type": {}
                                    },
                                    "k:{\"type\":\"InternalIP\"}": {
                                        ".": {},
                                        "f:address": {},
                                        "f:type": {}
                                    }
                                },
                                "f:allocatable": {
                                    ".": {},
                                    "f:attachable-volumes-azure-disk": {},
                                    "f:cpu": {},
                                    "f:ephemeral-storage": {},
                                    "f:hugepages-1Gi": {},
                                    "f:hugepages-2Mi": {},
                                    "f:memory": {},
                                    "f:pods": {}
                                },
                                "f:capacity": {
                                    ".": {},
                                    "f:attachable-volumes-azure-disk": {},
                                    "f:cpu": {},
                                    "f:ephemeral-storage": {},
                                    "f:hugepages-1Gi": {},
                                    "f:hugepages-2Mi": {},
                                    "f:memory": {},
                                    "f:pods": {}
                                },
                                "f:conditions": {
                                    ".": {},
                                    "k:{\"type\":\"DiskPressure\"}": {
                                        ".": {},
                                        "f:lastHeartbeatTime": {},
                                        "f:lastTransitionTime": {},
                                        "f:message": {},
                                        "f:reason": {},
                                        "f:status": {},
                                        "f:type": {}
                                    },
                                    "k:{\"type\":\"MemoryPressure\"}": {
                                        ".": {},
                                        "f:lastHeartbeatTime": {},
                                        "f:lastTransitionTime": {},
                                        "f:message": {},
                                        "f:reason": {},
                                        "f:status": {},
                                        "f:type": {}
                                    },
                                    "k:{\"type\":\"PIDPressure\"}": {
                                        ".": {},
                                        "f:lastHeartbeatTime": {},
                                        "f:lastTransitionTime": {},
                                        "f:message": {},
                                        "f:reason": {},
                                        "f:status": {},
                                        "f:type": {}
                                    },
                                    "k:{\"type\":\"Ready\"}": {
                                        ".": {},
                                        "f:lastHeartbeatTime": {},
                                        "f:lastTransitionTime": {},
                                        "f:message": {},
                                        "f:reason": {},
                                        "f:status": {},
                                        "f:type": {}
                                    }
                                },
                                "f:config": {},
                                "f:daemonEndpoints": {
                                    "f:kubeletEndpoint": {
                                        "f:Port": {}
                                    }
                                },
                                "f:images": {},
                                "f:nodeInfo": {
                                    "f:architecture": {},
                                    "f:bootID": {},
                                    "f:containerRuntimeVersion": {},
                                    "f:kernelVersion": {},
                                    "f:kubeProxyVersion": {},
                                    "f:kubeletVersion": {},
                                    "f:machineID": {},
                                    "f:operatingSystem": {},
                                    "f:osImage": {},
                                    "f:systemUUID": {}
                                },
                                "f:volumesInUse": {}
                            }
                        },
                        "manager": "kubelet",
                        "operation": "Update",
                        "time": "2021-07-18T12:36:05Z"
                    },
                    {
                        "apiVersion": "v1",
                        "fieldsType": "FieldsV1",
                        "fieldsV1": {
                            "f:metadata": {
                                "f:annotations": {
                                    "f:node.alpha.kubernetes.io/ttl": {}
                                }
                            },
                            "f:spec": {
                                "f:podCIDR": {},
                                "f:podCIDRs": {
                                    ".": {},
                                    "v:\"10.244.2.0/24\"": {}
                                }
                            },
                            "f:status": {
                                "f:conditions": {
                                    "k:{\"type\":\"NetworkUnavailable\"}": {
                                        ".": {},
                                        "f:lastHeartbeatTime": {},
                                        "f:lastTransitionTime": {},
                                        "f:message": {},
                                        "f:reason": {},
                                        "f:status": {},
                                        "f:type": {}
                                    }
                                },
                                "f:volumesAttached": {}
                            }
                        },
                        "manager": "kube-controller-manager",
                        "operation": "Update",
                        "time": "2021-07-18T12:36:15Z"
                    }
                ],
                "name": "aks-agentpool-30520393-vmss000001",
                "resourceVersion": "25295719",
                "selfLink": "/api/v1/nodes/aks-agentpool-30520393-vmss000001",
                "uid": "3335beb8-ed1f-41cd-af49-9cbe3f063514"
            },
            "spec": {
                "podCIDR": "10.244.2.0/24",
                "podCIDRs": [
                    "10.244.2.0/24"
                ]
            },
            "status": {
                "addresses": [
                    {
                        "address": "aks-agentpool-30520393-vmss000001",
                        "type": "Hostname"
                    },
                    {
                        "address": "10.240.0.5",
                        "type": "InternalIP"
                    }
                ],
                "allocatable": {
                    "attachable-volumes-azure-disk": "4",
                    "cpu": "1900m",
                    "ephemeral-storage": "119716326407",
                    "hugepages-1Gi": "0",
                    "hugepages-2Mi": "0",
                    "memory": "5497568Ki",
                    "pods": "110"
                },
                "capacity": {
                    "attachable-volumes-azure-disk": "4",
                    "cpu": "2",
                    "ephemeral-storage": "129900528Ki",
                    "hugepages-1Gi": "0",
                    "hugepages-2Mi": "0",
                    "memory": "8152800Ki",
                    "pods": "110"
                },
                "conditions": [
                    {
                        "lastHeartbeatTime": "2021-07-18T09:43:50Z",
                        "lastTransitionTime": "2021-07-18T09:43:50Z",
                        "message": "RouteController created a route",
                        "reason": "RouteCreated",
                        "status": "False",
                        "type": "NetworkUnavailable"
                    },
                    {
                        "lastHeartbeatTime": "2021-10-05T21:51:47Z",
                        "lastTransitionTime": "2021-07-18T09:43:29Z",
                        "message": "kubelet has sufficient memory available",
                        "reason": "KubeletHasSufficientMemory",
                        "status": "False",
                        "type": "MemoryPressure"
                    },
                    {
                        "lastHeartbeatTime": "2021-10-05T21:51:47Z",
                        "lastTransitionTime": "2021-07-18T09:43:29Z",
                        "message": "kubelet has no disk pressure",
                        "reason": "KubeletHasNoDiskPressure",
                        "status": "False",
                        "type": "DiskPressure"
                    },
                    {
                        "lastHeartbeatTime": "2021-10-05T21:51:47Z",
                        "lastTransitionTime": "2021-07-18T09:43:29Z",
                        "message": "kubelet has sufficient PID available",
                        "reason": "KubeletHasSufficientPID",
                        "status": "False",
                        "type": "PIDPressure"
                    },
                    {
                        "lastHeartbeatTime": "2021-10-05T21:51:47Z",
                        "lastTransitionTime": "2021-07-18T09:43:39Z",
                        "message": "kubelet is posting ready status. AppArmor enabled",
                        "reason": "KubeletReady",
                        "status": "True",
                        "type": "Ready"
                    }
                ],
                "config": {},
                "daemonEndpoints": {
                    "kubeletEndpoint": {
                        "Port": 10211
                    }
                },
                "nodeInfo": {
                    "architecture": "amd64",
                    "bootID": "417a9d39-f61b-4cc7-b43b-1c58d2669f6f",
                    "containerRuntimeVersion": "docker://19.3.14",
                    "kernelVersion": "5.4.0-1049-azure",
                    "kubeProxyVersion": "v1.18.19",
                    "kubeletVersion": "v1.18.19",
                    "machineID": "643edc584d36482aa3134748a2d288b4",
                    "operatingSystem": "linux",
                    "osImage": "Ubuntu 18.04.5 LTS",
                    "systemUUID": "128c4972-c980-4043-8f62-ed3dc9afac31"
                }
            }
        },
        {
            "apiVersion": "v1",
            "kind": "Node",
            "metadata": {
                "annotations": {
                    "node.alpha.kubernetes.io/ttl": "0",
                    "volumes.kubernetes.io/controller-managed-attach-detach": "true"
                },
                "creationTimestamp": "2021-07-18T09:42:45Z",
                "labels": {
                    "agentpool": "agentpool",
                    "beta.kubernetes.io/arch": "amd64",
                    "beta.kubernetes.io/instance-type": "Standard_D2s_v3",
                    "beta.kubernetes.io/os": "linux",
                    "failure-domain.beta.kubernetes.io/region": "southcentralus",
                    "failure-domain.beta.kubernetes.io/zone": "2",
                    "kubernetes.azure.com/node-image-version": "AKSUbuntu-1804gen2-2021.06.12",
                    "kubernetes.azure.com/os-sku": "Ubuntu",
                    "kubernetes.azure.com/role": "agent",
                    "kubernetes.io/arch": "amd64",
                    "kubernetes.io/hostname": "aks-agentpool-30520393-vmss000002",
                    "kubernetes.io/os": "linux",
                    "kubernetes.io/role": "agent",
                    "node-role.kubernetes.io/agent": "",
                    "node.kubernetes.io/instance-type": "Standard_D2s_v3",
                    "storageprofile": "managed",
                    "storagetier": "Premium_LRS",
                    "topology.kubernetes.io/region": "southcentralus",
                    "topology.kubernetes.io/zone": "2"
                },
                "managedFields": [
                    {
                        "apiVersion": "v1",
                        "fieldsType": "FieldsV1",
                        "fieldsV1": {
                            "f:metadata": {
                                "f:labels": {
                                    "f:kubernetes.io/role": {},
                                    "f:node-role.kubernetes.io/agent": {}
                                }
                            }
                        },
                        "manager": "kubectl",
                        "operation": "Update",
                        "time": "2021-07-18T09:43:02Z"
                    },
                    {
                        "apiVersion": "v1",
                        "fieldsType": "FieldsV1",
                        "fieldsV1": {
                            "f:metadata": {
                                "f:annotations": {
                                    ".": {},
                                    "f:volumes.kubernetes.io/controller-managed-attach-detach": {}
                                },
                                "f:labels": {
                                    ".": {},
                                    "f:agentpool": {},
                                    "f:beta.kubernetes.io/arch": {},
                                    "f:beta.kubernetes.io/instance-type": {},
                                    "f:beta.kubernetes.io/os": {},
                                    "f:failure-domain.beta.kubernetes.io/region": {},
                                    "f:failure-domain.beta.kubernetes.io/zone": {},
                                    "f:kubernetes.azure.com/cluster": {},
                                    "f:kubernetes.azure.com/node-image-version": {},
                                    "f:kubernetes.azure.com/os-sku": {},
                                    "f:kubernetes.azure.com/role": {},
                                    "f:kubernetes.io/arch": {},
                                    "f:kubernetes.io/hostname": {},
                                    "f:kubernetes.io/os": {},
                                    "f:node.kubernetes.io/instance-type": {},
                                    "f:storageprofile": {},
                                    "f:storagetier": {},
                                    "f:topology.kubernetes.io/region": {},
                                    "f:topology.kubernetes.io/zone": {}
                                }
                            },
                            "f:spec": {
                                "f:providerID": {}
                            },
                            "f:status": {
                                "f:addresses": {
                                    ".": {},
                                    "k:{\"type\":\"Hostname\"}": {
                                        ".": {},
                                        "f:address": {},
                                        "f:type": {}
                                    },
                                    "k:{\"type\":\"InternalIP\"}": {
                                        ".": {},
                                        "f:address": {},
                                        "f:type": {}
                                    }
                                },
                                "f:allocatable": {
                                    ".": {},
                                    "f:attachable-volumes-azure-disk": {},
                                    "f:cpu": {},
                                    "f:ephemeral-storage": {},
                                    "f:hugepages-1Gi": {},
                                    "f:hugepages-2Mi": {},
                                    "f:memory": {},
                                    "f:pods": {}
                                },
                                "f:capacity": {
                                    ".": {},
                                    "f:attachable-volumes-azure-disk": {},
                                    "f:cpu": {},
                                    "f:ephemeral-storage": {},
                                    "f:hugepages-1Gi": {},
                                    "f:hugepages-2Mi": {},
                                    "f:memory": {},
                                    "f:pods": {}
                                },
                                "f:conditions": {
                                    ".": {},
                                    "k:{\"type\":\"DiskPressure\"}": {
                                        ".": {},
                                        "f:lastHeartbeatTime": {},
                                        "f:lastTransitionTime": {},
                                        "f:message": {},
                                        "f:reason": {},
                                        "f:status": {},
                                        "f:type": {}
                                    },
                                    "k:{\"type\":\"MemoryPressure\"}": {
                                        ".": {},
                                        "f:lastHeartbeatTime": {},
                                        "f:lastTransitionTime": {},
                                        "f:message": {},
                                        "f:reason": {},
                                        "f:status": {},
                                        "f:type": {}
                                    },
                                    "k:{\"type\":\"PIDPressure\"}": {
                                        ".": {},
                                        "f:lastHeartbeatTime": {},
                                        "f:lastTransitionTime": {},
                                        "f:message": {},
                                        "f:reason": {},
                                        "f:status": {},
                                        "f:type": {}
                                    },
                                    "k:{\"type\":\"Ready\"}": {
                                        ".": {},
                                        "f:lastHeartbeatTime": {},
                                        "f:lastTransitionTime": {},
                                        "f:message": {},
                                        "f:reason": {},
                                        "f:status": {},
                                        "f:type": {}
                                    }
                                },
                                "f:config": {},
                                "f:daemonEndpoints": {
                                    "f:kubeletEndpoint": {
                                        "f:Port": {}
                                    }
                                },
                                "f:images": {},
                                "f:nodeInfo": {
                                    "f:architecture": {},
                                    "f:bootID": {},
                                    "f:containerRuntimeVersion": {},
                                    "f:kernelVersion": {},
                                    "f:kubeProxyVersion": {},
                                    "f:kubeletVersion": {},
                                    "f:machineID": {},
                                    "f:operatingSystem": {},
                                    "f:osImage": {},
                                    "f:systemUUID": {}
                                },
                                "f:volumesInUse": {}
                            }
                        },
                        "manager": "kubelet",
                        "operation": "Update",
                        "time": "2021-07-18T12:34:38Z"
                    },
                    {
                        "apiVersion": "v1",
                        "fieldsType": "FieldsV1",
                        "fieldsV1": {
                            "f:metadata": {
                                "f:annotations": {
                                    "f:node.alpha.kubernetes.io/ttl": {}
                                }
                            },
                            "f:spec": {
                                "f:podCIDR": {},
                                "f:podCIDRs": {
                                    ".": {},
                                    "v:\"10.244.0.0/24\"": {}
                                }
                            },
                            "f:status": {
                                "f:conditions": {
                                    "k:{\"type\":\"NetworkUnavailable\"}": {
                                        ".": {},
                                        "f:lastHeartbeatTime": {},
                                        "f:lastTransitionTime": {},
                                        "f:message": {},
                                        "f:reason": {},
                                        "f:status": {},
                                        "f:type": {}
                                    }
                                },
                                "f:volumesAttached": {}
                            }
                        },
                        "manager": "kube-controller-manager",
                        "operation": "Update",
                        "time": "2021-07-18T12:34:45Z"
                    }
                ],
                "name": "aks-agentpool-30520393-vmss000002",
                "resourceVersion": "25295824",
                "selfLink": "/api/v1/nodes/aks-agentpool-30520393-vmss000002",
                "uid": "0dc68414-ce91-4115-8fc7-364f56449572"
            },
            "spec": {
                "podCIDR": "10.244.0.0/24",
                "podCIDRs": [
                    "10.244.0.0/24"
                ]
            },
            "status": {
                "addresses": [
                    {
                        "address": "aks-agentpool-30520393-vmss000002",
                        "type": "Hostname"
                    },
                    {
                        "address": "10.240.0.6",
                        "type": "InternalIP"
                    }
                ],
                "allocatable": {
                    "attachable-volumes-azure-disk": "4",
                    "cpu": "1900m",
                    "ephemeral-storage": "119716326407",
                    "hugepages-1Gi": "0",
                    "hugepages-2Mi": "0",
                    "memory": "5497564Ki",
                    "pods": "110"
                },
                "capacity": {
                    "attachable-volumes-azure-disk": "4",
                    "cpu": "2",
                    "ephemeral-storage": "129900528Ki",
                    "hugepages-1Gi": "0",
                    "hugepages-2Mi": "0",
                    "memory": "8152796Ki",
                    "pods": "110"
                },
                "conditions": [
                    {
                        "lastHeartbeatTime": "2021-07-18T09:43:09Z",
                        "lastTransitionTime": "2021-07-18T09:43:09Z",
                        "message": "RouteController created a route",
                        "reason": "RouteCreated",
                        "status": "False",
                        "type": "NetworkUnavailable"
                    },
                    {
                        "lastHeartbeatTime": "2021-10-05T21:52:16Z",
                        "lastTransitionTime": "2021-07-18T09:42:45Z",
                        "message": "kubelet has sufficient memory available",
                        "reason": "KubeletHasSufficientMemory",
                        "status": "False",
                        "type": "MemoryPressure"
                    },
                    {
                        "lastHeartbeatTime": "2021-10-05T21:52:16Z",
                        "lastTransitionTime": "2021-07-18T09:42:45Z",
                        "message": "kubelet has no disk pressure",
                        "reason": "KubeletHasNoDiskPressure",
                        "status": "False",
                        "type": "DiskPressure"
                    },
                    {
                        "lastHeartbeatTime": "2021-10-05T21:52:16Z",
                        "lastTransitionTime": "2021-07-18T09:42:45Z",
                        "message": "kubelet has sufficient PID available",
                        "reason": "KubeletHasSufficientPID",
                        "status": "False",
                        "type": "PIDPressure"
                    },
                    {
                        "lastHeartbeatTime": "2021-10-05T21:52:16Z",
                        "lastTransitionTime": "2021-07-18T09:42:49Z",
                        "message": "kubelet is posting ready status. AppArmor enabled",
                        "reason": "KubeletReady",
                        "status": "True",
                        "type": "Ready"
                    }
                ],
                "config": {},
                "daemonEndpoints": {
                    "kubeletEndpoint": {
                        "Port": 10211
                    }
                },
                "nodeInfo": {
                    "architecture": "amd64",
                    "bootID": "dc5a2572-50c4-4eca-abef-e351a27b5ea2",
                    "containerRuntimeVersion": "docker://19.3.14",
                    "kernelVersion": "5.4.0-1049-azure",
                    "kubeProxyVersion": "v1.18.19",
                    "kubeletVersion": "v1.18.19",
                    "machineID": "a0f3ff3098744fe795119b2019c06253",
                    "operatingSystem": "linux",
                    "osImage": "Ubuntu 18.04.5 LTS",
                    "systemUUID": "4c191a84-2005-45b5-8f39-fc647c71a75f"
                }
            }
        }
    ],
    "kind": "List",
    "metadata": {
        "resourceVersion": "",
        "selfLink": ""
    }
}
`

var gpuNodesSampleOutput = `
{
    "apiVersion": "v1",
    "items": [
        {
            "apiVersion": "v1",
            "kind": "Node",
            "metadata": {
                "annotations": {
                    "alpha.kubernetes.io/provided-node-ip": "0.202.61.70",
                    "etcd.rke2.cattle.io/local-snapshots-timestamp": "2025-03-19T23:13:21Z",
                    "etcd.rke2.cattle.io/node-address": "0.202.61.70",
                    "etcd.rke2.cattle.io/node-name": "nori-c0896cb6",
                    "flannel.alpha.coreos.com/backend-data": "{\"VNI\":1,\"VtepMAC\":\"4a:27:01:74:7e:a5\"}",
                    "flannel.alpha.coreos.com/backend-type": "vxlan",
                    "flannel.alpha.coreos.com/kube-subnet-manager": "true",
                    "flannel.alpha.coreos.com/public-ip": "0.202.61.70",
                    "nfd.node.kubernetes.io/feature-labels": "cpu-cpuid.AESNI,cpu-cpuid.AVX,cpu-cpuid.AVX2,cpu-cpuid.CMPXCHG8,cpu-cpuid.FMA3,cpu-cpuid.FXSR,cpu-cpuid.FXSROPT,cpu-cpuid.HYPERVISOR,cpu-cpuid.IBPB,cpu-cpuid.LAHF,cpu-cpuid.MOVBE,cpu-cpuid.OSXSAVE,cpu-cpuid.SPEC_CTRL_SSBD,cpu-cpuid.SYSCALL,cpu-cpuid.SYSEE,cpu-cpuid.X87,cpu-cpuid.XSAVE,cpu-cpuid.XSAVEOPT,cpu-hardware_multithreading,cpu-model.family,cpu-model.id,cpu-model.vendor_id,kernel-config.NO_HZ,kernel-config.NO_HZ_IDLE,kernel-version.full,kernel-version.major,kernel-version.minor,kernel-version.revision,memory-swap,nvidia.com/cuda.driver-version.full,nvidia.com/cuda.driver-version.major,nvidia.com/cuda.driver-version.minor,nvidia.com/cuda.driver-version.revision,nvidia.com/cuda.driver.major,nvidia.com/cuda.driver.minor,nvidia.com/cuda.driver.rev,nvidia.com/cuda.runtime-version.full,nvidia.com/cuda.runtime-version.major,nvidia.com/cuda.runtime-version.minor,nvidia.com/cuda.runtime.major,nvidia.com/cuda.runtime.minor,nvidia.com/gfd.timestamp,nvidia.com/gpu.compute.major,nvidia.com/gpu.compute.minor,nvidia.com/gpu.count,nvidia.com/gpu.family,nvidia.com/gpu.machine,nvidia.com/gpu.memory,nvidia.com/gpu.mode,nvidia.com/gpu.product,nvidia.com/gpu.replicas,nvidia.com/gpu.sharing-strategy,nvidia.com/mig.capable,nvidia.com/mig.strategy,nvidia.com/mps.capable,nvidia.com/vgpu.host-driver-branch,nvidia.com/vgpu.host-driver-version,nvidia.com/vgpu.present,pci-10de.present,pci-1234.present,pci-1af4.present,system-os_release.ID,system-os_release.VERSION_ID,system-os_release.VERSION_ID.major,system-os_release.VERSION_ID.minor",
                    "node.alpha.kubernetes.io/ttl": "0",
                    "nvidia.com/gpu-driver-upgrade-enabled": "true",
                    "rke2.io/encryption-config-hash": "start-0841ae8749d836bd6fd825a61bcc768d83a5dddfe60c2fd8c6fe82a5e36bb67b",
                    "rke2.io/hostname": "nori",
                    "rke2.io/internal-ip": "0.202.61.70",
                    "rke2.io/node-args": "[\"server\"]",
                    "rke2.io/node-config-hash": "MLFMUCBMRVINLJJKSG32TOUFWB4CN55GMSNY25AZPESQXZCYRN2A====",
                    "rke2.io/node-env": "{}",
                    "volumes.kubernetes.io/controller-managed-attach-detach": "true"
                },
                "creationTimestamp": "2025-03-19T20:40:47Z",
                "finalizers": [
                    "wrangler.cattle.io/managed-etcd-controller",
                    "wrangler.cattle.io/node"
                ],
                "labels": {
                    "beta.kubernetes.io/arch": "amd64",
                    "beta.kubernetes.io/instance-type": "rke2",
                    "beta.kubernetes.io/os": "linux",
                    "feature.node.kubernetes.io/cpu-cpuid.AESNI": "true",
                    "feature.node.kubernetes.io/cpu-cpuid.AVX": "true",
                    "feature.node.kubernetes.io/cpu-cpuid.AVX2": "true",
                    "feature.node.kubernetes.io/cpu-cpuid.CMPXCHG8": "true",
                    "feature.node.kubernetes.io/cpu-cpuid.FMA3": "true",
                    "feature.node.kubernetes.io/cpu-cpuid.FXSR": "true",
                    "feature.node.kubernetes.io/cpu-cpuid.FXSROPT": "true",
                    "feature.node.kubernetes.io/cpu-cpuid.HYPERVISOR": "true",
                    "feature.node.kubernetes.io/cpu-cpuid.IBPB": "true",
                    "feature.node.kubernetes.io/cpu-cpuid.LAHF": "true",
                    "feature.node.kubernetes.io/cpu-cpuid.MOVBE": "true",
                    "feature.node.kubernetes.io/cpu-cpuid.OSXSAVE": "true",
                    "feature.node.kubernetes.io/cpu-cpuid.SPEC_CTRL_SSBD": "true",
                    "feature.node.kubernetes.io/cpu-cpuid.SYSCALL": "true",
                    "feature.node.kubernetes.io/cpu-cpuid.SYSEE": "true",
                    "feature.node.kubernetes.io/cpu-cpuid.X87": "true",
                    "feature.node.kubernetes.io/cpu-cpuid.XSAVE": "true",
                    "feature.node.kubernetes.io/cpu-cpuid.XSAVEOPT": "true",
                    "feature.node.kubernetes.io/cpu-hardware_multithreading": "true",
                    "feature.node.kubernetes.io/cpu-model.family": "6",
                    "feature.node.kubernetes.io/cpu-model.id": "61",
                    "feature.node.kubernetes.io/cpu-model.vendor_id": "Intel",
                    "feature.node.kubernetes.io/kernel-config.NO_HZ": "true",
                    "feature.node.kubernetes.io/kernel-config.NO_HZ_IDLE": "true",
                    "feature.node.kubernetes.io/kernel-version.full": "5.15.0-134-generic",
                    "feature.node.kubernetes.io/kernel-version.major": "5",
                    "feature.node.kubernetes.io/kernel-version.minor": "15",
                    "feature.node.kubernetes.io/kernel-version.revision": "0",
                    "feature.node.kubernetes.io/memory-swap": "true",
                    "feature.node.kubernetes.io/pci-10de.present": "true",
                    "feature.node.kubernetes.io/pci-1234.present": "true",
                    "feature.node.kubernetes.io/pci-1af4.present": "true",
                    "feature.node.kubernetes.io/system-os_release.ID": "ubuntu",
                    "feature.node.kubernetes.io/system-os_release.VERSION_ID": "22.04",
                    "feature.node.kubernetes.io/system-os_release.VERSION_ID.major": "22",
                    "feature.node.kubernetes.io/system-os_release.VERSION_ID.minor": "04",
                    "kubernetes.io/arch": "amd64",
                    "kubernetes.io/hostname": "nori",
                    "kubernetes.io/os": "linux",
                    "node-role.kubernetes.io/control-plane": "true",
                    "node-role.kubernetes.io/etcd": "true",
                    "node-role.kubernetes.io/master": "true",
                    "node.kubernetes.io/instance-type": "rke2",
                    "nvidia.com/cuda.driver-version.full": "550.90.07",
                    "nvidia.com/cuda.driver-version.major": "550",
                    "nvidia.com/cuda.driver-version.minor": "90",
                    "nvidia.com/cuda.driver-version.revision": "07",
                    "nvidia.com/cuda.driver.major": "550",
                    "nvidia.com/cuda.driver.minor": "90",
                    "nvidia.com/cuda.driver.rev": "07",
                    "nvidia.com/cuda.runtime-version.full": "12.4",
                    "nvidia.com/cuda.runtime-version.major": "12",
                    "nvidia.com/cuda.runtime-version.minor": "4",
                    "nvidia.com/cuda.runtime.major": "12",
                    "nvidia.com/cuda.runtime.minor": "4",
                    "nvidia.com/gfd.timestamp": "1742417103",
                    "nvidia.com/gpu-driver-upgrade-state": "upgrade-done",
                    "nvidia.com/gpu.compute.major": "8",
                    "nvidia.com/gpu.compute.minor": "6",
                    "nvidia.com/gpu.count": "1",
                    "nvidia.com/gpu.deploy.container-toolkit": "true",
                    "nvidia.com/gpu.deploy.dcgm": "true",
                    "nvidia.com/gpu.deploy.dcgm-exporter": "true",
                    "nvidia.com/gpu.deploy.device-plugin": "true",
                    "nvidia.com/gpu.deploy.driver": "pre-installed",
                    "nvidia.com/gpu.deploy.gpu-feature-discovery": "true",
                    "nvidia.com/gpu.deploy.node-status-exporter": "true",
                    "nvidia.com/gpu.deploy.operator-validator": "true",
                    "nvidia.com/gpu.family": "ampere",
                    "nvidia.com/gpu.machine": "VCG",
                    "nvidia.com/gpu.memory": "4096",
                    "nvidia.com/gpu.mode": "graphics",
                    "nvidia.com/gpu.present": "true",
                    "nvidia.com/gpu.product": "NVIDIA-A16-4Q",
                    "nvidia.com/gpu.replicas": "1",
                    "nvidia.com/gpu.sharing-strategy": "none",
                    "nvidia.com/mig.capable": "false",
                    "nvidia.com/mig.strategy": "single",
                    "nvidia.com/mps.capable": "false",
                    "nvidia.com/vgpu.host-driver-branch": "r551_40",
                    "nvidia.com/vgpu.host-driver-version": "550.54.16",
                    "nvidia.com/vgpu.present": "true"
                },
                "name": "nori",
                "resourceVersion": "37350",
                "uid": "a585cb64-68e9-4ee3-804e-754d7c13bbb1"
            },
            "spec": {
                "podCIDR": "10.42.0.0/24",
                "podCIDRs": [
                    "10.42.0.0/24"
                ],
                "providerID": "rke2://nori"
            },
            "status": {
                "addresses": [
                    {
                        "address": "0.202.61.70",
                        "type": "InternalIP"
                    },
                    {
                        "address": "nori",
                        "type": "Hostname"
                    }
                ],
                "allocatable": {
                    "cpu": "2",
                    "ephemeral-storage": "75959683218",
                    "hugepages-2Mi": "0",
                    "memory": "16367668Ki",
                    "nvidia.com/gpu": "1",
                    "pods": "110"
                },
                "capacity": {
                    "cpu": "2",
                    "ephemeral-storage": "78083556Ki",
                    "hugepages-2Mi": "0",
                    "memory": "16367668Ki",
                    "nvidia.com/gpu": "1",
                    "pods": "110"
                },
                "conditions": [
                    {
                        "lastHeartbeatTime": "2025-03-19T20:41:16Z",
                        "lastTransitionTime": "2025-03-19T20:41:16Z",
                        "message": "Flannel is running on this node",
                        "reason": "FlannelIsUp",
                        "status": "False",
                        "type": "NetworkUnavailable"
                    },
                    {
                        "lastHeartbeatTime": "2025-03-19T23:16:34Z",
                        "lastTransitionTime": "2025-03-19T20:41:04Z",
                        "message": "Node is a voting member of the etcd cluster",
                        "reason": "MemberNotLearner",
                        "status": "True",
                        "type": "EtcdIsVoter"
                    },
                    {
                        "lastHeartbeatTime": "2025-03-19T23:18:09Z",
                        "lastTransitionTime": "2025-03-19T20:40:47Z",
                        "message": "kubelet has sufficient memory available",
                        "reason": "KubeletHasSufficientMemory",
                        "status": "False",
                        "type": "MemoryPressure"
                    },
                    {
                        "lastHeartbeatTime": "2025-03-19T23:18:09Z",
                        "lastTransitionTime": "2025-03-19T20:40:47Z",
                        "message": "kubelet has no disk pressure",
                        "reason": "KubeletHasNoDiskPressure",
                        "status": "False",
                        "type": "DiskPressure"
                    },
                    {
                        "lastHeartbeatTime": "2025-03-19T23:18:09Z",
                        "lastTransitionTime": "2025-03-19T20:40:47Z",
                        "message": "kubelet has sufficient PID available",
                        "reason": "KubeletHasSufficientPID",
                        "status": "False",
                        "type": "PIDPressure"
                    },
                    {
                        "lastHeartbeatTime": "2025-03-19T23:18:09Z",
                        "lastTransitionTime": "2025-03-19T20:41:10Z",
                        "message": "kubelet is posting ready status",
                        "reason": "KubeletReady",
                        "status": "True",
                        "type": "Ready"
                    }
                ],
                "daemonEndpoints": {
                    "kubeletEndpoint": {
                        "Port": 10250
                    }
                },
                "images": [
                    {
                        "names": [
                            "docker.io/rancher/nginx-ingress-controller@sha256:9fa6a8fd38dc6ffcc269f82d18146c16a1f1ba8a9e1878312d42bf3602519a77",
                            "docker.io/rancher/nginx-ingress-controller:v1.12.0-hardened6"
                        ],
                        "sizeBytes": 298493685
                    },
                    {
                        "names": [
                            "docker.io/rancher/hardened-kubernetes@sha256:47061e09190e97b21dbe410dc6080fb58616467c5d68b93b1b8d29d0a1cb3ec4",
                            "docker.io/rancher/hardened-kubernetes:v1.31.6-rke2r1-build20250213"
                        ],
                        "sizeBytes": 228062944
                    },
                    {
                        "names": [
                            "nvcr.io/nvidia/cloud-native/k8s-driver-manager@sha256:b072c5793be65eee556eaff1b9cbbd115a1ef29982be95b2959adfcb4bc72382",
                            "nvcr.io/nvidia/cloud-native/k8s-driver-manager:v0.7.0"
                        ],
                        "sizeBytes": 225657726
                    },
                    {
                        "names": [
                            "nvcr.io/nvidia/gpu-operator@sha256:92f5262bb4934e0ea29eb10ec0ad4fc293164f2f2f94d48a935922791abbfdac",
                            "nvcr.io/nvidia/gpu-operator:v24.9.2"
                        ],
                        "sizeBytes": 221606384
                    },
                    {
                        "names": [
                            "docker.io/rancher/hardened-calico@sha256:30c7553a62147ce43bb00caf0ea2a95d40489edb1e3b904a6fc893f43e4f5f0d",
                            "docker.io/rancher/hardened-calico:v3.29.2-build20250218"
                        ],
                        "sizeBytes": 210583432
                    },
                    {
                        "names": [
                            "nvcr.io/nvidia/k8s-device-plugin@sha256:7089559ce6153018806857f5049085bae15b3bf6f1c8bd19d8b12f707d087dea",
                            "nvcr.io/nvidia/k8s-device-plugin:v0.17.0"
                        ],
                        "sizeBytes": 187560257
                    },
                    {
                        "names": [
                            "nvcr.io/nvidia/cloud-native/gpu-operator-validator@sha256:34eab99d7992a57c35803ec5e0afd538d16e997341e951fef4c4019afb08793e",
                            "nvcr.io/nvidia/cloud-native/gpu-operator-validator:v24.9.2"
                        ],
                        "sizeBytes": 183351646
                    },
                    {
                        "names": [
                            "nvcr.io/nvidia/k8s/container-toolkit@sha256:83a9f9fe948bd82358e53ed09470e2500ff689ce26241d76b444ec6b71792dcc",
                            "nvcr.io/nvidia/k8s/container-toolkit:v1.17.4-ubuntu20.04"
                        ],
                        "sizeBytes": 132859723
                    },
                    {
                        "names": [
                            "nvcr.io/nvidia/k8s/dcgm-exporter@sha256:3d4e0dfa5fc4d7d12689d29fc6b56cd6c610750e8d187a393882e341fbba6c12",
                            "nvcr.io/nvidia/k8s/dcgm-exporter:3.3.9-3.6.1-ubuntu22.04"
                        ],
                        "sizeBytes": 127723011
                    },
                    {
                        "names": [
                            "docker.io/rancher/rke2-runtime@sha256:9f4d7e28bf50c3343a6520b0a9c0660c4f33945ac7cd00c73a3b5c16069cfdad",
                            "docker.io/rancher/rke2-runtime:v1.31.6-rke2r1"
                        ],
                        "sizeBytes": 94555806
                    },
                    {
                        "names": [
                            "nvcr.io/nvidia/k8s/cuda-sample@sha256:79fa5da2e71ce9169d41b0a67f8575b8f713fd1fb3e6de306774fcfede3a4fe6",
                            "nvcr.io/nvidia/k8s/cuda-sample:vectoradd-cuda11.7.1-ubuntu20.04"
                        ],
                        "sizeBytes": 85614085
                    },
                    {
                        "names": [
                            "docker.io/rancher/hardened-flannel@sha256:c73c77d0a2ada7fe27218e1e610e171941d678ea15a63075ed35f31b9b19d508",
                            "docker.io/rancher/hardened-flannel:v0.26.4-build20250218"
                        ],
                        "sizeBytes": 81490879
                    },
                    {
                        "names": [
                            "docker.io/rancher/klipper-helm@sha256:d8aba471eb96967a3dfc66ef251c93ee5df8dac908459fbb9ed3e99ce0d5946f",
                            "docker.io/rancher/klipper-helm:v0.9.4-build20250113"
                        ],
                        "sizeBytes": 70422458
                    },
                    {
                        "names": [
                            "registry.k8s.io/nfd/node-feature-discovery@sha256:19ebca8b3804bfe2ee7324de4873875ab0a9112b51e0ace9dfd7c470beecf4a9",
                            "registry.k8s.io/nfd/node-feature-discovery:v0.16.6"
                        ],
                        "sizeBytes": 69405547
                    },
                    {
                        "names": [
                            "docker.io/rancher/mirrored-sig-storage-snapshot-controller@sha256:1cda6e2aeae92ad55aa33459b3903850010afce8e12c43842d5a98a0d620c159",
                            "docker.io/rancher/mirrored-sig-storage-snapshot-controller:v8.2.0"
                        ],
                        "sizeBytes": 29129582
                    },
                    {
                        "names": [
                            "docker.io/rancher/hardened-coredns@sha256:0611fc248207de233fc12358336396c936674f75326fa32841f8ebd22acdb3b8",
                            "docker.io/rancher/hardened-coredns:v1.12.0-build20241126"
                        ],
                        "sizeBytes": 27603460
                    },
                    {
                        "names": [
                            "docker.io/rancher/mirrored-ingress-nginx-kube-webhook-certgen@sha256:5709ba25ed42d84d0978cac62bb10156a1b1a6f06d32437470a35156cd07efe1",
                            "docker.io/rancher/mirrored-ingress-nginx-kube-webhook-certgen:v1.5.0"
                        ],
                        "sizeBytes": 26958501
                    },
                    {
                        "names": [
                            "docker.io/rancher/rke2-cloud-provider@sha256:67af052d966889717f54361e06a7129a882bb8790dc99ddd53cf49c2d2d7021f",
                            "docker.io/rancher/rke2-cloud-provider:v1.31.2-0.20241016053446-0955fa330f90-build20241016"
                        ],
                        "sizeBytes": 22079096
                    },
                    {
                        "names": [
                            "docker.io/rancher/hardened-k8s-metrics-server@sha256:ed8d96fd8b628ca98b650c0de6eee551d36f9e8cb90d0b01dff186df5c5befbc",
                            "docker.io/rancher/hardened-k8s-metrics-server:v0.7.2-build20250110"
                        ],
                        "sizeBytes": 18761838
                    },
                    {
                        "names": [
                            "docker.io/rancher/hardened-etcd@sha256:f9f767e3914db122bac5f822f5a6f95f15273ce960be09e5b07736616d50d35c",
                            "docker.io/rancher/hardened-etcd:v3.5.18-k3s1-build20250210"
                        ],
                        "sizeBytes": 17403640
                    },
                    {
                        "names": [
                            "docker.io/rancher/hardened-cluster-autoscaler@sha256:a3bcfb6934664491124894597d664ea0c3808b493ae2f15bf32be925b7ece08a",
                            "docker.io/rancher/hardened-cluster-autoscaler:v1.9.0-build20241126"
                        ],
                        "sizeBytes": 13693474
                    },
                    {
                        "names": [
                            "docker.io/rancher/mirrored-pause@sha256:74c4244427b7312c5b901fe0f67cbc53683d06f4f24c6faee65d4182bf0fa893",
                            "docker.io/rancher/mirrored-pause:3.6"
                        ],
                        "sizeBytes": 301463
                    }
                ],
                "nodeInfo": {
                    "architecture": "amd64",
                    "bootID": "166089b3-8e2e-4dd2-a592-3db929b191f8",
                    "containerRuntimeVersion": "containerd://2.0.2-k3s2",
                    "kernelVersion": "5.15.0-134-generic",
                    "kubeProxyVersion": "v1.31.6+rke2r1",
                    "kubeletVersion": "v1.31.6+rke2r1",
                    "machineID": "e4fd015acc30409483ecc8423273f476",
                    "operatingSystem": "linux",
                    "osImage": "Ubuntu 22.04.5 LTS",
                    "systemUUID": "bf296dd3-ddb6-4f97-b9f7-e18daf871170"
                },
                "runtimeHandlers": [
                    {
                        "features": {
                            "recursiveReadOnlyMounts": false,
                            "userNamespaces": false
                        },
                        "name": "runhcs-wcow-process"
                    },
                    {
                        "features": {
                            "recursiveReadOnlyMounts": true,
                            "userNamespaces": true
                        },
                        "name": "runc"
                    },
                    {
                        "features": {
                            "recursiveReadOnlyMounts": true,
                            "userNamespaces": true
                        },
                        "name": ""
                    },
                    {
                        "features": {
                            "recursiveReadOnlyMounts": true,
                            "userNamespaces": true
                        },
                        "name": "nvidia"
                    },
                    {
                        "features": {
                            "recursiveReadOnlyMounts": true,
                            "userNamespaces": true
                        },
                        "name": "nvidia-cdi"
                    }
                ]
            }
        }
    ],
    "kind": "List",
    "metadata": {
        "resourceVersion": ""
    }
}
`

func TestCheckNodesReady(t *testing.T) {
	log.InitTracer(nil)
	defer log.FinishTracer()
	ctx := log.StartTestSpan(context.Background())

	client := pc.DummyClient{}

	tests := []struct {
		out         string
		expReady    int
		expNotReady int
	}{{
		`NAME                       STATUS   ROLES                  AGE   VERSION
    k3d-reservable0-server-0   Ready    control-plane,master   43s   v1.27.4+k3s1
`, 1, 0,
	}, {
		`NAME                                STATUS   ROLES   AGE    VERSION
        aks-agentpool-40426869-vmss000002   Ready    agent   231d   v1.25.11
        aks-agentpool-40426869-vmss000007   Ready    agent   231d   v1.25.11
        aks-agentpool-40426869-vmss00000a   Ready    agent   124d   v1.25.11
        aks-agentpool-40426869-vmss00000b   Ready    agent   34d    v1.25.15
`, 4, 0,
	}, {
		"", 0, 0,
	}, {
		`NAME                       STATUS   ROLES                  AGE   VERSION
`, 0, 0,
	}, {
		`NAME                                STATUS   ROLES   AGE    VERSION
        aks-agentpool-40426869-vmss000002   Ready    agent   231d   v1.25.11
        aks-agentpool-40426869-vmss000007   Error    agent   231d   v1.25.11
        aks-agentpool-40426869-vmss00000a   Loading    agent   124d   v1.25.11
        aks-agentpool-40426869-vmss00000b   Offline    agent   34d    v1.25.15`, 1, 3,
	}}
	ci := &edgeproto.ClusterInst{}
	for _, test := range tests {
		client.Out = test.out
		r, nr, err := CheckNodesReady(ctx, &client, ci)
		require.Nil(t, err, test.out)
		require.Equal(t, test.expReady, r, test.out)
		require.Equal(t, test.expNotReady, nr, test.out)
	}
}
