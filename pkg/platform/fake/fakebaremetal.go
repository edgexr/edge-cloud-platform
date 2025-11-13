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

package fake

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/edgexr/edge-cloud-platform/api/edgeproto"
	"github.com/edgexr/edge-cloud-platform/pkg/cloudcommon"
	"github.com/edgexr/edge-cloud-platform/pkg/k8smgmt"
	"github.com/edgexr/edge-cloud-platform/pkg/platform"
	"github.com/edgexr/edge-cloud-platform/pkg/platform/pc"
	"github.com/edgexr/edge-cloud-platform/test/testutil"
)

type PlatformBareMetal struct {
	Platform
}

func NewPlatformBareMetal() platform.Platform {
	return &PlatformBareMetal{}
}

func (s *PlatformBareMetal) GetFeatures() *edgeproto.PlatformFeatures {
	features := s.Platform.GetFeatures()
	features.PlatformType = platform.PlatformTypeFakeBareMetal
	features.SupportsMultiTenantCluster = true
	features.SupportsKubernetesOnly = true
	features.KubernetesRequiresWorkerNodes = true
	features.IpAllocatedPerService = true
	features.RequiresCrmOffEdge = true
	features.UsesIngress = true
	return features
}

func (s *PlatformBareMetal) GatherCloudletInfo(ctx context.Context, info *edgeproto.CloudletInfo) error {
	s.Platform.GatherCloudletInfo(ctx, info)
	info.NodePools = testutil.CloudletInfoData()[4].NodePools
	return nil
}

func (s *PlatformBareMetal) CreateClusterInst(ctx context.Context, clusterInst *edgeproto.ClusterInst, updateCallback edgeproto.CacheUpdateCallback, timeout time.Duration) (map[string]string, error) {
	annotations, err := s.Platform.CreateClusterInst(ctx, clusterInst, updateCallback, timeout)
	if err != nil {
		return nil, err
	}
	client := &pc.TestClient{}
	client.OutputResponder = func(cmd string) (string, error) {
		if strings.Contains(cmd, fmt.Sprintf("%s get deployment %s -o json", k8smgmt.IngressNginxNamespace, "ingress-nginx-controller")) {
			return getIngressNginxDeployment, nil
		}
		return "", nil
	}
	names := k8smgmt.KconfNames{
		KconfName: "kubeconfig",
		KconfArg:  "--kubeconfig=kubeconfig",
	}
	// exercise ingress-nginx code
	ops := []k8smgmt.IngressNginxOp{}
	if _, ok := clusterInst.Annotations[cloudcommon.AnnotationControlVIP]; ok {
		// cloudlet has FloatingVIPs defined,
		// exercise ensure load balancer code
		ops = append(ops, k8smgmt.WithIngressNginxEnsureLB(s, clusterInst.Key))
	}
	err = k8smgmt.SetupIngressNginx(ctx, client, &names, &clusterInst.CloudletKey, s.Platform.platformConfig.ProxyCertsCache, "foo", k8smgmt.RefreshCertsOpts{}, nil, updateCallback, ops...)
	if err != nil {
		return nil, fmt.Errorf("failed to setup ingress-nginx: %s", err)
	}
	return annotations, nil
}

func (s *PlatformBareMetal) EnsureLoadBalancer(ctx context.Context, cloudletKey edgeproto.CloudletKey, clusterKey edgeproto.ClusterKey, lbKey edgeproto.LoadBalancerKey) (*edgeproto.LoadBalancer, error) {
	accessApi := s.Platform.platformConfig.AccessApi
	return accessApi.ReserveLoadBalancerIP(ctx, cloudletKey, clusterKey, lbKey)
}

func (s *PlatformBareMetal) DeleteLoadBalancer(ctx context.Context, cloudletKey edgeproto.CloudletKey, clusterKey edgeproto.ClusterKey, lbKey edgeproto.LoadBalancerKey) error {
	accessApi := s.Platform.platformConfig.AccessApi
	return accessApi.FreeLoadBalancerIP(ctx, cloudletKey, clusterKey, lbKey)
}

var getIngressNginxDeployment = `
{
    "apiVersion": "apps/v1",
    "kind": "Deployment",
    "metadata": {
        "annotations": {
            "deployment.kubernetes.io/revision": "3",
            "linkerd.io/inject": "disabled",
            "meta.helm.sh/release-name": "ingress-nginx",
            "meta.helm.sh/release-namespace": "ingress-nginx"
        },
        "creationTimestamp": "2025-02-10T19:43:38Z",
        "generation": 3,
        "labels": {
            "app.kubernetes.io/component": "controller",
            "app.kubernetes.io/instance": "ingress-nginx",
            "app.kubernetes.io/managed-by": "Helm",
            "app.kubernetes.io/name": "ingress-nginx",
            "app.kubernetes.io/part-of": "ingress-nginx",
            "app.kubernetes.io/version": "1.11.3",
            "helm.sh/chart": "ingress-nginx-4.11.3"
        },
        "name": "ingress-nginx-controller",
        "namespace": "ingress-nginx",
        "resourceVersion": "179015984",
        "uid": "c5aacc22-6302-477a-b786-3b70d8539b18"
    },
    "spec": {
        "progressDeadlineSeconds": 600,
        "replicas": 1,
        "revisionHistoryLimit": 10,
        "selector": {
            "matchLabels": {
                "app.kubernetes.io/component": "controller",
                "app.kubernetes.io/instance": "ingress-nginx",
                "app.kubernetes.io/name": "ingress-nginx"
            }
        },
        "strategy": {
            "rollingUpdate": {
                "maxSurge": "25%",
                "maxUnavailable": "25%"
            },
            "type": "RollingUpdate"
        },
        "template": {
            "metadata": {
                "creationTimestamp": null,
                "labels": {
                    "app.kubernetes.io/component": "controller",
                    "app.kubernetes.io/instance": "ingress-nginx",
                    "app.kubernetes.io/managed-by": "Helm",
                    "app.kubernetes.io/name": "ingress-nginx",
                    "app.kubernetes.io/part-of": "ingress-nginx",
                    "app.kubernetes.io/version": "1.11.3",
                    "helm.sh/chart": "ingress-nginx-4.11.3"
                }
            },
            "spec": {
                "containers": [
                    {
                        "args": [
                            "/nginx-ingress-controller",
                            "--publish-service=$(POD_NAMESPACE)/ingress-nginx-controller",
                            "--election-id=ingress-nginx-leader",
                            "--controller-class=k8s.io/ingress-nginx",
                            "--ingress-class=nginx",
                            "--configmap=$(POD_NAMESPACE)/ingress-nginx-controller",
                            "--tcp-services-configmap=$(POD_NAMESPACE)/ingress-nginx-tcp",
                            "--validating-webhook=:8443",
                            "--validating-webhook-certificate=/usr/local/certificates/cert",
                            "--validating-webhook-key=/usr/local/certificates/key",
                            "--enable-metrics=false",
                            "--enable-ssl-passthrough"
                        ],
                        "env": [
                            {
                                "name": "POD_NAME",
                                "valueFrom": {
                                    "fieldRef": {
                                        "apiVersion": "v1",
                                        "fieldPath": "metadata.name"
                                    }
                                }
                            },
                            {
                                "name": "POD_NAMESPACE",
                                "valueFrom": {
                                    "fieldRef": {
                                        "apiVersion": "v1",
                                        "fieldPath": "metadata.namespace"
                                    }
                                }
                            },
                            {
                                "name": "LD_PRELOAD",
                                "value": "/usr/local/lib/libmimalloc.so"
                            }
                        ],
                        "image": "registry.k8s.io/ingress-nginx/controller:v1.11.3@sha256:d56f135b6462cfc476447cfe564b83a45e8bb7da2774963b00d12161112270b7",
                        "imagePullPolicy": "IfNotPresent",
                        "lifecycle": {
                            "preStop": {
                                "exec": {
                                    "command": [
                                        "/wait-shutdown"
                                    ]
                                }
                            }
                        },
                        "livenessProbe": {
                            "failureThreshold": 5,
                            "httpGet": {
                                "path": "/healthz",
                                "port": 10254,
                                "scheme": "HTTP"
                            },
                            "initialDelaySeconds": 10,
                            "periodSeconds": 10,
                            "successThreshold": 1,
                            "timeoutSeconds": 1
                        },
                        "name": "controller",
                        "ports": [
                            {
                                "containerPort": 80,
                                "name": "http",
                                "protocol": "TCP"
                            },
                            {
                                "containerPort": 443,
                                "name": "https",
                                "protocol": "TCP"
                            },
                            {
                                "containerPort": 8443,
                                "name": "webhook",
                                "protocol": "TCP"
                            },
                            {
                                "containerPort": 37001,
                                "name": "37001-tcp",
                                "protocol": "TCP"
                            },
                            {
                                "containerPort": 41001,
                                "name": "41001-tcp",
                                "protocol": "TCP"
                            },
                            {
                                "containerPort": 50051,
                                "name": "50051-tcp",
                                "protocol": "TCP"
                            },
                            {
                                "containerPort": 52001,
                                "name": "52001-tcp",
                                "protocol": "TCP"
                            },
                            {
                                "containerPort": 53001,
                                "name": "53001-tcp",
                                "protocol": "TCP"
                            },
                            {
                                "containerPort": 6080,
                                "name": "6080-tcp",
                                "protocol": "TCP"
                            }
                        ],
                        "readinessProbe": {
                            "failureThreshold": 3,
                            "httpGet": {
                                "path": "/healthz",
                                "port": 10254,
                                "scheme": "HTTP"
                            },
                            "initialDelaySeconds": 10,
                            "periodSeconds": 10,
                            "successThreshold": 1,
                            "timeoutSeconds": 1
                        },
                        "resources": {
                            "requests": {
                                "cpu": "100m",
                                "memory": "90Mi"
                            }
                        },
                        "securityContext": {
                            "allowPrivilegeEscalation": false,
                            "capabilities": {
                                "add": [
                                    "NET_BIND_SERVICE"
                                ],
                                "drop": [
                                    "ALL"
                                ]
                            },
                            "readOnlyRootFilesystem": false,
                            "runAsNonRoot": true,
                            "runAsUser": 101,
                            "seccompProfile": {
                                "type": "RuntimeDefault"
                            }
                        },
                        "terminationMessagePath": "/dev/termination-log",
                        "terminationMessagePolicy": "File",
                        "volumeMounts": [
                            {
                                "mountPath": "/usr/local/certificates/",
                                "name": "webhook-cert",
                                "readOnly": true
                            }
                        ]
                    }
                ],
                "dnsPolicy": "ClusterFirst",
                "nodeSelector": {
                    "kubernetes.io/os": "linux"
                },
                "restartPolicy": "Always",
                "schedulerName": "default-scheduler",
                "securityContext": {},
                "serviceAccount": "ingress-nginx",
                "serviceAccountName": "ingress-nginx",
                "terminationGracePeriodSeconds": 300,
                "volumes": [
                    {
                        "name": "webhook-cert",
                        "secret": {
                            "defaultMode": 420,
                            "secretName": "ingress-nginx-admission"
                        }
                    }
                ]
            }
        }
    },
    "status": {
        "availableReplicas": 1,
        "conditions": [
            {
                "lastTransitionTime": "2025-02-10T19:43:59Z",
                "lastUpdateTime": "2025-02-10T19:43:59Z",
                "message": "Deployment has minimum availability.",
                "reason": "MinimumReplicasAvailable",
                "status": "True",
                "type": "Available"
            },
            {
                "lastTransitionTime": "2025-02-10T19:43:38Z",
                "lastUpdateTime": "2025-02-10T20:26:34Z",
                "message": "ReplicaSet \"ingress-nginx-controller-dfcc49c56\" has successfully progressed.",
                "reason": "NewReplicaSetAvailable",
                "status": "True",
                "type": "Progressing"
            }
        ],
        "observedGeneration": 3,
        "readyReplicas": 1,
        "replicas": 1,
        "updatedReplicas": 1
    }
}
`
