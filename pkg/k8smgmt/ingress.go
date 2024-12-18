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

package k8smgmt

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/edgexr/edge-cloud-platform/api/distributed_match_engine"
	"github.com/edgexr/edge-cloud-platform/api/edgeproto"
	"github.com/edgexr/edge-cloud-platform/pkg/log"
	"github.com/edgexr/edge-cloud-platform/pkg/platform/pc"
	ssh "github.com/edgexr/golang-ssh"
	networkingv1 "k8s.io/api/networking/v1"
	"k8s.io/cli-runtime/pkg/printers"
)

const (
	IngressClassName         = "nginx"
	IngressExternalIPRetries = 60
	IngressExternalIPRetry   = 2 * time.Second
)

// CreateIngress creates an ingress to handle HTTP ports for the
// AppInst. We assume each AppInst has its own host name,
// and an AppInst does not need more than one host name.
// The AppInst host name must match the wildcard cert for the
// cluster/cloudlet.
// TODO: This assumes the AppInst is in a single namespace and
// creates a single ingress.
// For complex AppInsts (helm charts) it may need create an
// ingress per namespace if the AppInst uses multiple namespaces.
func CreateIngress(ctx context.Context, client ssh.Client, names *KubeNames, appInst *edgeproto.AppInst) (*networkingv1.Ingress, error) {
	log.SpanLog(ctx, log.DebugLevelInfra, "creating ingress", "appInst", appInst.Key.GetKeyString())

	ingressClass := IngressClassName

	ingress := networkingv1.Ingress{}
	ingress.APIVersion = "networking.k8s.io/v1"
	ingress.Kind = "Ingress"
	ingress.ObjectMeta.Name = names.AppInstName
	ingress.ObjectMeta.Labels = map[string]string{
		ConfigLabel: getConfigLabel(names),
	}
	ingress.Spec.IngressClassName = &ingressClass

	// The ingress object needs to know the name of the service
	// for each HTTP port. For something like a helm chart based
	// AppInst, it is hard to determine beforehand what services
	// will be deployed. Look up service name by port. If there
	// are port conflicts, user must specify the service name in the
	// App.AccessPorts spec.
	svcsOps := []GetObjectsOp{}
	if names.MultitenantNamespace != "" {
		svcsOps = append(svcsOps, WithObjectNamespace(names.MultitenantNamespace))
	}
	svcs, err := GetKubeServices(ctx, client, names.GetKConfNames(), svcsOps...)
	if err != nil {
		return nil, err
	}
	svcNameByPort := map[int32]string{}
	for _, svc := range svcs {
		// for non-multitenant, typically everything will be in the
		// default namespace, but there may be Helm charts or an
		// operator which installs in other namespaces.
		// The GetKubeServices command thus looks in all
		// namespaces. We should probably add a namespace annotation
		// to the ports spec so we know which namespace to look in.
		// For now at least skip kube-system and ingress-nginx
		// namespaces.
		if svc.GetNamespace() == "kube-system" || svc.GetNamespace() == IngressNginxNamespace {
			continue
		}
		for _, port := range svc.Spec.Ports {
			if port.Protocol != "TCP" {
				continue
			}
			svcNameByPort[port.Port] = svc.ObjectMeta.Name
		}
	}

	// Build the ingress object
	httpRule := networkingv1.HTTPIngressRuleValue{}
	hasTLS := false
	for _, port := range appInst.MappedPorts {
		if port.Proto != distributed_match_engine.LProto_L_PROTO_HTTP {
			continue
		}
		// we do not support ranges here
		if port.Tls {
			hasTLS = true
		}
		svcName := port.ServiceName
		if svcName == "" {
			svcName = svcNameByPort[port.InternalPort]
		}
		if svcName == "" {
			log.SpanLog(ctx, log.DebugLevelApi, "failed to find service for port", "port", port.InternalPort, "svcNameByPort", svcNameByPort)
			return nil, fmt.Errorf("failed to find service for port %s(%d)", port.Id, port.InternalPort)
		}
		path := networkingv1.HTTPIngressPath{}
		pathType := networkingv1.PathTypePrefix
		path.PathType = &pathType
		path.Path = port.PathPrefix
		if path.Path == "" {
			path.Path = "/"
		}
		path.Backend.Service = &networkingv1.IngressServiceBackend{
			Name: svcName,
			Port: networkingv1.ServiceBackendPort{
				Number: port.InternalPort,
			},
		}
		httpRule.Paths = append(httpRule.Paths, path)
	}
	hostName := appInst.Uri
	hostName = strings.TrimPrefix(hostName, "https://")
	hostName = strings.TrimPrefix(hostName, "http://")
	rule := networkingv1.IngressRule{}
	rule.Host = hostName
	rule.HTTP = &httpRule
	ingress.Spec.Rules = []networkingv1.IngressRule{rule}
	if hasTLS {
		// Note the TLS secret is left blank to allow nginx to use
		// the default SSL certificate.
		tls := networkingv1.IngressTLS{
			Hosts: []string{hostName},
		}
		ingress.Spec.TLS = append(ingress.Spec.TLS, tls)
		ingress.ObjectMeta.Labels["nginx.ingress.kubernetes.io/ssl-redirect"] = "true"
	}

	// Apply the ingress spec
	printer := &printers.YAMLPrinter{}
	buf := bytes.Buffer{}
	err = printer.PrintObj(&ingress, &buf)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal the ingress object to yaml, %s", err)
	}
	contents := buf.String()
	kconfArg := names.GetTenantKconfArg()
	configDir := getConfigDirName(names)
	fileName := configDir + "/" + getIngressManifestName(names)
	err = pc.WriteFile(client, fileName, contents, "k8s ingress", pc.NoSudo)
	if err != nil {
		return nil, err
	}
	cmd := fmt.Sprintf("kubectl %s apply -f %s", kconfArg, fileName)
	log.SpanLog(ctx, log.DebugLevelInfra, "applying ingress", "cmd", cmd)
	out, err := client.Output(cmd)
	if err != nil {
		return nil, fmt.Errorf("failed to apply ingress command %s: %s, %s", cmd, out, err)
	}
	log.SpanLog(ctx, log.DebugLevelInfra, "applied ingress")
	return &ingress, nil
}

func DeleteIngress(ctx context.Context, client ssh.Client, names *KubeNames, appInst *edgeproto.AppInst) error {
	kconfArg := names.GetTenantKconfArg()
	configDir := getConfigDirName(names)
	ingressFile := configDir + "/" + getIngressManifestName(names)
	cmd := fmt.Sprintf("kubectl %s delete -f %s", kconfArg, ingressFile)
	out, err := client.Output(cmd)
	if err != nil && !strings.Contains(out, "not found") {
		return fmt.Errorf("failed to delete ingress for %s: %s, %s", ingressFile, out, err)
	}
	err = pc.DeleteFile(client, ingressFile, pc.NoSudo)
	if err != nil {
		return fmt.Errorf("failed to delete ingress file %s, %s", ingressFile, err)
	}
	return nil
}

func getIngressManifestName(names *KubeNames) string {
	ingressFile := getIngressFileName(names)
	return ingressFile
}

type ingressItems struct {
	Items []networkingv1.Ingress `json:"items"`
}

func GetIngresses(ctx context.Context, client ssh.Client, names *KconfNames, ops ...GetObjectsOp) ([]networkingv1.Ingress, error) {
	data := &ingressItems{}
	err := GetObjects(ctx, client, names, "ingress", data, ops...)
	if err != nil {
		return nil, err
	}
	return data.Items, nil
}

func GetIngressExternalIP(ctx context.Context, client ssh.Client, names *KubeNames, name string) (string, error) {
	log.SpanLog(ctx, log.DebugLevelInfra, "get ingress IP", "kconf", names.KconfName)
	for i := 0; i < IngressExternalIPRetries; i++ {
		ingress := &networkingv1.Ingress{}
		err := GetObject(ctx, client, names.GetKConfNames(), "ingress", name, ingress, WithObjectNamespace(names.MultitenantNamespace))
		if err != nil {
			if errors.Is(err, ErrObjectNotFound) && i < 5 {
				// maybe not present yet, wait a bit
				time.Sleep(IngressExternalIPRetry)
				continue
			}
			return "", err
		}
		if len(ingress.Status.LoadBalancer.Ingress) > 0 {
			if ingress.Status.LoadBalancer.Ingress[0].IP != "" {
				return ingress.Status.LoadBalancer.Ingress[0].IP, nil
			}
		}
		time.Sleep(IngressExternalIPRetry)
	}
	return "", fmt.Errorf("unable to get external IP for ingress %s", name)
}
