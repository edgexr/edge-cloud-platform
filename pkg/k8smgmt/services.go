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
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/edgexr/edge-cloud-platform/api/distributed_match_engine"
	"github.com/edgexr/edge-cloud-platform/api/edgeproto"
	"github.com/edgexr/edge-cloud-platform/pkg/cloudcommon"
	"github.com/edgexr/edge-cloud-platform/pkg/log"
	ssh "github.com/edgexr/golang-ssh"
	v1 "k8s.io/api/core/v1"
)

type svcItems struct {
	Items []v1.Service `json:"items"`
}

func GetServices(ctx context.Context, client ssh.Client, names *KubeNames, ops ...GetObjectsOp) ([]v1.Service, error) {
	log.SpanLog(ctx, log.DebugLevelInfra, "get services", "kconf", names.KconfName)
	if names.DeploymentType == cloudcommon.DeploymentTypeDocker {
		// just populate the service names
		svcs := svcItems{}
		for _, sn := range names.ServiceNames {
			item := v1.Service{}
			item.Name = sn
			svcs.Items = append(svcs.Items, item)
		}
		return svcs.Items, nil
	}
	return GetKubeServices(ctx, client, names.GetKConfNames(), ops...)
}

func GetKubeServices(ctx context.Context, client ssh.Client, names *KconfNames, ops ...GetObjectsOp) ([]v1.Service, error) {
	svcs := svcItems{}
	err := GetObjects(ctx, client, names, "svc", &svcs, ops...)
	if err != nil {
		return nil, err
	}
	opts := GetObjectsOptions{}
	for _, op := range ops {
		op(&opts)
	}
	items := svcs.Items
	if opts.loadBalancersOnly {
		var filtered []v1.Service
		for _, svc := range items {
			if svc.Spec.Type == v1.ServiceTypeLoadBalancer {
				filtered = append(filtered, svc)
			}
		}
		items = filtered
	}
	return items, nil
}

type PortProto string

func GetSvcPortProto(port int32, protocol string) PortProto {
	protocol = strings.ToLower(protocol)
	if protocol == "http" {
		protocol = "tcp"
	}
	return PortProto(fmt.Sprintf("%d/%s", port, protocol))
}

func GetSvcPortLProto(port int32, protocol distributed_match_engine.LProto) PortProto {
	proto, err := edgeproto.LProtoStr(protocol)
	if err != nil {
		proto = "unknown"
	}
	if proto == "http" {
		proto = "tcp"
	}
	return GetSvcPortProto(port, proto)
}

type AppServices struct {
	// List of AppInst services
	Services []*v1.Service
	// Map of port to service (may include a service multiple times)
	SvcsByPort map[PortProto]*v1.Service
	// AppInst ports for which no service was found
	PortsWithoutServices []string
}

func getServiceID(svc *v1.Service) string {
	return svc.Name + "/" + svc.Namespace
}

// GetAppServices gets load balancer services corresponding to an
// AppInst by the AppInst's ports. This is used to get load balancers
// to register DNS entries for, and to determine the service to
// associate with ingress objects.
func GetAppServices(ctx context.Context, client ssh.Client, names *KubeNames, mappedPorts []edgeproto.InstPort, svcsOps ...GetObjectsOp) (*AppServices, error) {
	// App can only deploy to a single namespace, search that namespace only
	svcsOps = append(svcsOps, WithObjectNamespace(names.InstanceNamespace))
	svcs, err := GetKubeServices(ctx, client, names.GetKConfNames(), svcsOps...)
	if err != nil {
		return nil, err
	}

	// There is no reliable way to match a load balancer/cluster IP service
	// with the AppInst the deployed it, given the ways in which we have
	// layers of manifests, helm charts, and operators. Consider an AppInst
	// with a custom manifest that deploys an operator, and the operator
	// deploys both another manifest and a helm chart.
	// For AppInsts with manifests, we label the objects in the manifest
	// with the AppInst name. For helm charts, helm annotates the services
	// with the helm release name. However because of the layering, for
	// example you can have a helm chart that deploys another helm chart,
	// services will have different annotations than expected. So it's not
	// possible to filter out services just based on labels/annotations.
	// The only guarantee we have is if the user specified for a specific
	// port, the service name that it must match.

	// Previously we filtered by namespace, but now we allow multiple
	// apps per namespace. We still only allow an App to deploy to a
	// single namespace, so we can limit our search to that namespace.

	// track filtered out services for logging
	filteredByHeadless := []string{}
	filteredByAppInstLabel := []string{}
	filteredByPortServiceStr := []string{}

	// Determine services by the ports they provide
	reqdPorts := map[PortProto]*edgeproto.InstPort{}
	portsList := []string{}
	for _, port := range mappedPorts {
		if port.InternalVisOnly {
			continue
		}
		pp := GetSvcPortLProto(port.InternalPort, port.Proto)
		reqdPorts[pp] = &port
		// for logging
		ppStr := string(pp)
		if port.ServiceName != "" {
			ppStr += "/svcname=" + port.ServiceName
		}
		portsList = append(portsList, ppStr)
	}
	// Match services to required ports
	appServices := &AppServices{
		SvcsByPort: map[PortProto]*v1.Service{},
	}
	conflictsByPort := map[PortProto][]string{}
	addedServices := map[string]struct{}{}
	for _, svc := range svcs {
		if svc.Spec.ClusterIP == "None" {
			// skip headless services that are meant for accessing
			// pods directly via kube DNS names.
			filteredByHeadless = append(filteredByHeadless, getServiceID(&svc))
			continue
		}
		if svc.GetNamespace() == "kube-system" || svc.GetNamespace() == IngressNginxNamespace || names.InstanceNamespace != svc.GetNamespace() {
			// skip system services and mismatched namespaces
			continue
		}
		// Try to eliminate services based on labels that indicate they
		// are from a different AppInst.
		if labels := svc.GetLabels(); labels != nil {
			// If the service has an AppInst label, we can filter it if
			// it belongs to a different AppInst.
			// This filtering is valid because it is not subject to layering,
			// i.e. an operator or helm chart will never apply these labels.
			// Note that we can only use these to filter, not match, because
			// layering may create a service without these labels.
			aiName, hasAiName := labels[AppInstNameLabel]
			aiOrg, hasAiOrg := labels[AppInstOrgLabel]
			if hasAiName && hasAiOrg && (aiName != names.AppInstName || aiOrg != names.AppInstOrg) {
				filteredByAppInstLabel = append(filteredByAppInstLabel, getServiceID(&svc))
				continue
			}
		}
		for _, port := range svc.Spec.Ports {
			proto := string(port.Protocol)
			if proto == "" {
				proto = "tcp"
			}
			pp := GetSvcPortProto(port.Port, proto)
			if instPort, ok := reqdPorts[pp]; ok {
				if instPort.ServiceName != "" && !strings.Contains(svc.Name, instPort.ServiceName) {
					// specified service name substring for port doesn't match
					filteredByPortServiceStr = append(filteredByPortServiceStr, getServiceID(&svc)+fmt.Sprintf(":%d", port.Port))
					continue
				}
				if ss, found := appServices.SvcsByPort[pp]; found {
					// if it's not the same service then it's ambiguous
					// which service to associate with the AppInst port.
					if svc.Name != ss.Name || svc.Namespace != ss.Namespace {
						conflictsByPort[pp] = append(conflictsByPort[pp], getServiceID(&svc))
					}
					continue
				} else {
					appServices.SvcsByPort[pp] = &svc
					conflictsByPort[pp] = []string{getServiceID(&svc)}
				}
				svcID := getServiceID(&svc)
				if _, found := addedServices[svcID]; !found {
					addedServices[svcID] = struct{}{}
					appServices.Services = append(appServices.Services, &svc)
				}
			}
		}
	}
	portsWithoutSvcs := []string{}
	for pp, _ := range reqdPorts {
		if _, found := appServices.SvcsByPort[pp]; !found {
			portsWithoutSvcs = append(portsWithoutSvcs, string(pp))
		}
	}
	appServices.PortsWithoutServices = portsWithoutSvcs

	log.SpanLog(ctx, log.DebugLevelInfra, "GetAppServices", "app", names.AppName, "appinst", names.AppInstName, "helmAppName", names.HelmAppName, "namespace", names.InstanceNamespace, "ports", portsList, "filteredByHeadless", filteredByHeadless, "filteredByAppInstLabel", filteredByAppInstLabel, "filteredByPortServiceStr", filteredByPortServiceStr, "addedServices", addedServices, "missingPorts", portsWithoutSvcs, "conflicts", conflictsByPort)

	conflicts := []string{}
	for pp, svcs := range conflictsByPort {
		if len(svcs) > 1 {
			sort.Strings(svcs)
			conflicts = append(conflicts, fmt.Sprintf("port %s is served by services %s", pp, strings.Join(svcs, ", ")))
		}
	}
	if len(conflicts) > 0 {
		sort.Strings(conflicts)
		return nil, fmt.Errorf("failed to determine service for port, too many services found, please add svcname annotation to App.AccessPorts to resolve (i.e. \"tcp:5432:svcname={{.AppName}}{{.AppVers}}\"): %s", strings.Join(conflicts, "; "))
	}
	return appServices, nil
}

func WaitForAppLBServices(ctx context.Context, client ssh.Client, names *KubeNames, mappedPorts []edgeproto.InstPort) (*AppServices, error) {
	var appServices *AppServices
	var err error
	maxTries := 50
	svcsOps := []GetObjectsOp{
		WithLoadBalancersOnly(),
	}
	for i := 0; ; i++ {
		log.SpanLog(ctx, log.DebugLevelInfra, "getting AppInst load balancers", "appinst", names.AppInstName)
		appServices, err = GetAppServices(ctx, client, names, mappedPorts, svcsOps...)
		if err != nil {
			return nil, err
		}
		if appServices == nil {
			return nil, fmt.Errorf("no services found for AppInst %s", names.AppInstName)
		}
		if len(appServices.PortsWithoutServices) == 0 {
			return appServices, nil
		}
		if i > maxTries {
			return nil, fmt.Errorf("timed out waiting for AppInst services, ports without services: %s", strings.Join(appServices.PortsWithoutServices, ", "))
		}
		log.SpanLog(ctx, log.DebugLevelInfra, "waiting for AppInst load balancers", "appinst", names.AppInstName, "portsWithoutSvcs", appServices.PortsWithoutServices)
		time.Sleep(3 * time.Second)
	}
}

/*
	if annotations := svc.GetAnnotations(); annotations != nil {
		// If AppInst is deployed via helm, services should have
		// helm release name annotation.
		helmReleaseName, ok := annotations["meta.helm.sh/release-name"]
		helmReleaseNamespace, ok2 := annotations["meta.helm.sh/release-namespace"]
		ns := names.InstanceNamespace
		if ns == "" {
			ns = DefaultNamespace
		}
		if ok && ok2 && (names.DeploymentType != cloudcommon.DeploymentTypeHelm || names.HelmAppName != helmReleaseName || ns != helmReleaseNamespace) {
			// non-matching helm service
			filteredByHelmAnnotation = append(filteredByHelmAnnotation, getServiceID(&svc))
			continue
		}
	}
*/
