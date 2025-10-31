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
	"slices"
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
	// with the AppInst that deployed it, given the ways in which we can have
	// layers of manifests, helm charts, and operators. Consider an AppInst
	// with a custom manifest that deploys an operator, and the operator
	// deploys both another manifest and a helm chart.
	// For AppInsts with manifests, we label the objects in the manifest
	// with the AppInst name. For helm charts, helm annotates the services
	// with the helm release name. However because of the layering, for
	// example you can have a helm chart that deploys another helm chart,
	// services will have different annotations than expected. So it's not
	// possible to match services just based on labels/annotations.
	// To resolve ambiguity we need the user to tell us, per exposed port
	// on the App, what the service name should be.

	// Previously we filtered by namespace, but now we allow multiple
	// apps per namespace. We do not support a single App to create
	// objects across multiple namespaces.

	// track filtered out services for logging
	filteredByHeadless := []string{}
	filteredByAppInstLabel := []string{}
	filteredByPortServiceStr := []string{}

	// Matche services to the exposed App ports
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
	type SvcMatch struct {
		svc       *v1.Service
		conflicts []string
	}
	svcsByPort := map[PortProto]*SvcMatch{}
	svcsByPortLabelMatch := map[PortProto]*SvcMatch{}
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
		// Special case: if the label matches, ignore other services
		// that do not have matching labels for the same port.
		// Note that it's still possible to have a conflict if there are
		// two matching labelled services for the same port.
		labelMatched := false
		if labels := svc.GetLabels(); labels != nil {
			// If the service has an AppInst label, we can filter it if
			// it belongs to a different AppInst.
			// This filtering is valid because it is not subject to layering,
			// i.e. an operator or helm chart will never apply these labels.
			aiName, hasAiName := labels[AppInstNameLabel]
			aiOrg, hasAiOrg := labels[AppInstOrgLabel]
			if hasAiName && hasAiOrg && (aiName != names.AppInstName || aiOrg != names.AppInstOrg) {
				filteredByAppInstLabel = append(filteredByAppInstLabel, getServiceID(&svc))
				continue
			}
			if hasAiName && hasAiOrg && aiName == names.AppInstName && aiOrg == names.AppInstOrg {
				labelMatched = true
			}
		}
		for _, port := range svc.Spec.Ports {
			proto := string(port.Protocol)
			if proto == "" {
				proto = "tcp"
			}
			pp := GetSvcPortProto(port.Port, proto)
			instPort, ok := reqdPorts[pp]
			if !ok {
				// don't need this port
				continue
			}
			if instPort.ServiceName != "" && !strings.Contains(svc.Name, instPort.ServiceName) {
				// specified service name substring for port doesn't match
				filteredByPortServiceStr = append(filteredByPortServiceStr, getServiceID(&svc)+fmt.Sprintf(":%d", port.Port))
				continue
			}
			var lookup map[PortProto]*SvcMatch
			if labelMatched {
				lookup = svcsByPortLabelMatch
			} else {
				lookup = svcsByPort
			}
			match, found := lookup[pp]
			if !found {
				lookup[pp] = &SvcMatch{
					svc: &svc,
					conflicts: []string{
						getServiceID(&svc),
					},
				}
				continue
			}
			if match.svc.Name == svc.Name && match.svc.Namespace == svc.Namespace {
				// same service, don't think this is possible, but check anyway
				continue
			}
			match.conflicts = append(match.conflicts, getServiceID(&svc))
		}
	}

	appServices := &AppServices{
		SvcsByPort: map[PortProto]*v1.Service{},
	}
	portsWithoutSvcs := []string{}
	addedServices := map[string]struct{}{}
	conflicts := []string{}

	// check for missing ports, prefers matches over non-matches,
	// gather conflicts, and build service list.
	for pp, _ := range reqdPorts {
		match, found := svcsByPortLabelMatch[pp]
		if !found {
			match, found = svcsByPort[pp]
		}
		if !found {
			portsWithoutSvcs = append(portsWithoutSvcs, string(pp))
			continue
		}
		appServices.SvcsByPort[pp] = match.svc
		// avoid adding the same service twice for different ports
		svcID := getServiceID(match.svc)
		if _, found := addedServices[svcID]; !found {
			addedServices[svcID] = struct{}{}
			appServices.Services = append(appServices.Services, match.svc)
		}
		if len(match.conflicts) > 1 {
			sort.Strings(match.conflicts)
			conflicts = append(conflicts, fmt.Sprintf("port %s is served by services %s", pp, strings.Join(match.conflicts, ", ")))
		}
	}
	slices.Sort(portsWithoutSvcs)
	appServices.PortsWithoutServices = portsWithoutSvcs

	log.SpanLog(ctx, log.DebugLevelInfra, "GetAppServices", "app", names.AppName, "appinst", names.AppInstName, "helmAppName", names.HelmAppName, "namespace", names.InstanceNamespace, "ports", portsList, "filteredByHeadless", filteredByHeadless, "filteredByAppInstLabel", filteredByAppInstLabel, "filteredByPortServiceStr", filteredByPortServiceStr, "addedServices", addedServices, "missingPorts", portsWithoutSvcs, "conflicts", conflicts)

	if len(conflicts) > 0 {
		slices.Sort(conflicts)
		return nil, fmt.Errorf("failed to determine service for port, too many services found, please add svcname annotation to App.AccessPorts to resolve (i.e. \"tcp:5432:svcname=myapp\"): %s", strings.Join(conflicts, "; "))
	}
	return appServices, nil
}

// WaitForAppServices waits for AppInst services to be created.
func WaitForAppServices(ctx context.Context, client ssh.Client, names *KubeNames, mappedPorts []edgeproto.InstPort) (*AppServices, error) {
	var appServices *AppServices
	var err error
	maxTries := 50
	for i := 0; ; i++ {
		log.SpanLog(ctx, log.DebugLevelInfra, "getting AppInst load balancers", "appinst", names.AppInstName)
		appServices, err = GetAppServices(ctx, client, names, mappedPorts)
		if err != nil {
			return nil, err
		}
		if appServices == nil {
			return nil, fmt.Errorf("no services found for AppInst %s", names.AppInstName)
		}
		if len(appServices.PortsWithoutServices) == 0 {
			return appServices, nil
		}
		// There were some ports without services. Try again later, as the
		// service may not be created yet.
		if i > maxTries {
			return nil, fmt.Errorf("timed out waiting for AppInst services, ports without services: %s", strings.Join(appServices.PortsWithoutServices, ", "))
		}
		log.SpanLog(ctx, log.DebugLevelInfra, "waiting for AppInst load balancers", "appinst", names.AppInstName, "portsWithoutSvcs", appServices.PortsWithoutServices)
		time.Sleep(3 * time.Second)
	}
}
