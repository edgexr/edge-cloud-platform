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
	"cmp"
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
	return svcs.Items, nil
}

func GetService(ctx context.Context, client ssh.Client, names *KconfNames, name, namespace string) (*v1.Service, error) {
	svc := v1.Service{}
	err := GetObject(ctx, client, names, "svc", name, &svc, WithObjectNamespace(namespace))
	if err != nil {
		return nil, err
	}
	return &svc, nil
}

// InstPortKey uniquely identifies an instance port.
// This is the information that is used to map the instance port
// to an underlying Kubernetes service (load balancer or cluster IP).
// If these are not unique, then it may not be possible to determine
// the correct service to use.
type InstPortKey struct {
	Proto        string
	InternalPort int32
	ServiceName  string
}

func GetInstPortKey(s *edgeproto.InstPort) InstPortKey {
	proto, err := edgeproto.LProtoStr(s.Proto)
	if err != nil {
		proto = "unknown"
	}
	return InstPortKey{
		Proto:        proto,
		InternalPort: s.InternalPort,
		ServiceName:  s.ServiceName,
	}
}

func (s *InstPortKey) String() string {
	desc := edgeproto.ProtoPortToString(s.Proto, s.InternalPort)
	if s.ServiceName != "" {
		desc = s.ServiceName + "/" + desc
	}
	return desc
}

// CheckInstPortAmbiguity checks for inst ports that would map
// to the same Kubernetes service, which would make it impossible
// for us to determine which service to use.
func CheckInstPortAmbiguity(ports []edgeproto.InstPort) error {
	portMap := map[InstPortKey]*edgeproto.InstPort{}
	for _, port := range ports {
		if port.InternalVisOnly {
			continue
		}
		key := GetInstPortKey(&port)
		if _, found := portMap[key]; found {
			return fmt.Errorf("duplicate access port definitions for %s, please add a service name substring to distinguish", key.String())
		}
		portMap[key] = &port
	}
	return nil
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
	SvcsByPort map[InstPortKey]*v1.Service
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

	// There is no guaranteed way to match a load balancer/cluster IP service
	// with the AppInst that deployed it, given the ways in which we can have
	// layers of manifests, helm charts, and operators. Consider an AppInst
	// with a custom manifest that deploys an operator, and the operator
	// deploys both another manifest and a helm chart.
	// For AppInsts with manifests, we label the objects in the manifest
	// with the AppInst name. For helm charts, helm annotates the services
	// with the helm release name. However because of the layering, for
	// example you can have a helm chart that deploys another helm chart,
	// services may have different annotations than expected. So it's not
	// possible to match services just based on labels/annotations.
	// To resolve ambiguity we need the user to tell us, per exposed port
	// on the App, what the service name should be.

	// Previously we filtered by namespace, but now we allow multiple
	// apps per namespace. We do not support a single App to create
	// objects across multiple namespaces.

	// track filtered out services for logging
	filteredByHeadless := []string{}
	filteredByAppInstLabel := []string{}
	filteredByReqdPorts := []string{}

	// Get the ports we need to get services for
	reqdPorts := map[PortProto][]*edgeproto.InstPort{}
	portsList := []string{}
	for ii := range mappedPorts {
		port := &mappedPorts[ii]
		if port.InternalVisOnly {
			continue
		}
		if port.ServiceName != "" {
			port.ServiceName = strings.ReplaceAll(port.ServiceName, "{{.Name}}", names.AppInstName)
		}
		pp := GetSvcPortLProto(port.InternalPort, port.Proto)
		reqdPorts[pp] = append(reqdPorts[pp], port)
		// for logging
		ppStr := string(pp)
		if port.ServiceName != "" {
			ppStr += "/svcname=" + port.ServiceName
		}
		portsList = append(portsList, ppStr)
	}
	// Match services to the required ports
	type SvcMatch []*v1.Service

	svcsByPort := map[PortProto]SvcMatch{}
	svcsByPortLabelMatch := map[PortProto]SvcMatch{}
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
		// Check AppInst labels.
		// Special case: if the label matches, ignore other services
		// that do not have matching labels for the same port.
		// Note that it's still possible to have a conflict if there are
		// two matching labeled services for the same port.
		labelMatched := false
		if labels := svc.GetLabels(); labels != nil {
			aiName, hasAiName := labels[cloudcommon.AppInstNameLabel]
			aiOrg, hasAiOrg := labels[cloudcommon.AppInstOrgLabel]
			if hasAiName && hasAiOrg && (aiName != names.AppInstNameLabelValue || aiOrg != names.AppInstOrgLabelValue) {
				// service from a different AppInst
				filteredByAppInstLabel = append(filteredByAppInstLabel, getServiceID(&svc))
				continue
			}
			if hasAiName && hasAiOrg && aiName == names.AppInstNameLabelValue && aiOrg == names.AppInstOrgLabelValue {
				labelMatched = true
			}
		}
		for _, port := range svc.Spec.Ports {
			proto := string(port.Protocol)
			if proto == "" {
				proto = "tcp"
			}
			pp := GetSvcPortProto(port.Port, proto)
			_, ok := reqdPorts[pp]
			if !ok {
				// don't need this port
				filteredByReqdPorts = append(filteredByReqdPorts, getServiceID(&svc))
				continue
			}
			if labelMatched {
				svcsByPortLabelMatch[pp] = append(svcsByPortLabelMatch[pp], &svc)
			} else {
				svcsByPort[pp] = append(svcsByPort[pp], &svc)
			}
		}
	}
	appServices := &AppServices{
		SvcsByPort: map[InstPortKey]*v1.Service{},
	}
	portsWithoutSvcs := []string{}
	addedServices := map[string]struct{}{}
	allConflicts := []string{}

	// match ports to service, filtering by service name if specified
	// walk the list of ports grouped by tcp|udp port.
	for pp, portList := range reqdPorts {
		// Prefer AppInst labelled services. Note that if labelled
		// services are present, we should ignore non-labelled services
		// because they must belong to another AppInst.
		svcs, ok := svcsByPortLabelMatch[pp]
		if !ok {
			svcs = svcsByPort[pp]
		}
		slices.SortFunc(portList, func(i, j *edgeproto.InstPort) int {
			// sort by longest service name first as that is
			// more specific.
			return cmp.Compare(len(j.ServiceName), len(i.ServiceName))
		})
		for _, port := range portList {
			matched := false
			conflicts := []string{}
			key := GetInstPortKey(port)
			// walk services for the tcp|udp port
			for _, svc := range svcs {
				if port.ServiceName != "" && !strings.Contains(svc.Name, port.ServiceName) {
					continue
				}
				matched = true
				// map InstPort to service
				appServices.SvcsByPort[key] = svc
				// track services in use
				svcID := getServiceID(svc)
				if _, found := addedServices[svcID]; !found {
					addedServices[svcID] = struct{}{}
					appServices.Services = append(appServices.Services, svc)
				}
				// track potential conflicts where more than one service
				// maps to the port
				conflicts = append(conflicts, getServiceID(svc))
			}
			if !matched {
				portsWithoutSvcs = append(portsWithoutSvcs, key.String())
			}
			if len(conflicts) > 1 {
				sort.Strings(conflicts)
				allConflicts = append(allConflicts, fmt.Sprintf("port %s is served by services %s", key.String(), strings.Join(conflicts, ", ")))
			}
		}
	}
	slices.Sort(portsWithoutSvcs)
	appServices.PortsWithoutServices = portsWithoutSvcs

	log.SpanLog(ctx, log.DebugLevelInfra, "GetAppServices", "app", names.AppName, "appinst", names.AppInstName, "helmAppName", names.HelmAppName, "namespace", names.InstanceNamespace, "ports", portsList, "filteredByHeadless", filteredByHeadless, "filteredByAppInstLabel", filteredByAppInstLabel, "filteredByReqdPorts", filteredByReqdPorts, "addedServices", addedServices, "missingPorts", portsWithoutSvcs, "conflicts", allConflicts)

	if len(allConflicts) > 0 {
		slices.Sort(allConflicts)
		return nil, fmt.Errorf("failed to determine service for port, too many services found, please add svcname annotation to App.AccessPorts to resolve (i.e. \"tcp:5432:svcname=myapp\"): %s", strings.Join(allConflicts, "; "))
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

// LoadbalancerIPsAnnotation is for specifying IPs for a loadbalancer
// use plural for dual stack support in the future
// Example: kube-vip.io/loadbalancerIPs: 10.1.2.3,fd00::100
// See https://github.com/kube-vip/kube-vip-cloud-provider/blob/main/pkg/provider/loadBalancer.go
const KubeVipLoadbalancerIPsAnnotation = "kube-vip.io/loadbalancerIPs"
const MetalLBLoadbalancerIPsAnnotation = "metallb.io/loadBalancerIPs"

func AnnotateLoadBalancerIP(ctx context.Context, client ssh.Client, names *KconfNames, lb *edgeproto.LoadBalancer, annotation string) error {
	cmd := fmt.Sprintf("kubectl %s annotate -n %s svc %s %s=%s", names.KconfArg, lb.Key.Namespace, lb.Key.Name, annotation, lb.Ipv4)
	out, err := client.Output(cmd)
	if err != nil {
		return fmt.Errorf("failed to set loadbalancer IP cmd %s: %s, %s", cmd, out, err)
	}
	return nil
}

// PatchServiceIP updates the service to have the given external ips.
func PatchServiceIP(ctx context.Context, client ssh.Client, names *KconfNames, servicename, ipaddr, ipv6Addr, namespace string) error {
	log.SpanLog(ctx, log.DebugLevelInfra, "patch service IP", "servicename", servicename, "ipaddr", ipaddr, "ipv6Addr", ipv6Addr, "namespace", namespace)

	// TODO: handle ipv6Addr, requires ipv6 enabled on kubernetes
	cmd := fmt.Sprintf(`kubectl %s patch svc %s -n %s -p '{"spec":{"externalIPs":["%s"]}}'`, names.KconfArg, servicename, namespace, ipaddr)
	out, err := client.Output(cmd)
	if err != nil {
		log.SpanLog(ctx, log.DebugLevelInfra, "patch svc failed",
			"servicename", servicename, "out", out, "err", err)
		return fmt.Errorf("error patching for kubernetes service, %s, %s, %v", cmd, out, err)
	}
	log.SpanLog(ctx, log.DebugLevelInfra, "patched externalIPs on service", "service", servicename, "externalIPs", ipaddr)
	return nil
}
