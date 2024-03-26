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

package infracommon

import (
	"context"
	"fmt"
	"time"

	"github.com/edgexr/edge-cloud-platform/pkg/cloudcommon"
	"github.com/edgexr/edge-cloud-platform/pkg/dnsmgmt/dnsapi"
	"github.com/edgexr/edge-cloud-platform/pkg/k8smgmt"
	"github.com/edgexr/edge-cloud-platform/pkg/log"
	ssh "github.com/edgexr/golang-ssh"
	v1 "k8s.io/api/core/v1"
)

var dnsRegisterRetryDelay time.Duration = 3 * time.Second

type DnsSvcAction struct {
	// if non-empty string, DNS entry will be created against this IP
	// for the service. The DNS name is derived from App parameters.
	ExternalIP string
	// IPv6 external IP
	ExternalIPV6 string
	// AWS uses hostname for service
	Hostname string
	// True to patch the kubernetes service with the Patch IP.
	PatchKube bool
	// IP to patch the kubernetes service with. If empty, will use
	// ExternalIP instead.
	PatchIP string
	// IPv6 to patch the kubernetes service with. If empty, will use
	// ExternalIPV6 instead.
	PatchIPV6 string
	// Should we add DNS, or not
	AddDNS bool
}

// Callback function for callers to control the behavior of DNS changes.
type GetDnsSvcActionFunc func(svc v1.Service) (*DnsSvcAction, error)

var NoDnsOverride = ""

// Register DNS entries for externally visible services.
// The passed in GetDnsSvcActionFunc function should provide this function
// with the actions to perform for each service, since different platforms
// will use different IPs and patching.
func (c *CommonPlatform) CreateAppDNSAndPatchKubeSvc(ctx context.Context, client ssh.Client, kubeNames *k8smgmt.KubeNames, overrideDns string, getSvcAction GetDnsSvcActionFunc) error {

	log.SpanLog(ctx, log.DebugLevelInfra, "CreateAppDNSAndPatchKubeSvc")

	// Validate URI just once
	if kubeNames.AppURI != "" && !kubeNames.IsUriIPAddr {
		err := validateDomain(kubeNames.AppURI)
		if err != nil {
			return err
		}
	}
	svcs, err := k8smgmt.GetServices(ctx, client, kubeNames)
	if err != nil {
		return err
	}
	if len(svcs) < 1 {
		return fmt.Errorf("no load balancer services for %s", kubeNames.AppURI)
	}

	for _, svc := range svcs {
		if kubeNames.DeploymentType != cloudcommon.DeploymentTypeDocker && svc.Spec.Type != v1.ServiceTypeLoadBalancer {
			continue
		}
		if !kubeNames.ContainsService(svc.Name) {
			continue
		}
		sn := svc.ObjectMeta.Name
		namespace := svc.ObjectMeta.Namespace
		if namespace == "" {
			namespace = k8smgmt.DefaultNamespace
		}

		action, err := getSvcAction(svc)
		if err != nil {
			return err
		}
		if action.Hostname == "" && action.ExternalIP == "" && action.ExternalIPV6 == "" {
			continue
		}
		if action.PatchKube {
			patchIP := action.PatchIP
			if patchIP == "" {
				patchIP = action.ExternalIP
			}
			patchIPV6 := action.PatchIPV6
			if patchIPV6 == "" {
				patchIPV6 = action.ExternalIPV6
			}
			err = KubePatchServiceIP(ctx, client, kubeNames, sn, patchIP, patchIPV6, namespace)
			if err != nil {
				return err
			}
		}
		if action.AddDNS {
			if kubeNames.AppURI == "" {
				return fmt.Errorf("URI not specified")
			}
			fqdnBase := uri2fqdn(kubeNames.AppURI)
			fqdn := cloudcommon.ServiceFQDN(sn, fqdnBase)
			if overrideDns != "" {
				fqdn = overrideDns
			}
			recordUpdates := []struct {
				ip         string
				recordType string
			}{
				{action.ExternalIP, dnsapi.RecordTypeA},
				{action.ExternalIPV6, dnsapi.RecordTypeAAAA},
				{action.Hostname, dnsapi.RecordTypeCNAME},
			}
			for _, record := range recordUpdates {
				if record.ip == "" {
					continue
				}
				ip := c.GetMappedExternalIP(record.ip)
				if err := c.PlatformConfig.AccessApi.CreateOrUpdateDNSRecord(ctx, fqdn, record.recordType, ip, 1, false); err != nil {
					if testMode {
						log.SpanLog(ctx, log.DebugLevelInfra, "ignoring dns error in testMode", "err", err)
					} else {
						return fmt.Errorf("can't create DNS record for %s,%s,%s, %v", fqdn, ip, record.recordType, err)
					}
				}
				log.SpanLog(ctx, log.DebugLevelInfra, "registered DNS name, may still need to wait for propagation", "name", fqdn, "externalIP", ip, "recordType", record.recordType)
			}
		}
	}
	return nil
}

func (c *CommonPlatform) DeleteAppDNS(ctx context.Context, client ssh.Client, kubeNames *k8smgmt.KubeNames, overrideDns string) error {
	log.SpanLog(ctx, log.DebugLevelInfra, "DeleteAppDNS", "kubeNames", kubeNames)
	if kubeNames.AppURI == "" {
		log.SpanLog(ctx, log.DebugLevelInfra, "URI not specified, no DNS entry to delete")
		return nil
	}
	err := validateDomain(kubeNames.AppURI)
	if err != nil {
		return err
	}
	svcs, err := k8smgmt.GetServices(ctx, client, kubeNames)
	if err != nil {
		return err
	}
	fqdnBase := uri2fqdn(kubeNames.AppURI)
	for _, svc := range svcs {
		if kubeNames.DeploymentType != cloudcommon.DeploymentTypeDocker && svc.Spec.Type != v1.ServiceTypeLoadBalancer {
			continue
		}
		if !kubeNames.ContainsService(svc.Name) {
			continue
		}
		sn := svc.ObjectMeta.Name
		fqdn := cloudcommon.ServiceFQDN(sn, fqdnBase)
		if overrideDns != "" {
			fqdn = overrideDns
		}
		err := c.DeleteDNSRecords(ctx, fqdn)
		if err != nil {
			return err
		}
	}
	return nil
}

func (c *CommonPlatform) DeleteDNSRecords(ctx context.Context, fqdn string) error {
	log.SpanLog(ctx, log.DebugLevelInfra, "DeleteDNSRecords", "fqdn", fqdn)
	if err := c.PlatformConfig.AccessApi.DeleteDNSRecord(ctx, fqdn); err != nil {
		return fmt.Errorf("cannot delete DNS record %v, %v", fqdn, err)
	}
	log.SpanLog(ctx, log.DebugLevelInfra, "deleted DNS record", "name", fqdn)
	return nil
}

// KubePatchServiceIP updates the service to have the given external ip.  This is done locally and not thru
// an ssh client
func KubePatchServiceIP(ctx context.Context, client ssh.Client, kubeNames *k8smgmt.KubeNames, servicename, ipaddr, ipv6Addr, namespace string) error {
	log.SpanLog(ctx, log.DebugLevelInfra, "patch service IP", "servicename", servicename, "ipaddr", ipaddr, "ipv6Addr", ipv6Addr, "namespace", namespace)

	// TODO: handle ipv6Addr, requires ipv6 enabled on kubernetes
	cmd := fmt.Sprintf(`kubectl %s patch svc %s -n %s -p '{"spec":{"externalIPs":["%s"]}}'`, kubeNames.KconfArg, servicename, namespace, ipaddr)
	out, err := client.Output(cmd)
	if err != nil {
		log.SpanLog(ctx, log.DebugLevelInfra, "patch svc failed",
			"servicename", servicename, "out", out, "err", err)
		return fmt.Errorf("error patching for kubernetes service, %s, %s, %v", cmd, out, err)
	}
	log.SpanLog(ctx, log.DebugLevelInfra, "patched externalIPs on service", "service", servicename, "externalIPs", ipaddr)
	return nil
}
