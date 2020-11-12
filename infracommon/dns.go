package infracommon

import (
	"context"
	"fmt"
	"net"
	"time"

	"github.com/mobiledgex/edge-cloud/cloud-resource-manager/k8smgmt"
	"github.com/mobiledgex/edge-cloud/cloudcommon"
	"github.com/mobiledgex/edge-cloud/log"
	ssh "github.com/mobiledgex/golang-ssh"
	v1 "k8s.io/api/core/v1"
)

var dnsRegisterRetryDelay time.Duration = 3 * time.Second

type DnsSvcAction struct {
	// if non-empty string, DNS entry will be created against this IP
	// for the service. The DNS name is derived from App parameters.
	ExternalIP string
	// AWS uses hostname for service
	Hostname string
	// True to patch the kubernetes service with the Patch IP.
	PatchKube bool
	// IP to patch the kubernetes service with. If empty, will use
	// ExternalIP instead.
	PatchIP string
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

	log.SpanLog(ctx, log.DebugLevelInfra, "createAppDNS")

	if kubeNames.AppURI == "" {
		return fmt.Errorf("URI not specified")
	}
	err := validateDomain(kubeNames.AppURI)
	if err != nil {
		return err
	}
	svcs, err := GetServices(ctx, client, kubeNames)
	if err != nil {
		return err
	}
	if len(svcs) < 1 {
		return fmt.Errorf("no load balancer services for %s", kubeNames.AppURI)
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

		action, err := getSvcAction(svc)
		if err != nil {
			return err
		}
		if action.Hostname == "" && action.ExternalIP == "" {
			continue
		}
		if action.PatchKube {
			patchIP := action.PatchIP
			if patchIP == "" {
				patchIP = action.ExternalIP
			}
			err = KubePatchServiceIP(ctx, client, kubeNames, sn, patchIP)
			if err != nil {
				return err
			}
		}
		if action.AddDNS {
			mappedAddr := c.GetMappedExternalIP(action.ExternalIP)
			fqdn := cloudcommon.ServiceFQDN(sn, fqdnBase)
			if overrideDns != "" {
				fqdn = overrideDns
			}
			dnsRecType := "A"
			if action.Hostname != "" {
				dnsRecType = "CNAME"
				mappedAddr = action.Hostname
			}
			if err := c.PlatformConfig.AccessApi.CreateOrUpdateDNSRecord(ctx, c.GetCloudletDNSZone(), fqdn, dnsRecType, mappedAddr, 1, false); err != nil {
				if testMode {
					log.SpanLog(ctx, log.DebugLevelInfra, "ignoring dns error in testMode", "err", err)
				} else {
					return fmt.Errorf("can't create DNS record for %s,%s, %v", fqdn, mappedAddr, err)
				}
			}
			log.SpanLog(ctx, log.DebugLevelInfra, "registered DNS name, may still need to wait for propagation", "name", fqdn, "externalIP", action.ExternalIP)
		}
	}
	return nil
}

func (c *CommonPlatform) DeleteAppDNS(ctx context.Context, client ssh.Client, kubeNames *k8smgmt.KubeNames, overrideDns string) error {
	log.SpanLog(ctx, log.DebugLevelInfra, "DeleteAppDNS", "kubeNames", kubeNames)
	if kubeNames.AppURI == "" {
		return fmt.Errorf("URI not specified")
	}
	err := validateDomain(kubeNames.AppURI)
	if err != nil {
		return err
	}
	svcs, err := GetServices(ctx, client, kubeNames)
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
	recs, derr := c.PlatformConfig.AccessApi.GetDNSRecords(ctx, c.GetCloudletDNSZone(), fqdn)
	if derr != nil {
		return fmt.Errorf("error getting dns records for %s, %v", c.GetCloudletDNSZone(), derr)
	}
	for _, rec := range recs {
		if (rec.Type == "A" || rec.Type == "CNAME") && rec.Name == fqdn {
			if err := c.PlatformConfig.AccessApi.DeleteDNSRecord(ctx, c.GetCloudletDNSZone(), rec.ID); err != nil {
				return fmt.Errorf("cannot delete existing DNS record %v, %v", rec, err)
			}
			log.SpanLog(ctx, log.DebugLevelInfra, "deleted DNS record", "name", fqdn)
		}
	}
	return nil
}

// KubePatchServiceIP updates the service to have the given external ip.  This is done locally and not thru
// an ssh client
func KubePatchServiceIP(ctx context.Context, client ssh.Client, kubeNames *k8smgmt.KubeNames, servicename string, ipaddr string) error {
	log.SpanLog(ctx, log.DebugLevelInfra, "patch service IP", "servicename", servicename, "ipaddr", ipaddr)

	cmd := fmt.Sprintf(`%s kubectl patch svc %s -p '{"spec":{"externalIPs":["%s"]}}'`, kubeNames.KconfEnv, servicename, ipaddr)
	out, err := client.Output(cmd)
	if err != nil {
		log.SpanLog(ctx, log.DebugLevelInfra, "patch svc failed",
			"servicename", servicename, "out", out, "err", err)
		return fmt.Errorf("error patching for kubernetes service, %s, %s, %v", cmd, out, err)
	}
	log.SpanLog(ctx, log.DebugLevelInfra, "patched externalIPs on service", "service", servicename, "externalIPs", ipaddr)
	return nil
}

func LookupDNS(name string) (string, error) {
	ips, err := net.LookupIP(name)
	if err != nil {
		return "", fmt.Errorf("DNS lookup error, %s, %v", name, err)
	}
	if len(ips) == 0 {
		return "", fmt.Errorf("no DNS records, %s", name)
	}
	for _, ip := range ips {
		return ip.String(), nil //XXX return only first one
	}
	return "", fmt.Errorf("no IP in DNS record for %s", name)
}

func WaitforDNSRegistration(ctx context.Context, name string) error {
	var ipa string
	var err error

	for i := 0; i < 100; i++ {
		ipa, err = LookupDNS(name)
		if err == nil && ipa != "" {
			return nil
		}
		time.Sleep(dnsRegisterRetryDelay)
	}
	log.SpanLog(ctx, log.DebugLevelInfra, "DNS lookup timed out", "name", name)
	return fmt.Errorf("error, timed out while looking up DNS for name %s", name)
}
