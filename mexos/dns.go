package mexos

import (
	"fmt"
	"net"
	"os/exec"
	"time"

	"github.com/mobiledgex/edge-cloud-infra/k8s-prov/dind"
	"github.com/mobiledgex/edge-cloud-infra/openstack-tenant/agent/cloudflare"
	"github.com/mobiledgex/edge-cloud/cloudcommon"
	"github.com/mobiledgex/edge-cloud/log"
	"k8s.io/api/core/v1"
)

var dnsRegisterRetryDelay time.Duration = 3 * time.Second

func createAppDNS(kp *kubeParam, kubeNames *KubeNames) error {

	log.DebugLog(log.DebugLevelMexos, "createAppDNS")

	if err := cloudflare.InitAPI(GetCloudletCFUser(), GetCloudletCFKey()); err != nil {
		return fmt.Errorf("cannot init cloudflare api, %v", err)
	}
	if kubeNames.appURI == "" {
		return fmt.Errorf("URI not specified")
	}
	err := validateDomain(kubeNames.appURI)
	if err != nil {
		return err
	}
	svcs, err := getServices(kp)
	if err != nil {
		return err
	}
	if len(svcs) < 1 {
		return fmt.Errorf("no load balancer services for %s", kubeNames.appURI)
	}

	fqdnBase := uri2fqdn(kubeNames.appURI)
	for _, svc := range svcs {
		if svc.Spec.Type != v1.ServiceTypeLoadBalancer {
			continue
		}
		if !kubeNames.containsService(svc.Name) {
			continue
		}
		sn := svc.ObjectMeta.Name
		// for the DIND case we need to patch the service here
		externalIP := ""
		if CloudletIsLocalDIND() {
			addr := dind.GetMasterAddr(kubeNames.clusterName)
			if len(svc.Spec.ExternalIPs) > 0 && svc.Spec.ExternalIPs[0] == addr {
				log.DebugLog(log.DebugLevelMexos, "external IP already present in DIND, no patch required", "addr", addr)
			} else {
				err = KubePatchServiceLocal(sn, addr)
				if err != nil {
					return err
				}
			}
			externalIP, err = dind.GetLocalAddr()
		} else {
			externalIP, err = getSvcExternalIP(sn, kp)
		}
		if err != nil {
			return err
		}
		fqdn := cloudcommon.ServiceFQDN(sn, fqdnBase)

		if err := cloudflare.CreateOrUpdateDNSRecord(GetCloudletDNSZone(), fqdn, "A", externalIP, 1, false); err != nil {
			return fmt.Errorf("can't create DNS record for %s,%s, %v", fqdn, externalIP, err)
		}
		log.DebugLog(log.DebugLevelMexos, "registered DNS name, may still need to wait for propagation", "name", fqdn, "externalIP", externalIP)
	}
	return nil
}

func deleteAppDNS(kp *kubeParam, kubeNames *KubeNames) error {

	if err := cloudflare.InitAPI(GetCloudletCFUser(), GetCloudletCFKey()); err != nil {
		return fmt.Errorf("cannot init cloudflare api, %v", err)
	}
	if kubeNames.appURI == "" {
		return fmt.Errorf("URI not specified")
	}
	err := validateDomain(kubeNames.appURI)
	if err != nil {
		return err
	}
	svcs, err := getServices(kp)
	if err != nil {
		return err
	}
	if len(svcs) < 1 {
		return fmt.Errorf("no services in cluster")
	}
	fqdnBase := uri2fqdn(kubeNames.appURI)
	for _, svc := range svcs {
		if svc.Spec.Type != v1.ServiceTypeLoadBalancer {
			continue
		}
		if !kubeNames.containsService(svc.Name) {
			continue
		}
		sn := svc.ObjectMeta.Name
		fqdn := cloudcommon.ServiceFQDN(sn, fqdnBase)
		recs, derr := cloudflare.GetDNSRecords(GetCloudletDNSZone(), fqdn)
		if derr != nil {
			return fmt.Errorf("cannot get dns records for dns zone %s, error %v", GetCloudletDNSZone(), err)
		}
		for _, rec := range recs {
			if rec.Type == "A" && rec.Name == fqdn {
				if err := cloudflare.DeleteDNSRecord(GetCloudletDNSZone(), rec.ID); err != nil {
					return fmt.Errorf("cannot delete existing DNS record %v, %v", rec, err)
				}
			}
		}
		log.DebugLog(log.DebugLevelMexos, "deleted DNS name", "name", fqdn)
	}
	return nil
}

// KubePatchServiceLocal updates the service to have the given external ip.  This is done locally and not thru
// an ssh client
func KubePatchServiceLocal(servicename string, ipaddr string) error {

	ips := fmt.Sprintf(`{"spec":{"externalIPs":["%s"]}}'`, ipaddr)
	log.DebugLog(log.DebugLevelMexos, "KubePatchServiceLocal", "servicename", servicename, "ipaddr", ipaddr, "ipspec", ips)

	out, err := exec.Command("kubectl", "patch", "svc", servicename, "-p", ips).CombinedOutput()
	if err != nil {
		log.DebugLog(log.DebugLevelMexos, "patch svc failed", "servicename", servicename, "out", out, "err", err)
		return fmt.Errorf("error patching for kubernetes service ip: %s, name: %s, err: %v", ipaddr, servicename, err)
	}
	return nil
}

// TODO: This function and createAppDNS share a lot of duplicate code,
// but are subtly different. It'd be good to consolidate and remove
// duplicate code and highlight what the different use cases are,
// since it's not clear when to use one or the other.
// This should be easier to consolidate now that kubeParam can issue
// commands locally for DIND or other cases.
// Same for KubeDeleteDNSRecords and deleteAppDNS.

func KubePatchSvcAddDNSRecords(rootLB *MEXRootLB, kp *kubeParam, kubeNames *KubeNames) error {
	log.DebugLog(log.DebugLevelMexos, "patching service and adding dns records for kubenernets app", "name", kubeNames.appName)
	rootLBIPaddr, err := GetServerIPAddr(GetCloudletExternalNetwork(), rootLB.Name)
	if err != nil {
		log.DebugLog(log.DebugLevelMexos, "cannot get rootlb IP address", "error", err)
		return fmt.Errorf("cannot deploy kubernetes app, cannot get rootlb IP")
	}

	svcs, err := getServices(kp)
	log.DebugLog(log.DebugLevelMexos, "got kubernetes services", "services", svcs)

	if err != nil {
		return err
	}
	if err := cloudflare.InitAPI(GetCloudletCFUser(), GetCloudletCFKey()); err != nil {
		return fmt.Errorf("cannot init cloudflare api, %v", err)
	}
	fqdnBase := uri2fqdn(kubeNames.appURI)
	processed := 0
	for _, svc := range svcs {
		if svc.Spec.Type != v1.ServiceTypeLoadBalancer {
			continue
		}
		if !kubeNames.containsService(svc.Name) {
			continue
		}
		log.DebugLog(log.DebugLevelMexos, "patching service", "svc", svc)

		cmd := fmt.Sprintf(`%s kubectl patch svc %s -p '{"spec":{"externalIPs":["%s"]}}'`, kp.kubeconfig, svc.ObjectMeta.Name, kp.ipaddr)
		out, err := kp.client.Output(cmd)
		if err != nil {
			return fmt.Errorf("error patching for kubernetes service, %s, %s, %v", cmd, out, err)
		}
		log.DebugLog(log.DebugLevelMexos, "patched externalIPs on service", "service", svc.ObjectMeta.Name, "externalIPs", kp.ipaddr)
		fqdn := cloudcommon.ServiceFQDN(svc.ObjectMeta.Name, fqdnBase)

		if err := cloudflare.CreateOrUpdateDNSRecord(GetCloudletDNSZone(), fqdn, "A", rootLBIPaddr, 1, false); err != nil {
			return fmt.Errorf("can't create DNS record for %s,%s, %v", fqdn, rootLBIPaddr, err)
		}
		processed++
		log.DebugLog(log.DebugLevelMexos, "created DNS record", "name", fqdn, "addr", rootLBIPaddr)
	}
	if processed == 0 {
		return fmt.Errorf("cannot patch service, %s not found", kubeNames.appName)
	}
	return nil
}

func KubeDeleteDNSRecords(rootLB *MEXRootLB, kp *kubeParam, kubeNames *KubeNames) error {
	//TODO before removing dns records, especially for the purpose of creating
	// a dns entry that was there before, to overwrite, we need to check
	// if the user really wants to. For example, if the cluster naming was in error,
	// it would be bad to overwrite working existing cluster dns.
	cmd := fmt.Sprintf("%s kubectl get svc -o json", kp.kubeconfig)
	out, err := kp.client.Output(cmd)
	if err != nil {
		return fmt.Errorf("can not get list of services, %s, %v", out, err)
	}
	svcs, err := getServices(kp)
	if err != nil {
		return err
	}
	if err := cloudflare.InitAPI(GetCloudletCFUser(), GetCloudletCFKey()); err != nil {
		return fmt.Errorf("cannot init cloudflare api, %v", err)
	}

	fqdnBase := uri2fqdn(kubeNames.appURI)
	//FIXME use k8s manifest file to delete the whole services and deployments
	for _, svc := range svcs {
		if svc.Spec.Type != v1.ServiceTypeLoadBalancer {
			continue
		}
		if !kubeNames.containsService(svc.Name) {
			continue
		}
		fqdn := cloudcommon.ServiceFQDN(svc.ObjectMeta.Name, fqdnBase)
		recs, derr := cloudflare.GetDNSRecords(GetCloudletDNSZone(), fqdn)
		if derr != nil {
			return fmt.Errorf("error getting dns records for %s, %v", GetCloudletDNSZone(), derr)
		}
		for _, rec := range recs {
			if rec.Type == "A" && rec.Name == fqdn {
				if err := cloudflare.DeleteDNSRecord(GetCloudletDNSZone(), rec.ID); err != nil {
					return fmt.Errorf("cannot delete existing DNS record %v, %v", rec, err)
				}
				log.DebugLog(log.DebugLevelMexos, "deleted DNS record", "name", fqdn)
			}
		}
	}
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

func WaitforDNSRegistration(name string) error {
	var ipa string
	var err error

	for i := 0; i < 100; i++ {
		ipa, err = LookupDNS(name)
		if err == nil && ipa != "" {
			return nil
		}
		time.Sleep(dnsRegisterRetryDelay)
	}
	log.DebugLog(log.DebugLevelMexos, "DNS lookup timed out", "name", name)
	return fmt.Errorf("error, timed out while looking up DNS for name %s", name)
}
