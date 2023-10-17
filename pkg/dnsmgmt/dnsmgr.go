// Package dnsmgmt manages DNS entries
package dnsmgmt

import (
	"context"
	"fmt"
	"strings"

	"github.com/edgexr/edge-cloud-platform/pkg/dnsmgmt/cloudflaremgmt"
	"github.com/edgexr/edge-cloud-platform/pkg/dnsmgmt/dnsapi"
	"github.com/edgexr/edge-cloud-platform/pkg/dnsmgmt/googleclouddns"
	"github.com/edgexr/edge-cloud-platform/pkg/log"
	"github.com/edgexr/edge-cloud-platform/pkg/vault"
)

const LocalTestZone = "localtest.net"

type DNSMgr struct {
	vaultConfig  *vault.Config
	allowedZones []string
	providerName string
	provider     dnsapi.Provider
}

// NoProvider can be used to specify that DNS service is not needed.
const NoProvider = "none"

var providerFuncs = map[string]dnsapi.GetProviderFunc{
	cloudflaremgmt.ProviderName: cloudflaremgmt.GetProvider,
	googleclouddns.ProviderName: googleclouddns.GetProvider,
	NoProvider:                  nil,
}

func GetProviderNames() []string {
	names := []string{}
	for name := range providerFuncs {
		names = append(names, name)
	}
	return names
}

// NewDNSMgr creates a new DNS manager that will look for DNS API
// credentials in Vault, and only allow modification of the specified zones.
func NewDNSMgr(vaultConfig *vault.Config, allowedZones []string, providerName string) *DNSMgr {
	return &DNSMgr{
		vaultConfig:  vaultConfig,
		allowedZones: allowedZones,
		providerName: providerName,
	}
}

func (s *DNSMgr) Init(ctx context.Context) error {
	if s.providerName == NoProvider {
		log.SpanLog(ctx, log.DebugLevelInfra, "skip DNS provider", "provider", s.providerName)
		return nil
	}

	// Use dns provider if specified
	if s.providerName != "" {
		getProvider, ok := providerFuncs[s.providerName]
		if !ok {
			return fmt.Errorf("specified dns provider %s is not supported", s.providerName)
		}
		provider, err := getProvider(ctx, s.vaultConfig)
		if err != nil {
			return fmt.Errorf("error getting DNS provider %s, %s", s.providerName, err)
		}
		s.provider = provider
		return nil
	}

	// Use provider based on what credentials have been supplied
	var provider dnsapi.Provider
	var provName string
	var errs []string
	for name, getProvider := range providerFuncs {
		prov, err := getProvider(ctx, s.vaultConfig)
		log.SpanLog(ctx, log.DebugLevelInfra, "get DNS provider", "provider", name, "err", err)
		if err == nil {
			if provider != nil {
				// credentials exist for more than one provider,
				// require provider to be specified.
				return fmt.Errorf("found credentials for multiple DNS providers, please specify which provider to use.")
			}
			provider = prov
			provName = name
		} else {
			errs = append(errs, name+": "+err.Error())
		}
	}
	if provider == nil {
		return fmt.Errorf("failed to initialize DNS provider: %s", strings.Join(errs, ", "))
	}

	s.provider = provider
	s.providerName = provName
	return nil
}

func (s *DNSMgr) ensureProvider(ctx context.Context) error {
	if s.provider == nil {
		return fmt.Errorf("dns manager not initialized")
	}
	return nil
}

func (s *DNSMgr) GetDNSRecords(ctx context.Context, name string) ([]dnsapi.Record, error) {
	log.SpanLog(ctx, log.DebugLevelInfra, "GetDNSRecords", "name", name, "zones", s.allowedZones)
	if err := s.ensureProvider(ctx); err != nil {
		return nil, err
	}
	zone, err := getAllowedZone(ctx, name, s.allowedZones)
	if err != nil {
		return nil, err
	}
	return s.provider.GetDNSRecords(ctx, zone, name)
}

func (s *DNSMgr) CreateOrUpdateDNSRecord(ctx context.Context, name, rtype, content string, ttl int, proxy bool) error {
	log.SpanLog(ctx, log.DebugLevelInfra, "CreateOrUpdateDNSRecord", "zones", s.allowedZones, "name", name, "content", content)
	if err := s.ensureProvider(ctx); err != nil {
		return err
	}
	zone, err := getAllowedZone(ctx, name, s.allowedZones)
	if err != nil {
		return err
	}
	if zone == LocalTestZone {
		log.SpanLog(ctx, log.DebugLevelInfra, "Skip record creation for test zone", "zone", zone)
		return nil
	}
	return s.provider.CreateOrUpdateDNSRecord(ctx, zone, name, rtype, content, ttl, proxy)
}

func (s *DNSMgr) DeleteDNSRecord(ctx context.Context, name string) error {
	log.SpanLog(ctx, log.DebugLevelInfra, "DeleteDNSRecord", "zones", s.allowedZones, "name", name)
	if name == "" {
		return fmt.Errorf("missing name")
	}
	if err := s.ensureProvider(ctx); err != nil {
		return err
	}
	zone, err := getAllowedZone(ctx, name, s.allowedZones)
	if err != nil {
		return err
	}
	if zone == LocalTestZone {
		return nil
	}
	return s.provider.DeleteDNSRecord(ctx, zone, name)
}

func getAllowedZone(ctx context.Context, name string, zones []string) (string, error) {
	if len(zones) == 0 {
		return "", fmt.Errorf("missing allowed DNS zone domain")
	}
	for _, zone := range zones {
		if strings.Contains(name, zone) {
			return zone, nil
		}
	}
	return "", fmt.Errorf("Zone mismatch between requested DNS record %s and allowed zones %v", name, zones)
}

// PlatformRecordTypeAllowed restricts the record types that can be
// created by external platform services (like CRM, etc).
func PlatformRecordTypeAllowed(rtype string) bool {
	if rtype == dnsapi.RecordTypeA ||
		rtype == dnsapi.RecordTypeAAAA ||
		rtype == dnsapi.RecordTypeCNAME {
		return true
	}
	return false
}
