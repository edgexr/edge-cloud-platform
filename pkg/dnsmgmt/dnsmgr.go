// Package dnsmgmt manages DNS entries
package dnsmgmt

import (
	"context"
	"fmt"
	"os"
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
	provider     dnsapi.Provider
}

// NewDNSMgr creates a new DNS manager that will look for DNS API
// credentials in Vault, and only allow modification of the specified zones.
func NewDNSMgr(vaultConfig *vault.Config, allowedZones []string) *DNSMgr {
	return &DNSMgr{
		vaultConfig:  vaultConfig,
		allowedZones: allowedZones,
	}
}

func (s *DNSMgr) ensureProvider(ctx context.Context) error {
	if s.provider != nil {
		return nil
	}
	// prefer provider specified by environment, otherwise look for
	// providers in the order below.
	providerName := os.Getenv("DNS_PROVIDER")

	if providerName == "" || providerName == cloudflaremgmt.ProviderName {
		provider, err := cloudflaremgmt.GetProvider(s.vaultConfig)
		log.SpanLog(ctx, log.DebugLevelInfra, "get cloudflare DNS provider", "err", err)
		if err == nil {
			s.provider = provider
			return nil
		}
	}
	if providerName == "" || providerName == googleclouddns.ProviderName {
		provider, err := googleclouddns.GetProvider(ctx, s.vaultConfig)
		log.SpanLog(ctx, log.DebugLevelInfra, "get google cloud DNS provider", "err", err)
		if err == nil {
			s.provider = provider
			return nil
		}
	}
	if providerName != "" {
		return fmt.Errorf("failed to set up DNS provider " + providerName)
	} else {
		return fmt.Errorf("no DNS provider configured")
	}
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
