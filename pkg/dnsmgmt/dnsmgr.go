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

// Package dnsmgmt manages DNS entries
package dnsmgmt

import (
	"context"
	"fmt"
	"strings"
	"sync"

	"github.com/edgexr/edge-cloud-platform/pkg/dnsmgmt/cloudflaremgmt"
	"github.com/edgexr/edge-cloud-platform/pkg/dnsmgmt/dnsapi"
	"github.com/edgexr/edge-cloud-platform/pkg/dnsmgmt/googleclouddns"
	"github.com/edgexr/edge-cloud-platform/pkg/log"
	"github.com/edgexr/edge-cloud-platform/pkg/vault"
)

const LocalTestZone = "localtest.net"

const vaultDnsProviderPath = "secret/data/accounts/dnsprovidersbyzone"
const vaultProviderTypeKey = "dnsprovidertype"

type DNSMgr struct {
	vaultConfig         *vault.Config
	allowedZones        []string
	zoneToProviderCache map[string]dnsapi.Provider
	mux                 sync.Mutex
}

var providerFuncs = map[string]dnsapi.GetProviderFunc{
	cloudflaremgmt.ProviderName: cloudflaremgmt.GetProvider,
	googleclouddns.ProviderName: googleclouddns.GetProvider,
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
func NewDNSMgr(vaultConfig *vault.Config, allowedZones []string) *DNSMgr {
	return &DNSMgr{
		vaultConfig:         vaultConfig,
		allowedZones:        allowedZones,
		zoneToProviderCache: make(map[string]dnsapi.Provider),
	}
}

func (s *DNSMgr) GetDNSRecords(ctx context.Context, name string) ([]dnsapi.Record, error) {
	log.SpanLog(ctx, log.DebugLevelInfra, "GetDNSRecords", "name", name, "zones", s.allowedZones)
	provider, zone, err := s.getProvider(ctx, name)
	if err != nil {
		return nil, err
	}
	return provider.GetDNSRecords(ctx, zone, name)
}

func (s *DNSMgr) CreateOrUpdateDNSRecord(ctx context.Context, name, rtype, content string, ttl int, proxy bool) error {
	log.SpanLog(ctx, log.DebugLevelInfra, "CreateOrUpdateDNSRecord", "zones", s.allowedZones, "name", name, "content", content)
	provider, zone, err := s.getProvider(ctx, name)
	if err != nil {
		return err
	}
	return provider.CreateOrUpdateDNSRecord(ctx, zone, name, rtype, content, ttl, proxy)
}

func (s *DNSMgr) DeleteDNSRecord(ctx context.Context, name string) error {
	log.SpanLog(ctx, log.DebugLevelInfra, "DeleteDNSRecord", "zones", s.allowedZones, "name", name)
	if name == "" {
		return fmt.Errorf("missing name")
	}
	provider, zone, err := s.getProvider(ctx, name)
	if err != nil {
		return err
	}
	return provider.DeleteDNSRecord(ctx, zone, name)
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

func (s *DNSMgr) getProvider(ctx context.Context, fqdn string) (dnsapi.Provider, string, error) {
	// lookup the zone for the fqdn
	zone, err := getAllowedZone(ctx, fqdn, s.allowedZones)
	if err != nil {
		return nil, "", err
	}
	// see if we have the provider cached
	provider := s.getCachedProvider(zone)
	if provider != nil {
		return provider, zone, nil
	}

	if zone == LocalTestZone {
		// special case for local testing
		return &TestProvider{}, zone, nil
	}

	// lookup the credentials for the zone
	vaultPath := vaultDnsProviderPath + "/" + zone
	data := map[string]string{}
	err = vault.GetData(s.vaultConfig, vaultPath, 0, &data)
	if err != nil {
		return nil, "", err
	}
	providerType, ok := data[vaultProviderTypeKey]
	if !ok {
		return nil, "", fmt.Errorf("vault data for zone %s missing %q key, allowed value is one of %v", zone, vaultProviderTypeKey, GetProviderNames())
	}
	getProviderFunc, ok := providerFuncs[providerType]
	if !ok {
		return nil, "", fmt.Errorf("unknown dns provider type %q for zone %s, allowed values are %v", providerType, zone, GetProviderNames())
	}
	provider, err = getProviderFunc(ctx, zone, data)
	if err != nil {
		return nil, "", err
	}
	s.putCachedProvider(zone, provider)
	return provider, zone, nil
}

func getAllowedZone(ctx context.Context, name string, zones []string) (string, error) {
	if len(zones) == 0 {
		return "", fmt.Errorf("missing allowed DNS zones")
	}
	for _, zone := range zones {
		if strings.Contains(name, zone) {
			return zone, nil
		}
	}
	return "", fmt.Errorf("Zone mismatch between requested DNS record %s and allowed zones %v", name, zones)
}

func (s *DNSMgr) getCachedProvider(zone string) dnsapi.Provider {
	s.mux.Lock()
	defer s.mux.Unlock()
	return s.zoneToProviderCache[zone]
}

func (s *DNSMgr) putCachedProvider(zone string, provider dnsapi.Provider) {
	s.mux.Lock()
	defer s.mux.Unlock()
	s.zoneToProviderCache[zone] = provider
}
