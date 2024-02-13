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

// Package googleclouddns provides functions to manage Google Cloud DNS entries
package googleclouddns

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"github.com/edgexr/edge-cloud-platform/pkg/dnsmgmt/dnsapi"
	"github.com/edgexr/edge-cloud-platform/pkg/log"
	"google.golang.org/api/dns/v1"
	"google.golang.org/api/googleapi"
	"google.golang.org/api/option"
)

const projectID = "project_id"
const ProviderName = "googleclouddns"

type CloudDNS struct {
	api        *dns.Service
	project    string
	zoneToName map[string]string // map DNS zone to GCP name
}

func GetProvider(ctx context.Context, zone string, vaultData map[string]string) (dnsapi.Provider, error) {
	project, ok := vaultData[projectID]
	if !ok {
		return nil, fmt.Errorf("google cloud DNS credentials missing " + projectID)
	}
	jsonData, err := json.Marshal(vaultData)
	if err != nil {
		return nil, err
	}
	log.SpanLog(ctx, log.DebugLevelInfra, "initializing google cloud DNS", "project", project)
	api, err := dns.NewService(ctx, option.WithCredentialsJSON(jsonData))
	if err != nil {
		return nil, err
	}
	cloudDNS := &CloudDNS{
		api:        api,
		project:    project,
		zoneToName: map[string]string{},
	}
	err = cloudDNS.setManagedZones(ctx)
	if err != nil {
		return nil, err
	}
	return cloudDNS, nil
}

func (s *CloudDNS) setManagedZones(ctx context.Context) error {
	req := s.api.ManagedZones.List(s.project)
	err := req.Pages(ctx, func(page *dns.ManagedZonesListResponse) error {
		if page.HTTPStatusCode < 200 || page.HTTPStatusCode >= 300 {
			return fmt.Errorf("list managed zones returned %d", page.HTTPStatusCode)
		}
		for _, mz := range page.ManagedZones {
			dnsName := strings.TrimSuffix(mz.DnsName, ".")
			s.zoneToName[dnsName] = mz.Name
		}
		return nil
	})
	if err != nil {
		return err
	}
	log.SpanLog(ctx, log.DebugLevelInfra, "google cloud DNS", "managedZones", s.zoneToName)
	return nil
}

func (s *CloudDNS) GetDNSRecords(ctx context.Context, zone, name string) ([]dnsapi.Record, error) {
	mz, ok := s.zoneToName[zone]
	if !ok {
		return nil, fmt.Errorf("no managed zone found for %s", zone)
	}
	records := []dnsapi.Record{}

	req := s.api.ResourceRecordSets.List(s.project, mz)
	err := req.Pages(ctx, func(page *dns.ResourceRecordSetsListResponse) error {
		for _, rrset := range page.Rrsets {
			rrsetName := strings.TrimSuffix(rrset.Name, ".")
			if name != "" && name != rrsetName {
				continue
			}
			record := dnsapi.Record{
				Type:    rrset.Type,
				Name:    rrsetName,
				Content: rrset.Rrdatas,
				TTL:     int(rrset.Ttl),
			}
			records = append(records, record)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return records, nil
}

func (s *CloudDNS) CreateOrUpdateDNSRecord(ctx context.Context, zone, name, rtype, content string, ttl int, proxy bool) error {
	if !strings.HasSuffix(name, ".") {
		name += "."
	}
	mz, ok := s.zoneToName[zone]
	if !ok {
		return fmt.Errorf("no managed zone found for %s", zone)
	}
	var existing *dns.ResourceRecordSet
	noUpdateNeeded := false
	req := s.api.ResourceRecordSets.List(s.project, mz)
	err := req.Pages(ctx, func(page *dns.ResourceRecordSetsListResponse) error {
		for _, rrset := range page.Rrsets {
			if name == rrset.Name && rtype == rrset.Type {
				existing = rrset
				if len(rrset.Rrdatas) > 0 && content == rrset.Rrdatas[0] && int64(ttl) == rrset.Ttl {
					noUpdateNeeded = true
				}
				break
			}
		}
		return nil
	})
	if err != nil {
		return err
	}
	if noUpdateNeeded {
		log.SpanLog(ctx, log.DebugLevelInfra, "update dns record not needed", "record", *existing)
	}

	if existing != nil {
		// update existing
		existing.Rrdatas = []string{content}
		existing.Ttl = int64(ttl)
		log.SpanLog(ctx, log.DebugLevelInfra, "update dns record", "new", existing)
		resp, err := s.api.ResourceRecordSets.Patch(s.project, mz, name, rtype, existing).Context(ctx).Do()
		if err != nil && !googleapi.IsNotModified(err) {
			return fmt.Errorf("update existing dns record failed, %s", err)
		}
		if err := responseError(&resp.ServerResponse); err != nil {
			return fmt.Errorf("update existing dns record failed, %s", err)
		}
		return nil
	}

	// create new
	rrset := dns.ResourceRecordSet{
		Name:    name,
		Type:    rtype,
		Rrdatas: []string{content},
		Ttl:     int64(ttl),
	}
	log.SpanLog(ctx, log.DebugLevelInfra, "create dns record", "new", rrset)
	change := dns.Change{}
	change.Additions = []*dns.ResourceRecordSet{
		&rrset,
	}
	err = s.changeDNSRecords(ctx, zone, &change)
	if err != nil {
		return fmt.Errorf("failed to create dns entry for %s, %s", name, err)
	}
	return nil
}

func (s *CloudDNS) changeDNSRecords(ctx context.Context, zone string, change *dns.Change) error {
	mz, ok := s.zoneToName[zone]
	if !ok {
		return fmt.Errorf("no managed zone found for %s", zone)
	}
	resp, err := s.api.Changes.Create(s.project, mz, change).Context(ctx).Do()
	if err != nil {
		if googleapi.IsNotModified(err) {
			return nil
		}
		return err
	}
	if err := responseError(&resp.ServerResponse); err != nil {
		return err
	}
	return nil
}

func (s *CloudDNS) DeleteDNSRecord(ctx context.Context, zone, name string) error {
	mz, ok := s.zoneToName[zone]
	if !ok {
		return fmt.Errorf("no managed zone found for %s", zone)
	}
	if name == "" {
		return fmt.Errorf("no name specified to delete")
	}
	if !strings.HasSuffix(name, ".") {
		name += "."
	}

	change := dns.Change{}

	req := s.api.ResourceRecordSets.List(s.project, mz)
	err := req.Pages(ctx, func(page *dns.ResourceRecordSetsListResponse) error {
		for _, rrset := range page.Rrsets {
			if name != "" && name != rrset.Name {
				continue
			}
			// Note: ResourceRecordSet must match exactly to delete
			change.Deletions = append(change.Deletions, rrset)
		}
		return nil
	})
	if err != nil {
		return err
	}
	err = s.changeDNSRecords(ctx, zone, &change)
	if err != nil {
		return fmt.Errorf("failed to delete dns entries for %s, %s", name, err)
	}
	return nil
}

func responseError(resp *googleapi.ServerResponse) error {
	code := resp.HTTPStatusCode
	if code >= 200 && code < 300 {
		return nil
	}
	return fmt.Errorf("server returned %s", http.StatusText(code))
}
