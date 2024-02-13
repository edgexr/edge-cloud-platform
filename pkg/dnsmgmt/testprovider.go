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

package dnsmgmt

import (
	"context"

	"github.com/edgexr/edge-cloud-platform/pkg/dnsmgmt/dnsapi"
	"github.com/edgexr/edge-cloud-platform/pkg/log"
)

type TestProvider struct{}

func (s *TestProvider) GetDNSRecords(ctx context.Context, zone, name string) ([]dnsapi.Record, error) {
	log.SpanLog(ctx, log.DebugLevelInfra, "DNS test provider get records", "zone", zone, "name", name)
	return []dnsapi.Record{}, nil
}

func (s *TestProvider) CreateOrUpdateDNSRecord(ctx context.Context, zone, name, rtype, content string, ttl int, proxy bool) error {
	log.SpanLog(ctx, log.DebugLevelInfra, "DNS test provider create or update record", "zone", zone, "name", name, "rtype", rtype)
	return nil
}

func (s *TestProvider) DeleteDNSRecord(ctx context.Context, zone, name string) error {
	log.SpanLog(ctx, log.DebugLevelInfra, "DNS test provider delete record", "zone", zone, "name", name)
	return nil
}
