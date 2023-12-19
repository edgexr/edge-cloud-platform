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
