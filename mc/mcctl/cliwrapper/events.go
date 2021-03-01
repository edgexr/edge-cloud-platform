package cliwrapper

import (
	"github.com/mobiledgex/edge-cloud-infra/mc/ormapi"
	"github.com/mobiledgex/edge-cloud/cloudcommon/node"
	"github.com/mobiledgex/jaeger/plugin/storage/es/spanstore/dbmodel"
)

func (s *Client) ShowAppEvents(uri, token string, query *ormapi.RegionAppInstEvents) (*ormapi.AllMetrics, int, error) {
	args := []string{"billingevents", "app"}
	metrics := ormapi.AllMetrics{}
	st, err := s.runObjs(uri, token, args, query, &metrics)
	return &metrics, st, err
}
func (s *Client) ShowClusterEvents(uri, token string, query *ormapi.RegionClusterInstEvents) (*ormapi.AllMetrics, int, error) {
	args := []string{"billingevents", "cluster"}
	metrics := ormapi.AllMetrics{}
	st, err := s.runObjs(uri, token, args, query, &metrics)
	return &metrics, st, err
}

func (s *Client) ShowCloudletEvents(uri, token string, query *ormapi.RegionCloudletEvents) (*ormapi.AllMetrics, int, error) {
	args := []string{"billingevents", "cloudlet"}
	metrics := ormapi.AllMetrics{}
	st, err := s.runObjs(uri, token, args, query, &metrics)
	return &metrics, st, err
}

func (s *Client) ShowEvents(uri, token string, query *node.EventSearch) ([]node.EventData, int, error) {
	args := []string{"events", "show"}
	events := []node.EventData{}
	st, err := s.runObjs(uri, token, args, query, &events)
	return events, st, err
}

func (s *Client) FindEvents(uri, token string, query *node.EventSearch) ([]node.EventData, int, error) {
	args := []string{"events", "find"}
	events := []node.EventData{}
	st, err := s.runObjs(uri, token, args, query, &events)
	return events, st, err
}

func (s *Client) EventTerms(uri, token string, query *node.EventSearch) (*node.EventTerms, int, error) {
	args := []string{"events", "terms"}
	terms := node.EventTerms{}
	st, err := s.runObjs(uri, token, args, query, &terms)
	return &terms, st, err
}

func (s *Client) ShowSpans(uri, token string, query *node.SpanSearch) ([]node.SpanOutCondensed, int, error) {
	args := []string{"events", "showspans"}
	spans := []node.SpanOutCondensed{}
	st, err := s.runObjs(uri, token, args, query, &spans)
	return spans, st, err
}

func (s *Client) ShowSpansVerbose(uri, token string, query *node.SpanSearch) ([]dbmodel.Span, int, error) {
	args := []string{"events", "showspansverbose"}
	spans := []dbmodel.Span{}
	st, err := s.runObjs(uri, token, args, query, &spans)
	return spans, st, err
}

func (s *Client) SpanTerms(uri, token string, query *node.SpanSearch) (*node.SpanTerms, int, error) {
	args := []string{"events", "spanterms"}
	terms := node.SpanTerms{}
	st, err := s.runObjs(uri, token, args, query, &terms)
	return &terms, st, err
}
