// Package dnsapi defines the common API interface for DNS managers
package dnsapi

import (
	"context"
)

const (
	RecordTypeA     = "A"
	RecordTypeAAAA  = "AAAA"
	RecordTypeCNAME = "CNAME"
)

// Provider common interface for managing DNS entries.
type Provider interface {
	// GetDNSRecords returns a list of DNS records. If name is
	// provided, that is used as a filter.
	GetDNSRecords(ctx context.Context, zone, name string) ([]Record, error)
	// CreateOrUpdateDNSRecord changes the existing record if found,
	// or adds a new one
	CreateOrUpdateDNSRecord(ctx context.Context, zone, name, rtype, content string, ttl int, proxy bool) error
	// DeleteDNSRecord deletes all DNS records for the name.
	DeleteDNSRecord(ctx context.Context, zone, name string) error
}

type GetProviderFunc = func(ctx context.Context, zone string, vaultData map[string]string) (Provider, error)

// Record represents a DNS record in a zone.
type Record struct {
	Type    string   `json:"type,omitempty"`
	Name    string   `json:"name,omitempty"`
	Content []string `json:"content,omitempty"`
	TTL     int      `json:"ttl,omitempty"`
}
