package dnsapitest

import (
	"context"
	"testing"

	"github.com/edgexr/edge-cloud-platform/pkg/dnsmgmt/dnsapi"
	"github.com/stretchr/testify/require"
)

func ProviderTest(t *testing.T, ctx context.Context, prov dnsapi.Provider, domain string) {
	testEntry := "unittest." + domain

	// create test entry
	ip := "127.0.0.1"
	err := prov.CreateOrUpdateDNSRecord(ctx, domain, testEntry, "A", ip, 3000, false)
	require.Nil(t, err)
	// check that it was created
	records, err := prov.GetDNSRecords(ctx, domain, testEntry)
	require.Nil(t, err)
	require.Equal(t, 1, len(records))
	require.Equal(t, testEntry, records[0].Name)
	require.Equal(t, 1, len(records[0].Content))
	require.Equal(t, ip, records[0].Content[0])

	// test updating existing entry
	ip = "192.0.0.1"
	err = prov.CreateOrUpdateDNSRecord(ctx, domain, testEntry, "A", ip, 3000, false)
	require.Nil(t, err)
	// check that it was updated
	records, err = prov.GetDNSRecords(ctx, domain, testEntry)
	require.Nil(t, err)
	require.Equal(t, 1, len(records))
	require.Equal(t, testEntry, records[0].Name)
	require.Equal(t, 1, len(records[0].Content))
	require.Equal(t, ip, records[0].Content[0])

	// delete the entry
	err = prov.DeleteDNSRecord(ctx, domain, testEntry)
	require.Nil(t, err)

	// verify it was deleted
	records, err = prov.GetDNSRecords(ctx, domain, testEntry)
	require.Nil(t, err)
	require.Equal(t, 0, len(records))
}
