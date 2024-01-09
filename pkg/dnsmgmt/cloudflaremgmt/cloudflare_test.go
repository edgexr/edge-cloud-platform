package cloudflaremgmt

import (
	"context"
	"os"
	"testing"

	"github.com/edgexr/edge-cloud-platform/pkg/dnsmgmt/dnsapitest"
	"github.com/edgexr/edge-cloud-platform/pkg/log"
	"github.com/stretchr/testify/require"
)

func TestCloudflareDNS(t *testing.T) {
	// skip unless needed to debug
	t.Skip("skipping cloudflare DNS test")

	log.SetDebugLevel(log.DebugLevelInfra)
	log.InitTracer(nil)
	defer log.FinishTracer()
	ctx := log.StartTestSpan(context.Background())

	key := os.Getenv("CFKEY")
	domain := os.Getenv("DOMAIN")

	if key == "" {
		t.Errorf("missing CFKEY environment variable")
	}
	if domain == "" {
		t.Errorf("missing DOMAIN environment variable")
	}

	prov, err := GetProvider(ctx, "", map[string]string{"token": key})
	require.Nil(t, err)
	dnsapitest.ProviderTest(t, ctx, prov, domain)
}
