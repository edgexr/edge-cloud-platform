package cloudflaremgmt

import (
	"context"
	"os"
	"testing"

	cloudflare "github.com/cloudflare/cloudflare-go"
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

	api, err := cloudflare.NewWithAPIToken(key)
	require.Nil(t, err)
	prov := &CloudflareAPI{
		api: api,
	}
	dnsapitest.ProviderTest(t, ctx, prov, domain)
}
