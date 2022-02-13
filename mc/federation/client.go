package federation

import (
	"context"
	"fmt"
	"net/http"
	"strings"

	"github.com/mobiledgex/edge-cloud-infra/mc/ormclient"
	"github.com/mobiledgex/edge-cloud/cloud-resource-manager/platform"
	"github.com/mobiledgex/edge-cloud/log"
	"github.com/mobiledgex/edge-cloud/tls"
)

const (
	APIKeyFromVault string = ""
)

type FederationClient struct {
	AccessApi platform.AccessApi
	UnitTest  bool
}

func NewClient(accessApi platform.AccessApi) (*FederationClient, error) {
	return &FederationClient{
		AccessApi: accessApi,
	}, nil
}

func (c *FederationClient) SendRequest(ctx context.Context, method, fedAddr, fedName, apiKey, endpoint string, reqData, replyData interface{}) error {
	if fedAddr == "" {
		return fmt.Errorf("Missing partner federation address")
	}
	if apiKey == APIKeyFromVault {
		// fetch partner API key from vault
		if fedName == "" {
			return fmt.Errorf("Missing partner federation name")
		}
		var err error
		apiKey, err = c.AccessApi.GetFederationAPIKey(ctx, fedName)
		if err != nil {
			return fmt.Errorf("Unable to fetch partner %q API key from vault: %s", fedName, err)
		}
	}

	if apiKey == "" {
		return fmt.Errorf("Missing partner federation API key from vault")
	}

	restClient := &ormclient.Client{}
	if c.UnitTest {
		restClient.ForceDefaultTransport = true
	}
	if tls.IsTestTls() {
		restClient.SkipVerify = true
	}
	if !strings.HasPrefix(fedAddr, "http") {
		fedAddr = "https://" + fedAddr
	}
	fedAddr = strings.TrimSuffix(fedAddr, "/")
	requestUrl := fmt.Sprintf("%s%s", fedAddr, endpoint)
	status, err := restClient.HttpJsonSend(method, requestUrl, apiKey, reqData, replyData)
	if err != nil {
		log.SpanLog(ctx, log.DebugLevelFedapi, "Federation API failed", "method", method, "url", requestUrl, "request", reqData, "response", replyData, "error", err)
		return err
	}
	log.SpanLog(ctx, log.DebugLevelFedapi, "Federation API success", "method", method, "url", requestUrl, "request", reqData, "response", replyData)
	if status != http.StatusOK {
		return fmt.Errorf("Failed to get response for %s request to URL %s, status=%s", method, requestUrl, http.StatusText(status))
	}
	return nil
}
