package chargify

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"

	"github.com/mobiledgex/edge-cloud/vault"
)

type BillingService struct{}

type accountCreds struct {
	ApiKey string `json:"apikey"`
	Url    string `json:"url"`
}

func (bs *BillingService) Init(ctx context.Context, vaultConfig *vault.Config, path string) error {
	creds := accountCreds{}
	err := vault.GetData(vaultConfig, vaultPath+path, 0, &creds)
	if err != nil && !strings.Contains(err.Error(), "no secrets") {
		return err
	}
	apiKey = creds.ApiKey
	siteName = creds.Url

	// if the creds weren't in vault check env vars
	if apiKey == "" {
		apiKey = os.Getenv("CHARGIFY_API_KEY")
	}
	if apiKey == "" {
		return fmt.Errorf("unable to get apiKey")
	}
	if siteName == "" {
		siteName = os.Getenv("CHARGIFY_SITE_NAME")
	}
	if siteName == "" {
		return fmt.Errorf("unable to get siteName")
	}

	// since we can potentially be sending stuff like credit card info, make sure the url is secure
	if !strings.Contains(siteName, "https") {
		return fmt.Errorf("insecure chargify site")
	}

	return nil
}

func (bs *BillingService) GetType() string {
	return "chargify"
}

func newChargifyReq(method, endpoint string, payload interface{}) (*http.Response, error) {
	url := siteName + endpoint
	var body io.Reader
	if payload != nil {
		marshalled, err := json.Marshal(payload)
		if err != nil {
			return nil, fmt.Errorf("Could not marshal %+v, err: %v", payload, err)
		}
		body = bytes.NewReader(marshalled)
	} else {
		body = strings.NewReader("{}")
	}
	req, err := http.NewRequest(method, url, body)
	if err != nil {
		return nil, fmt.Errorf("Error creating request: %v\n", err)
	}
	req.SetBasicAuth(apiKey, apiPassword)
	if payload != nil {
		req.Header.Set("Content-Type", "application/json")
	}

	client := &http.Client{}
	return client.Do(req)
}
