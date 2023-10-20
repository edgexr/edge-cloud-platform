// Package toollib provides common helper functions for
// binary tools to run against a deployment for one-off upgrade
// funcs, etc.
package toollib

import (
	"fmt"
	"io/ioutil"
	"os"

	"github.com/edgexr/edge-cloud-platform/pkg/mc/ormclient"
	"github.com/edgexr/edge-cloud-platform/pkg/mcctl/mctestclient"
	"gopkg.in/yaml.v2"
)

type MCClient struct {
	Addr   string
	Token  string
	Client *mctestclient.Client
}

func GetMCClient(domain string) (*mctestclient.Client, string, string, error) {
	if domain == "" {
		domain = os.Getenv("DOMAIN")
	}
	if domain == "" {
		return nil, "", "", fmt.Errorf("please specify domain or set env var DOMAIN")
	}
	console := "https://console." + domain
	addr := console + "/api/v1"

	// prepare mc client
	mcClient := mctestclient.NewClient(&ormclient.Client{})
	home := os.Getenv("HOME")
	contents, err := ioutil.ReadFile(home + "/.mctoken.yml")
	if err != nil {
		return nil, "", "", err
	}
	tokens := map[string]string{}
	err = yaml.Unmarshal(contents, &tokens)
	if err != nil {
		return nil, "", "", err
	}
	token, ok := tokens[console]
	if !ok {
		return nil, "", "", fmt.Errorf("no token found for %s, please log in via mcctl", console)
	}
	return mcClient, addr, token, nil
}
