// Copyright 2025 EdgeXR, Inc
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package promutils

import (
	"fmt"

	ssh "github.com/edgexr/golang-ssh"
)

// PromClient obfuscates how prometheus is accessed
type PromClient interface {
	// Send a GET request to promemtheus
	Get(path string) (string, error)
}

// CurlClient implements PromClient by sshing to a jump
// host and running a curl command against the prometheus address.
// This allows for accessing a prometheus server whose port is only
// exposed to the private jump host and not externally.
type CurlClient struct {
	promAddr string // ip:port
	client   ssh.Client
}

func NewCurlClient(promAddr string, client ssh.Client) *CurlClient {
	return &CurlClient{
		promAddr: promAddr,
		client:   client,
	}
}

func (s *CurlClient) Get(path string) (string, error) {
	// curl clients ssh to a node and run curl
	if path == "" {
		path = "/"
	}
	if path[0] != '/' {
		path = "/" + path
	}
	reqURI := "'http://" + s.promAddr + path + "'"
	out, err := s.client.Output("curl -s -S " + reqURI)
	if err != nil {
		return "", fmt.Errorf("failed to run <%s>, %v[%s]", reqURI, err, out)
	}
	return out, nil
}
