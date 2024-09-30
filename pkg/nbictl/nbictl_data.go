// Copyright 2024 EdgeXR, Inc
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Package nbictl provides client functions for accessing the NBI
// (north bound interface)
package nbictl

import (
	"context"
	"crypto/tls"
	"net/http"

	"github.com/edgexr/edge-cloud-platform/api/nbi"
	"github.com/edgexr/edge-cloud-platform/pkg/cloudcommon"
)

type AppInst struct {
	AppID    nbi.AppId    `json:"appid"`
	AppZones nbi.AppZones `json:"appzones"`
}

type ApplyData struct {
	Apps     []nbi.AppManifest `json:"apps,omitempty"`
	AppInsts []AppInst         `json:"appinsts,omitempty"`
}

type GetData struct {
	Apps     []nbi.AppManifest     `json:"apps,omitempty"`
	AppInsts []nbi.AppInstanceInfo `json:"appinsts,omitempty"`
	Zones    []nbi.EdgeCloudZone   `json:"zones,omitempty"`
}

type APIErr struct {
	Desc   string
	Status int
	Err    error
}

func getURL(addr string) string {
	return addr + cloudcommon.NBIRootPath
}

func BasicClient(addr, bearerToken string, skipVerify bool) (*nbi.ClientWithResponses, error) {
	url := getURL(addr)
	customize := func(client *nbi.Client) error {
		if skipVerify {
			client.Client = &http.Client{
				Transport: &http.Transport{
					TLSClientConfig: &tls.Config{
						InsecureSkipVerify: true,
					},
				},
			}
		}
		if bearerToken != "" {
			addToken := func(ctx context.Context, req *http.Request) error {
				req.Header.Add("Authorization", "Bearer "+bearerToken)
				return nil
			}
			client.RequestEditors = append(client.RequestEditors, addToken)
		}
		return nil
	}
	return nbi.NewClientWithResponses(url, customize)
}
