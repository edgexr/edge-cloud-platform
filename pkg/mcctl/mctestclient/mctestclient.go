// Copyright 2022 MobiledgeX, Inc
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

package mctestclient

import "github.com/edgexr/edge-cloud-platform/mc/mcctl/ormctl"

type ClientRun interface {
	Run(apiCmd *ormctl.ApiCommand, runData *RunData)
	EnablePrintTransformations()
}

type RunData struct {
	Uri       string
	Token     string
	In        interface{}
	Out       interface{}
	RetStatus int
	RetError  error
}

type Client struct {
	ClientRun ClientRun
}

func NewClient(clientRun ClientRun) *Client {
	s := Client{}
	s.ClientRun = clientRun
	return &s
}