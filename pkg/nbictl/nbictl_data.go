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
	"github.com/edgexr/edge-cloud-platform/api/nbi"
)

// CreateAppInst adds additional fields to the NBI data to allow for
// declarative and infrastructure-as-code input.
type CreateAppInst struct {
	nbi.CreateAppInstanceJSONBody
	AppName           string `json:"appname,omitempty"`
	AppProvider       string `json:"appprovider,omitempty"`
	AppVersion        string `json:"appversion,omitempty"`
	EdgeCloudZoneName string `json:"zonename,omitempty"`
	EdgeCloudProvider string `json:"edgecloudprovider,omitempty"`
	ClusterName       string `json:"clustername,omitempty"`
	ClusterProvider   string `json:"clusterprovider,omitempty"`
}

// DeleteAppInst adds additional fields to the NBI data to allow for
// declarative and infrastructure-as-code input.
type DeleteAppInst struct {
	ID          string `json:"id,omitempty"`
	Name        string `json:"name,omitempty"`
	AppProvider string `json:"appprovider,omitempty"`
}

type ApplyData struct {
	Apps     []nbi.AppManifest `json:"apps,omitempty"`
	AppInsts []CreateAppInst   `json:"appinsts,omitempty"`
}

type GetData struct {
	Apps     []nbi.AppManifest    `json:"apps,omitempty"`
	AppInsts []GetAppInstanceInfo `json:"appinsts,omitempty"`
	Zones    []nbi.EdgeCloudZone  `json:"zones,omitempty"`
	Clusters []GetClusterInfo     `json:"clusters,omitempty"`
}

// GetAppInstanceInfo adds additional fields to the NBI data to allow
// for declarative and infrastructure-as-code output.
type GetAppInstanceInfo struct {
	nbi.AppInstanceInfo
	AppName           string `json:"appname,omitempty"`
	EdgeCloudZoneName string `json:"zonename,omitempty"`
	EdgeCloudProvider string `json:"edgecloudprovider,omitempty"`
	ClusterName       string `json:"clustername,omitempty"`
	ClusterProvider   string `json:"clusterprovider,omitempty"`
}

// GetClusterInfo adds additional fields to the NBI data to allow
// for declarative and infrastructure-as-code output.
type GetClusterInfo struct {
	nbi.ClusterInfo
	EdgeCloudZoneName string `json:"zonename,omitempty"`
	EdgeCloudProvider string `json:"edgecloudprovider,omitempty"`
	ClusterName       string `json:"clustername,omitempty"`
	ClusterProvider   string `json:"clusterprovider,omitempty"`
}

type DeleteData struct {
	Apps     []nbi.AppManifest `json:"apps,omitempty"`
	AppInsts []DeleteAppInst   `json:"appinsts,omitempty"`
}

type APIErr struct {
	Desc   string
	Status int
	Err    string
}
