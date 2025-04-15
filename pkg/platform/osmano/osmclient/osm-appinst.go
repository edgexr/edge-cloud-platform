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

package osmclient

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/edgexr/edge-cloud-platform/api/edgeproto"
	"github.com/edgexr/edge-cloud-platform/pkg/cloudcommon"
	"github.com/edgexr/edge-cloud-platform/pkg/k8smgmt"
	"github.com/edgexr/edge-cloud-platform/pkg/log"
)

type AppProfileInfo struct {
	ID      string `json:"_id,omitempty"`
	Name    string `json:"name,omitempty"`
	Default bool   `json:"default,omitempty"`
}

func (s *OSMClient) ListAppProfiles(ctx context.Context) ([]AppProfileInfo, error) {
	client, err := s.GetClient(ctx)
	if err != nil {
		return nil, err
	}
	appProfiles := []AppProfileInfo{}

	resp, err := client.ListAppProfile(ctx)
	err = mustResp("list app-profile", resp, err, http.StatusOK, &appProfiles)
	if err != nil {
		return nil, err
	}
	return appProfiles, nil
}

func (s *OSMClient) GetAppProfile(ctx context.Context, name string) (*AppProfileInfo, error) {
	list, err := s.ListAppProfiles(ctx)
	if err != nil {
		return nil, err
	}
	for _, prof := range list {
		if prof.Name == name {
			return &prof, nil
		}
	}
	return nil, nil
}

func getOSMAppInstName(appInst *edgeproto.AppInst) string {
	return NameSanitize(fmt.Sprintf("%s-%s", appInst.Key.Organization, appInst.Key.Name))
}

type ArrayOfKsu struct {
	Ksus []Ksu `json:"ksus,omitempty"`
}

type Ksu struct {
	ID             string     `json:"_id,omitempty"`
	Description    string     `json:"description,omitempty"`
	Name           string     `json:"name,omitempty"`
	Oka            []KsuOka   `json:"oka,omitempty"`
	Profile        KsuProfile `json:"profile,omitempty"`
	ResourceState  string     `json:"resourceState,omitempty"`
	OperatingState string     `json:"operatingState,omitempty"`
}

type KsuOka struct {
	ID             string         `json:"_id,omitempty"`
	Transformation map[string]any `json:"transformation,omitempty"`
}

type KsuProfile struct {
	ID          string `json:"_id,omitempty"`
	ProfileType string `json:"profile_type,omitempty"`
}

type CreateKsuResp struct {
	IDs []string `json:"_id,omitempty"`
}

func (s *OSMClient) CreateAppInst(ctx context.Context, names *k8smgmt.KubeNames, clusterName string, app *edgeproto.App, appInst *edgeproto.AppInst) (string, error) {
	name := getOSMAppInstName(appInst)

	cluster, err := s.FindClusterInfo(ctx, clusterName)
	if err != nil {
		return "", err
	}
	if len(cluster.AppProfiles) == 0 {
		return "", fmt.Errorf("cluster %s has no app profiles", clusterName)
	}

	oka, err := s.CreateApp(ctx, app)
	if err != nil {
		return "", err
	}

	client, err := s.GetClient(ctx)
	if err != nil {
		return "", err
	}
	ns := names.InstanceNamespace
	if ns == "" {
		ns = k8smgmt.DefaultNamespace
	}

	ksu := Ksu{}
	ksu.Name = name
	ksu.Description = name
	ksu.Oka = []KsuOka{{
		ID: oka.ID,
		Transformation: map[string]any{
			"namespace": ns,
		},
	}}
	ksu.Profile.ID = cluster.AppProfiles[0]
	ksu.Profile.ProfileType = "app_profiles"
	req := ArrayOfKsu{
		Ksus: []Ksu{
			ksu,
		},
	}
	out, err := json.Marshal(&req)
	if err != nil {
		return "", fmt.Errorf("failed to marshal create KSU request, %s", err)
	}
	rdr := bytes.NewReader(out)
	resp, err := client.AddKSUWithBody(ctx, "application/json", rdr)
	createResp := CreateKsuResp{}
	err = mustResp("add KSU", resp, err, http.StatusAccepted, &createResp)
	if err != nil {
		return "", err
	}
	if len(createResp.IDs) == 0 {
		return "", fmt.Errorf("no IDs returned from create KSU app instance")
	}
	_, err = s.waitAppInstStatus(ctx, name, cloudcommon.Create)
	if err != nil {
		return "", err
	}

	return createResp.IDs[0], nil
}

func (s *OSMClient) DeleteAppInst(ctx context.Context, appInst *edgeproto.AppInst) error {
	name := getOSMAppInstName(appInst)
	ksu, err := s.FindKSU(ctx, name)
	if err != nil {
		return nil
	}
	if ksu == nil {
		return nil
	}
	client, err := s.GetClient(ctx)
	if err != nil {
		return err
	}
	resp, err := client.DeleteKSU(ctx, ksu.ID)
	err = mustResp("delete KSU", resp, err, http.StatusAccepted, nil)
	if err != nil {
		return err
	}
	_, err = s.waitAppInstStatus(ctx, name, cloudcommon.Delete)
	return err
}

func (s *OSMClient) ListKSU(ctx context.Context) ([]Ksu, error) {
	client, err := s.GetClient(ctx)
	if err != nil {
		return nil, err
	}
	ksus := []Ksu{}
	resp, err := client.GetKSU(ctx)
	err = mustResp("get KSU", resp, err, http.StatusOK, &ksus)
	if err != nil {
		return nil, err
	}
	return ksus, nil
}

func (s *OSMClient) FindKSU(ctx context.Context, name string) (*Ksu, error) {
	ksus, err := s.ListKSU(ctx)
	if err != nil {
		return nil, err
	}
	for _, ksu := range ksus {
		if ksu.Name == name {
			return &ksu, nil
		}
	}
	return nil, nil
}

func (s *OSMClient) ReadKSU(ctx context.Context, id string) (*Ksu, error) {
	client, err := s.GetClient(ctx)
	if err != nil {
		return nil, err
	}
	desc := "read KSU"
	ksu := Ksu{}
	resp, err := client.ReadKSU(ctx, id)
	status, body, err := readResp(desc, resp, err)
	if err != nil {
		return nil, err
	}
	if status == http.StatusOK {
		err := parseResp(desc, body, &ksu)
		if err != nil {
			return nil, err
		}
		return &ksu, nil
	} else if status == http.StatusNotFound {
		return nil, nil
	}
	return nil, fmt.Errorf("failed to %s (%d), %s", desc, status, string(body))
}

func (s *OSMClient) waitAppInstStatus(ctx context.Context, name string, action cloudcommon.Action) (*Ksu, error) {
	var retryDelay time.Duration
	if action == cloudcommon.Create {
		retryDelay = 12 * time.Second
	} else {
		retryDelay = 6 * time.Second
	}
	ksu, err := s.FindKSU(ctx, name)
	if err != nil {
		return nil, err
	}
	id := ksu.ID
	resState := "unknown"
	for ii := 0; ii < 100; ii++ {
		if err := ctx.Err(); err != nil {
			log.SpanLog(ctx, log.DebugLevelInfra, "context error, aborting wait for appinst", "name", name, "err", err)
			return nil, err
		}
		ksu, err = s.ReadKSU(ctx, id)
		if err != nil {
			log.SpanLog(ctx, log.DebugLevelInfra, "check appinst status failed", "name", name, "err", err)
			resState = err.Error()
		} else if ksu == nil {
			log.SpanLog(ctx, log.DebugLevelInfra, "check appinst status not found", "name", name)
			if action == cloudcommon.Delete {
				// desired final state for delete
				return nil, nil
			}
			resState = "not found"
		} else {
			// found
			log.SpanLog(ctx, log.DebugLevelInfra, "check appinst status", "name", name, "resourceState", ksu.ResourceState, "operatingState", ksu.OperatingState)
			resState = ksu.ResourceState
			if action == cloudcommon.Create {
				if resState == RESOURCE_STATE_READY {
					// desired final state for create
					return ksu, nil
				} else if resState == RESOURCE_STATE_ERROR {
					return nil, fmt.Errorf("ksu in error state")
				}
			}
		}
		time.Sleep(retryDelay)
	}
	return nil, fmt.Errorf("timed out waiting for OKA app state, current state is: %s", resState)
}
