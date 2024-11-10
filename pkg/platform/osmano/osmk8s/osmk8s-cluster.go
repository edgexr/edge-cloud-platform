// Copyright 2024 EdgeXR, Inc
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

package osmk8s

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/edgexr/edge-cloud-platform/api/edgeproto"
	"github.com/edgexr/edge-cloud-platform/pkg/cloudcommon"
	"github.com/edgexr/edge-cloud-platform/pkg/log"
	"github.com/edgexr/edge-cloud-platform/pkg/platform/osmano/osmapi"
	"gopkg.in/yaml.v2"
)

const (
	ClusterNameAnnotation = "clusterName"
	ClusterIDAnnotation   = "clusterID"
)

const ClusterActionTimeout = 20 * time.Minute
const WaitForClusterDoneInterval = 30 * time.Second

type createClusterResp struct {
	ID string `json:"_id"`
}

type GetClusterInfo struct {
	ID             string          `json:"_id"`
	Name           string          `json:"name"`
	State          string          `json:"state"`
	OperatingState string          `json:"operatingState"`
	ResourceState  string          `json:"resourceState"`
	Credentials    json.RawMessage `json:"credentials,omitempty"`
}

func (s *Platform) CreateClusterPrerequisites(ctx context.Context, clusterName string) error {
	return nil
}

func (s *Platform) RunClusterCreateCommand(ctx context.Context, clusterName string, clusterInst *edgeproto.ClusterInst) (map[string]string, error) {
	log.SpanLog(ctx, log.DebugLevelInfra, "Create Cluster", "clusterName", clusterName, "vim", s.getVIMAccount(), "region", s.getRegion())
	client, err := s.getClient(ctx)
	if err != nil {
		return nil, err
	}
	pool := clusterInst.NodePools[0]

	nodeCount := int(pool.NumNodes)
	regionName := s.getRegion()
	vimAccount := s.getVIMAccount()
	resourceGroup := s.getResourceGroup()
	kubeVersion := clusterInst.KubernetesVersion
	if kubeVersion == "" {
		kubeVersion = "1.29"
	}

	createCluster := osmapi.CreateClusterInfo{
		Name:          &clusterName,
		NodeSize:      &pool.NodeResources.InfraNodeFlavor,
		NodeCount:     &nodeCount,
		RegionName:    &regionName,
		VimAccount:    &vimAccount,
		ResourceGroup: &resourceGroup,
		K8sVersion:    &kubeVersion,
		Description:   &clusterName,
	}
	log.SpanLog(ctx, log.DebugLevelInfra, "creating OSM cluster", "clusterName", clusterName, "req", createCluster)
	resp, err := client.Createk8sClusterWithResponse(ctx, createCluster)
	if err != nil {
		return nil, fmt.Errorf("create cluster %s failed, %s", clusterName, err)
	}
	if resp.StatusCode() != http.StatusCreated {
		return nil, fmt.Errorf("create cluster %s failed (%d), %s", clusterName, resp.StatusCode(), string(resp.Body))
	}
	infraAnnotations := map[string]string{}
	id := ""
	if resp.JSON201 != nil && resp.JSON201.Id != nil {
		id = resp.JSON201.Id.String()
	} else {
		// TODO: OpenAPI spec is wrong, it defines response with
		// "id" but OSM actually returns "_id"
		log.SpanLog(ctx, log.DebugLevelInfra, "missing expected cluster ID", "resp", string(resp.Body))
		idresp := createClusterResp{}
		err := json.Unmarshal(resp.Body, &idresp)
		if err == nil && idresp.ID != "" {
			id = idresp.ID
		}
	}
	if id == "" {
		return nil, fmt.Errorf("create cluster %s failed to determine created cluster id", clusterName)
	}
	log.SpanLog(ctx, log.DebugLevelInfra, "created cluster", "clusterName", clusterName, "id", id)
	infraAnnotations[ClusterIDAnnotation] = id

	// wait for cluster ready
	if err := s.waitForClusterDone(ctx, clusterName, id, cloudcommon.Create); err != nil {
		return infraAnnotations, err
	}
	return infraAnnotations, nil
}

func (s *Platform) RunClusterDeleteCommand(ctx context.Context, clusterName string, clusterInst *edgeproto.ClusterInst) error {
	log.SpanLog(ctx, log.DebugLevelInfra, "Delete Cluster", "clusterName", clusterName, "vim", s.getVIMAccount(), "region", s.getRegion())
	client, err := s.getClient(ctx)
	if err != nil {
		return err
	}
	id, err := s.getClusterID(ctx, clusterName, clusterInst)
	if err != nil {
		return err
	}
	resp, err := client.Deletek8sClusterWithResponse(ctx, id)
	if err != nil {
		return fmt.Errorf("failed to delete cluster %s, %s", clusterName, err)
	}
	if resp.StatusCode() != http.StatusAccepted {
		return fmt.Errorf("failed to delete cluster %s (%d), %s", clusterName, resp.StatusCode(), string(resp.Body))
	}
	// wait for cluster to be deleted
	if err := s.waitForClusterDone(ctx, clusterName, id, cloudcommon.Delete); err != nil {
		return err
	}
	return nil
}

func (s *Platform) waitForClusterDone(ctx context.Context, clusterName, clusterID string, action cloudcommon.Action) error {
	endTime := time.Now().Add(ClusterActionTimeout)
	msg := "ready"
	if action == cloudcommon.Delete {
		msg = "deleted"
	}
	curState := "unknown"
	credsFound := false
	for {
		if time.Now().After(endTime) {
			// timeout is not an error, maybe we just didn't wait
			// long enough.
			log.SpanLog(ctx, log.DebugLevelInfra, "timed out waiting for cluster state", "cluster", clusterName, "id", clusterID, "target", msg, "curState", curState)
			return nil
		}
		info, status, err := s.getClusterInfo(ctx, clusterName, clusterID)
		if err != nil {
			return err
		}
		if status == http.StatusNotFound {
			if action == cloudcommon.Delete {
				return nil
			}
			return fmt.Errorf("wait for cluster done, cluster %s (%s) not found", clusterName, clusterID)
		}
		curState = info.ResourceState
		if action == cloudcommon.Create && curState == "READY" {
			// cluster gets marked ready before it's actually ready
			// We can check when it's actually ready if we check
			// for the kubeconfig
			creds, err := s.getCredentialsRaw(ctx, clusterName, clusterID)
			if err != nil {
				return err
			}
			if len(creds) > 0 {
				return nil
			}
		}
		// delete waits until cluster is not found
		log.SpanLog(ctx, log.DebugLevelInfra, "wait for cluster done", "clusterName", clusterName, "id", clusterID, "curState", curState, "credsFound", credsFound)
		time.Sleep(WaitForClusterDoneInterval)
	}
}

func (s *Platform) getClusterInfo(ctx context.Context, clusterName, clusterID string) (*GetClusterInfo, int, error) {
	client, err := s.getClient(ctx)
	if err != nil {
		return nil, 0, err
	}
	// TODO: OpenAPI spec is wrong, it doesn't define any response data,
	// so we need to define and parse the response ourselves.
	resp, err := client.Readk8sClusterWithResponse(ctx, clusterID)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to get cluster status, %s", err)
	}
	if resp.StatusCode() == http.StatusNotFound {
		// this is ok for delete case
		return nil, http.StatusNotFound, nil
	}
	if resp.StatusCode() != http.StatusOK {
		return nil, resp.StatusCode(), fmt.Errorf("failed to get cluster %s status (%d), %s", clusterName, resp.StatusCode(), string(resp.Body))
	}
	info := GetClusterInfo{}
	if err := json.Unmarshal(resp.Body, &info); err != nil {
		return nil, resp.StatusCode(), fmt.Errorf("failed to unmarshal get cluster response, %s, %s", err, string(resp.Body))
	}
	return &info, resp.StatusCode(), nil
}

func (s *Platform) GetCredentials(ctx context.Context, clusterName string, clusterInst *edgeproto.ClusterInst) ([]byte, error) {
	id, err := s.getClusterID(ctx, clusterName, clusterInst)
	if err != nil {
		return nil, err
	}
	jsonData, err := s.getCredentialsRaw(ctx, clusterName, id)
	if err != nil {
		return nil, err
	}
	if len(jsonData) == 0 {
		return nil, fmt.Errorf("no credentials found for cluster %s", clusterName)
	}
	// credentials are in json, convert to desired yaml format
	dat := map[string]any{}
	if err := json.Unmarshal(jsonData, &dat); err != nil {
		return nil, fmt.Errorf("failed to json unmarshal cluster credentials, %s", err)
	}
	kconf, err := yaml.Marshal(dat)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal cluster credentials to yaml, %s", err)
	}
	return kconf, nil
}

func (s *Platform) getCredentialsRaw(ctx context.Context, clusterName, clusterID string) ([]byte, error) {
	client, err := s.getClient(ctx)
	if err != nil {
		return nil, err
	}
	// TODO: Openapi spec doesn't define a 200 response, so we can't
	// use the "WithResponse" version of the auto-generated API.
	resp, err := client.GetCreds(ctx, clusterID)
	if err != nil {
		return nil, fmt.Errorf("failed to get cluster %s credentials, %s", clusterName, err)
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("get creds failed to read response body, %s", err)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("failed to get creds for cluster %s, %d %s", clusterName, resp.StatusCode, string(data))
	}
	info := GetClusterInfo{}
	if err := json.Unmarshal(data, &info); err != nil {
		return nil, fmt.Errorf("failed to unmarshal get creds json data, %s", err)
	}
	return info.Credentials, nil
}

func (s *Platform) GetCloudletInfraResourcesInfo(ctx context.Context) ([]edgeproto.InfraResource, error) {
	return []edgeproto.InfraResource{}, nil
}

// GetClusterAdditionalResources is called by controller, make sure it doesn't make any calls to infra API
func (s *Platform) GetClusterAdditionalResources(ctx context.Context, cloudlet *edgeproto.Cloudlet, vmResources []edgeproto.VMResource) map[string]edgeproto.InfraResource {
	return nil
}

func (s *Platform) GetClusterAdditionalResourceMetric(ctx context.Context, cloudlet *edgeproto.Cloudlet, resMetric *edgeproto.Metric, resources []edgeproto.VMResource) error {
	return nil
}

func (s *Platform) getClusterID(ctx context.Context, clusterName string, clusterInst *edgeproto.ClusterInst) (string, error) {
	id, ok := clusterInst.InfraAnnotations[ClusterIDAnnotation]
	if !ok {
		// try to look it up by name
		info, err := s.lookupCluster(ctx, clusterName)
		if err != nil {
			return "", err
		}
		if info.ID == "" {
			return "", fmt.Errorf("found cluster %s but ID is blank", clusterName)
		}
		id = info.ID
	}
	log.SpanLog(ctx, log.DebugLevelInfra, "got cluster id", "clusterName", clusterName, "id", id)
	return id, nil
}

func (s *Platform) lookupCluster(ctx context.Context, clusterName string) (*GetClusterInfo, error) {
	clusters, err := s.listClusters(ctx)
	if err != nil {
		return nil, err
	}
	for _, cluster := range clusters {
		if cluster.Name == clusterName {
			return cluster, nil
		}
	}
	return nil, fmt.Errorf("cluster %s not found", clusterName)
}

func (s *Platform) listClusters(ctx context.Context) ([]*GetClusterInfo, error) {
	client, err := s.getClient(ctx)
	if err != nil {
		return nil, err
	}

	// TODO: once OpenAPI spec is fixed, we can use the "WithReseponse"
	// version of the API.
	if true {
		// listClusters openapi spec doesn't specify StatusOK data, so trying
		// to use the "WithResponse" version of the auto-generated API will
		// generate JSON parse errors.
		resp, err := client.Listk8sCluster(ctx)
		if err != nil {
			return nil, err
		}
		defer resp.Body.Close()
		data, err := io.ReadAll(resp.Body)
		if err != nil {
			return nil, fmt.Errorf("failed to read list cluster response body, %s", err)
		}
		if resp.StatusCode != http.StatusOK {
			return nil, fmt.Errorf("list clusters failed (%d) %s", resp.StatusCode, string(data))
		}
		clusters := []*GetClusterInfo{}
		if err := json.Unmarshal(data, &clusters); err != nil {
			return nil, fmt.Errorf("failed to unmarshal cluster list, %s", err)
		}
		return clusters, nil
	}
	resp, err := client.Listk8sClusterWithResponse(ctx)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode() != http.StatusOK {
		return nil, fmt.Errorf("list clusters failed (%d) %s", resp.StatusCode(), string(resp.Body))
	}
	// TODO:
	// return resp.JSON200, but openapi spec doesn't define it yet.
	return nil, fmt.Errorf("unsupported")
}
