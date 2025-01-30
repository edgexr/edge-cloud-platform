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
	"io"
	"net/http"
	"time"

	"github.com/edgexr/edge-cloud-platform/api/edgeproto"
	"github.com/edgexr/edge-cloud-platform/pkg/cloudcommon"
	"github.com/edgexr/edge-cloud-platform/pkg/log"
	"github.com/edgexr/edge-cloud-platform/pkg/platform/osmano/osmapi"
	"gopkg.in/yaml.v3"
)

const (
	ClusterNameAnnotation = "clusterName"
	ClusterIDAnnotation   = "clusterID"
)

const ClusterActionTimeout = 20 * time.Minute
const WaitForClusterDoneInterval = 30 * time.Second

type GetClusterInfo struct {
	ID             string          `json:"_id"`
	Name           string          `json:"name"`
	State          string          `json:"state"`
	OperatingState string          `json:"operatingState"`
	ResourceState  string          `json:"resourceState"`
	Credentials    json.RawMessage `json:"credentials,omitempty"`
	AppProfiles    []string        `json:"app_profiles,omitempty"`
	NodeSize       string          `json:"node_size"`
	NodeCount      int             `json:"node_count"`
	RegionName     string          `json:"region_name"`
	ResourceGroup  string          `json:"resource_group"`
	VimAccount     string          `json:"vim_account"`
	K8SVersion     string          `json:"k8s_version"`
	Bootstrap      bool            `json:"bootstrap"`
}

type createClusterResp struct {
	ID string `json:"_id"`
}

func (s *OSMClient) CreateCluster(ctx context.Context, clusterName string, clusterInst *edgeproto.ClusterInst) (string, error) {
	log.SpanLog(ctx, log.DebugLevelInfra, "Create Cluster", "clusterName", clusterName, "vim", s.getVIMAccount(), "region", s.getRegion())
	client, err := s.GetClient(ctx)
	if err != nil {
		return "", err
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

	bootstrap := true
	createCluster := osmapi.CreateClusterInfo{
		Name:          &clusterName,
		NodeSize:      &pool.NodeResources.InfraNodeFlavor,
		NodeCount:     &nodeCount,
		RegionName:    &regionName,
		VimAccount:    &vimAccount,
		ResourceGroup: &resourceGroup,
		K8sVersion:    &kubeVersion,
		Description:   &clusterName,
		Bootstrap:     &bootstrap,
	}
	// check if cluster already exists in case our state is out
	// of sync with OSM
	var id string
	existing, err := s.FindClusterInfo(ctx, clusterName)
	if err == nil && existing != nil {
		if *createCluster.NodeSize == existing.NodeSize &&
			*createCluster.NodeCount == existing.NodeCount &&
			*createCluster.RegionName == existing.RegionName &&
			*createCluster.VimAccount == existing.VimAccount &&
			*createCluster.ResourceGroup == existing.ResourceGroup &&
			*createCluster.K8sVersion == existing.K8SVersion &&
			*createCluster.Bootstrap == existing.Bootstrap {
			// already exists
			log.SpanLog(ctx, log.DebugLevelInfra, "cluster already exists and matches", "cluster", clusterName)
			id = existing.ID
		} else {
			return "", fmt.Errorf("cluster %s already exists, want %v but is %v", clusterName, createCluster, existing)
		}
	} else {
		log.SpanLog(ctx, log.DebugLevelInfra, "creating OSM cluster", "clusterName", clusterName, "req", createCluster)
		resp, err := client.Createk8sCluster(ctx, createCluster)
		// TODO: OpenAPI spec is wrong, it defines response with
		// "id" but OSM actually returns "_id"
		idresp := createClusterResp{}
		err = mustResp("create cluster "+clusterName, resp, err, http.StatusCreated, &idresp)
		if err != nil {
			return "", err
		}
		id = idresp.ID
		if id == "" {
			return "", fmt.Errorf("create cluster %s failed to determine created cluster id", clusterName)
		}
	}
	err = s.waitForClusterDone(ctx, clusterName, id, cloudcommon.Create, ClusterActionTimeout, WaitForClusterDoneInterval)
	if err != nil {
		return "", err
	}
	log.SpanLog(ctx, log.DebugLevelInfra, "created cluster", "clusterName", clusterName, "id", id)
	return id, nil
}

func (s *OSMClient) DeleteCluster(ctx context.Context, clusterName string, clusterInst *edgeproto.ClusterInst) error {
	log.SpanLog(ctx, log.DebugLevelInfra, "Delete Cluster", "clusterName", clusterName, "vim", s.getVIMAccount(), "region", s.getRegion())
	client, err := s.GetClient(ctx)
	if err != nil {
		return err
	}
	id, err := s.GetClusterID(ctx, clusterName, clusterInst)
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
	if err := s.waitForClusterDone(ctx, clusterName, id, cloudcommon.Delete, ClusterActionTimeout, WaitForClusterDoneInterval); err != nil {
		return err
	}
	return nil
}

func (s *OSMClient) ScaleCluster(ctx context.Context, clusterName string, clusterInst *edgeproto.ClusterInst) error {
	log.SpanLog(ctx, log.DebugLevelInfra, "Scale Cluster", "clusterName", clusterName, "vim", s.getVIMAccount(), "region", s.getRegion())
	client, err := s.GetClient(ctx)
	if err != nil {
		return err
	}
	id, err := s.GetClusterID(ctx, clusterName, clusterInst)
	if err != nil {
		return err
	}
	// scale cluster nodes
	// mk8s provider only supports one node pool, so we
	// just look at the first pool
	newNumNodes := int(clusterInst.NodePools[0].NumNodes)
	scale := osmapi.ScaleNodeInfo{
		NodeCount: &newNumNodes,
	}
	resp, err := client.NodeScalingWithResponse(ctx, id, scale)
	if err != nil {
		return fmt.Errorf("failed to scale cluster %s, %s", clusterName, err)
	}
	if resp.StatusCode() != http.StatusCreated {
		return fmt.Errorf("failed to scale cluster %s (%d), %s", clusterName, resp.StatusCode(), string(resp.Body))
	}
	// wait for cluster ready
	if err := s.waitForClusterDone(ctx, clusterName, id, cloudcommon.Create, ClusterActionTimeout, WaitForClusterDoneInterval); err != nil {
		return err
	}
	return nil
}

type RegisterClusterInfo struct {
	Bootstrap   *bool           `json:"bootstrap,omitempty"`
	Credentials json.RawMessage `json:"credentials,omitempty"`
	Description *string         `json:"description,omitempty"`
	Name        *string         `json:"name,omitempty"`
	VimAccount  *string         `json:"vim_account,omitempty"`
}

func (s *OSMClient) RegisterCluster(ctx context.Context, clusterName, kubeconfig string) (string, error) {
	vim, ok := s.Properties.GetValue(OSM_VIM_ACCOUNT)
	if !ok || vim == "" {
		return "", fmt.Errorf("OSM VIM account property not set")
	}
	client, err := s.GetClient(ctx)
	if err != nil {
		return "", err
	}

	// credentials need to be converted to json
	kcDat := map[string]any{}
	err = yaml.Unmarshal([]byte(kubeconfig), &kcDat)
	if err != nil {
		return "", fmt.Errorf("failed to parse yaml kubeconfig, %s", err)
	}
	kcJSON, err := json.Marshal(kcDat)
	if err != nil {
		return "", fmt.Errorf("failed to marshal kubeconfig data to JSON, %s", err)
	}

	bootstrap := true // bootstrap prepares the cluster to use FluxCD
	body := RegisterClusterInfo{}
	body.Name = &clusterName
	body.Credentials = kcJSON
	body.VimAccount = &vim
	body.Description = &clusterName
	body.Bootstrap = &bootstrap

	bodyData, err := json.Marshal(&body)
	if err != nil {
		return "", fmt.Errorf("failed to marshal register cluster body, %s", err)
	}
	rdr := bytes.NewReader(bodyData)

	resp, err := client.Registerk8sClusterWithBodyWithResponse(ctx, "application/json", rdr)
	if err != nil {
		return "", fmt.Errorf("failed to register cluster %s, %s", clusterName, err)
	}
	if resp.StatusCode() == http.StatusConflict {
		// assume already registered
		log.SpanLog(ctx, log.DebugLevelInfra, "cluster already registered", "clusterName", clusterName, "resp", string(resp.Body))
		id, err := s.GetClusterID(ctx, clusterName, nil)
		if err != nil {
			return "", err
		}
		err = s.waitForClusterDone(ctx, clusterName, id, cloudcommon.Create, ClusterActionTimeout, WaitForClusterDoneInterval)
		return "", err
	}
	if resp.StatusCode() != http.StatusCreated {
		return "", fmt.Errorf("failed to register cluster %s (%d), %s", clusterName, resp.StatusCode(), string(resp.Body))
	}
	id := ""
	if resp.JSON201 != nil && resp.JSON201.Id != nil {
		id = resp.JSON201.Id.String()
	} else {
		log.SpanLog(ctx, log.DebugLevelInfra, "missing expected cluster ID", "resp", string(resp.Body))
		idresp := createClusterResp{}
		err := json.Unmarshal(resp.Body, &idresp)
		if err == nil && idresp.ID != "" {
			id = idresp.ID
		}
	}
	if id == "" {
		return "", fmt.Errorf("register cluster %s failed to determine registered cluster id", clusterName)
	}
	// wait for cluster to be ready
	err = s.waitForClusterDone(ctx, clusterName, id, cloudcommon.Create, ClusterActionTimeout, WaitForClusterDoneInterval)
	if err != nil {
		return "", err
	}
	log.SpanLog(ctx, log.DebugLevelInfra, "registered cluster", "clusterName", clusterName, "id", id)
	return id, nil
}

func (s *OSMClient) GetClusterInfo(ctx context.Context, clusterID string) (*GetClusterInfo, int, error) {
	client, err := s.GetClient(ctx)
	if err != nil {
		return nil, 0, err
	}
	// TODO: OpenAPI spec is wrong, it doesn't define any response data,
	// so we need to define and parse the response ourselves.
	resp, err := client.Readk8sCluster(ctx, clusterID)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to get cluster status, %s", err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to get cluster status, read body failed, %s", err)
	}
	if resp.StatusCode == http.StatusNotFound {
		// this is ok for delete case
		return nil, http.StatusNotFound, nil
	}
	if resp.StatusCode != http.StatusOK {
		return nil, resp.StatusCode, fmt.Errorf("failed to get cluster %s status (%d), %s", clusterID, resp.StatusCode, string(body))
	}
	info := GetClusterInfo{}
	if err := json.Unmarshal(body, &info); err != nil {
		return nil, resp.StatusCode, fmt.Errorf("failed to unmarshal get cluster response, %s, %s", err, string(body))
	}
	return &info, resp.StatusCode, nil
}

func (s *OSMClient) FindClusterInfo(ctx context.Context, clusterName string) (*GetClusterInfo, error) {
	clusters, err := s.ListClusters(ctx)
	if err != nil {
		return nil, err
	}
	for _, cluster := range clusters {
		if cluster.Name == clusterName {
			return cluster, nil
		}
	}
	return nil, nil
}

func (s *OSMClient) waitForClusterDone(ctx context.Context, clusterName, clusterID string, action cloudcommon.Action, timeout time.Duration, retry time.Duration) error {
	endTime := time.Now().Add(timeout)
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
		info, status, err := s.GetClusterInfo(ctx, clusterID)
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
		if curState == "ERROR" {
			return fmt.Errorf("cluster in error state")
		}
		time.Sleep(retry)
	}
}

func (s *OSMClient) GetCredentials(ctx context.Context, clusterName string, clusterInst *edgeproto.ClusterInst) ([]byte, error) {
	id, err := s.GetClusterID(ctx, clusterName, clusterInst)
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

func (s *OSMClient) getCredentialsRaw(ctx context.Context, clusterName, clusterID string) ([]byte, error) {
	client, err := s.GetClient(ctx)
	if err != nil {
		return nil, err
	}
	// the REST API for /k8scluster/v1/clusters/<id>/get_creds
	// doesn't actually get the credentials, it just returns a
	// single op_id. The osm cli in fact just gets the cluster info,
	// which includes the credentials.
	// We have been told this is the correct behavior, and that
	// the get_creds API is required to ensure the credentials
	// are up to date. So this must be run first, before calling
	// the cluster  list API which will then have the creds.

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
	// creds should now be ready in cluster info
	info, status, err := s.GetClusterInfo(ctx, clusterID)
	if err != nil {
		return nil, err
	}
	if status == http.StatusNotFound {
		return nil, fmt.Errorf("cluster %s(%s) not found", clusterName, clusterID)
	}
	return info.Credentials, nil
}

func (s *OSMClient) GetClusterID(ctx context.Context, clusterName string, clusterInst *edgeproto.ClusterInst) (string, error) {
	var id string
	if clusterInst != nil {
		id = clusterInst.InfraAnnotations[ClusterIDAnnotation]
	}
	if id == "" {
		// try to look it up by name
		info, err := s.FindClusterInfo(ctx, clusterName)
		if err != nil {
			return "", err
		}
		if info == nil {
			return "", fmt.Errorf("cluster %s not found", clusterName)
		}
		if info.ID == "" {
			return "", fmt.Errorf("found cluster %s but ID is blank", clusterName)
		}
		id = info.ID
	}
	log.SpanLog(ctx, log.DebugLevelInfra, "got cluster id", "clusterName", clusterName, "id", id)
	return id, nil
}

func (s *OSMClient) ListClusters(ctx context.Context) ([]*GetClusterInfo, error) {
	client, err := s.GetClient(ctx)
	if err != nil {
		return nil, err
	}
	// TODO: once OpenAPI spec is fixed, we can use the "WithReseponse"
	// version of the API.
	// listClusters openapi spec doesn't specify StatusOK data, so trying
	// to use the "WithResponse" version of the auto-generated API will
	// generate JSON parse errors.
	resp, err := client.Listk8sCluster(ctx)
	clusters := []*GetClusterInfo{}
	err = mustResp("list clusters", resp, err, http.StatusOK, &clusters)
	if err != nil {
		return nil, err
	}
	return clusters, nil
}
