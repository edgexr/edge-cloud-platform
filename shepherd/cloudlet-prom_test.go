package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
	"sync"
	"testing"

	"github.com/mobiledgex/edge-cloud/edgeproto"
	"github.com/mobiledgex/edge-cloud/log"
	"github.com/stretchr/testify/assert"
)

const testInstCount = 50

var testWaitGroup sync.WaitGroup

type TestJsonTargets []struct {
	Targets []string `json:"targets"`
	Labels  struct {
		MetricsPath string `json:"__metrics_path__"`
		App         string `json:"app"`
		Apporg      string `json:"apporg"`
		Appver      string `json:"appver"`
		Cloudlet    string `json:"cloudlet"`
		Cloudletorg string `json:"cloudletorg"`
		Cluster     string `json:"cluster"`
		Clusterorg  string `json:"clusterorg"`
	} `json:"labels"`
}

func testUpdateAndWrite(ctx context.Context, inst *edgeproto.AppInst, t *testing.T) {
	AppInstCache.Update(ctx, inst, 0)
	writePrometheusTargetsFile()
	testWaitGroup.Done()
}
func TestCloudletPrometheusFuncs(t *testing.T) {
	ctx := setupLog()
	defer log.FinishTracer()
	// test targets file
	*promTargetsFile = "/tmp/testTargets.json"
	edgeproto.InitAppInstCache(&AppInstCache)
	testTargetAppInstances, targetKeys := genAppInstances(testInstCount)
	testWaitGroup.Add(testInstCount)
	for ii := range testTargetAppInstances {
		go testUpdateAndWrite(ctx, &testTargetAppInstances[ii], t)
	}
	// Wait for all to complete
	testWaitGroup.Wait()
	// verify they all are here
	content, err := ioutil.ReadFile(*promTargetsFile)
	assert.Nil(t, err)
	targets := TestJsonTargets{}
	err = json.Unmarshal(content, &targets)
	assert.Nil(t, err)
	assert.Len(t, targets, testInstCount)
	for _, target := range targets {
		key := target.Labels.App
		if _, found := targetKeys[key]; !found {
			assert.Fail(t, "Unable to find target", target)
		} else {
			// Delete to verify we don't have multiples
			delete(targetKeys, key)
		}
	}
	// we should have found all the keys
	assert.Len(t, targetKeys, 0)
	// clean up file
	err = os.Remove(*promTargetsFile)
	assert.Nil(t, err)
}

// generate appInstances and keys for later verification
func genAppInstances(cnt int) ([]edgeproto.AppInst, map[string]struct{}) {
	list := []edgeproto.AppInst{}
	keys := map[string]struct{}{}
	for ii := 0; ii < cnt; ii++ {
		inst := edgeproto.AppInst{
			Key: edgeproto.AppInstKey{
				AppKey: edgeproto.AppKey{
					Name:         fmt.Sprintf("App-%d", ii),
					Organization: fmt.Sprintf("AppOrg-%d", ii),
				},
				ClusterInstKey: edgeproto.ClusterInstKey{
					ClusterKey: edgeproto.ClusterKey{
						Name: fmt.Sprintf("Cluster-%d", ii),
					},
					CloudletKey: edgeproto.CloudletKey{
						Organization: fmt.Sprintf("Cloudletorg-%d", ii),
						Name:         fmt.Sprintf("Cloudlet-%d", ii),
					},
					Organization: fmt.Sprintf("Clusterorg-%d", ii),
				},
			},
		}
		list = append(list, inst)
		keys[inst.Key.AppKey.Name] = struct{}{}
	}
	return list, keys
}
