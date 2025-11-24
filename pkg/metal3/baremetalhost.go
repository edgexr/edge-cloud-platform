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

package metal3

import (
	"cmp"
	"context"
	"encoding/json"
	"fmt"
	"slices"
	"strings"

	"github.com/edgexr/edge-cloud-platform/api/edgeproto"
	"github.com/edgexr/edge-cloud-platform/pkg/k8smgmt"
	"github.com/edgexr/edge-cloud-platform/pkg/log"
	ssh "github.com/edgexr/golang-ssh"
	"github.com/metal3-io/baremetal-operator/apis/metal3.io/v1alpha1"
)

const FlavorLabel = "app.edgexr.org/flavor"

func GetBareMetalHosts(ctx context.Context, client ssh.Client, names *k8smgmt.KconfNames, namespace, label string) ([]v1alpha1.BareMetalHost, error) {
	if label != "" {
		label = "-l " + label
	}
	cmd := fmt.Sprintf("kubectl %s get baremetalhosts -n %s -o json %s", names.KconfArg, namespace, label)
	// no logging as this is polled by clusterapi
	out, err := client.Output(cmd)
	if err != nil {
		return nil, fmt.Errorf("get baremetalhosts failed, %s, %v", out, err)
	}
	blist := v1alpha1.BareMetalHostList{}
	err = json.Unmarshal([]byte(out), &blist)
	if err != nil {
		return nil, fmt.Errorf("unmarshal baremetalhosts failed, %s, %v", out, err)
	}
	return blist.Items, nil
}

type FlavorsData struct {
	Flavors []*edgeproto.FlavorInfo
	Counts  map[string]int
	Vcpus   edgeproto.Udec64
	Ram     edgeproto.Udec64
	Disk    edgeproto.Udec64
}

func UpdateBareMetalHostFlavors(ctx context.Context, client ssh.Client, names *k8smgmt.KconfNames, namespace string) (*FlavorsData, error) {
	log.SpanLog(ctx, log.DebugLevelInfra, "update baremetalhost flavor labels", "namespace", namespace)
	hosts, err := GetBareMetalHosts(ctx, client, names, namespace, "")
	if err != nil {
		return nil, err
	}
	data := FlavorsData{}
	data.Counts = map[string]int{}
	flavors := map[string]*edgeproto.FlavorInfo{}
	for _, host := range hosts {
		if host.Status.HardwareDetails == nil {
			log.SpanLog(ctx, log.DebugLevelInfra, "baremetalhost has no hardware details", "name", host.Name, "namespace", host.Namespace)
			continue
		}
		hw := host.Status.HardwareDetails
		data.Vcpus.AddUint64(uint64(hw.CPU.Count))
		data.Ram.AddUint64(uint64(hw.RAMMebibytes))
		diskTotalGb := uint64(0)
		for _, st := range hw.Storage {
			diskTotalGb += uint64(st.SizeBytes / 1024 / 1024 / 1024)
		}
		data.Disk.AddUint64(diskTotalGb)
		// We require that the operator adds GPU labels to the
		// BareMetalHosts when they are creating them. These labels
		// should follow the standard labels that an Nvidia/AMD GPU
		// operator would apply to kubernetes nodes. This will be
		// used for resource tracking and allocation.
		gpus, _, err := k8smgmt.GetNodeGPUInfo(host.Labels)
		if err != nil {
			log.SpanLog(ctx, log.DebugLevelInfra, "failed to get GPU info from labels on bare metal host", "name", host.Name, "namespace", host.Namespace, "labels", host.Labels, "err", err)
			return nil, fmt.Errorf("failed to get GPU info from labels on bare metal host %s.%s, %v", host.Namespace, host.Name, err)
		}
		// generate ff for the node
		ff := &edgeproto.FlavorInfo{
			Vcpus: uint64(hw.CPU.Count),
			Ram:   uint64(hw.RAMMebibytes),
			Disk:  diskTotalGb,
			Gpus:  gpus,
		}
		ff.Name = ff.ResBasedName()
		if _, found := flavors[ff.Name]; !found {
			flavors[ff.Name] = ff
		}
		data.Counts[ff.Name]++
		if val, ok := host.GetLabels()[FlavorLabel]; !ok || val != ff.Name {
			// update flavor label
			cmd := fmt.Sprintf("kubectl %s label -n %s baremetalhost %s %s=%s --overwrite", names.KconfArg, namespace, host.Name, FlavorLabel, ff.Name)
			out, err := client.Output(cmd)
			log.SpanLog(ctx, log.DebugLevelInfra, "update flavor label", "cmd", cmd, "out", out, "err", err)
			if err != nil {
				return nil, fmt.Errorf("update flavor label failed, %s, %v", out, err)
			}
		}
	}
	for _, flavor := range flavors {
		data.Flavors = append(data.Flavors, flavor)
	}
	slices.SortFunc(data.Flavors, func(i, j *edgeproto.FlavorInfo) int {
		if i.Vcpus != j.Vcpus {
			return cmp.Compare(i.Vcpus, j.Vcpus)
		}
		if i.Ram != j.Ram {
			return cmp.Compare(i.Ram, j.Ram)
		}
		return strings.Compare(i.Name, j.Name)
	})
	return &data, nil
}
