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

package resspec

import (
	"fmt"
	"slices"
	"strings"

	"github.com/edgexr/edge-cloud-platform/api/edgeproto"
	"github.com/edgexr/edge-cloud-platform/pkg/cloudcommon"
)

// ResVal provides a generic resource used for doing math
// on and comparing resource values. Values are internally
// stored as edgeproto.Udec64.
type ResVal struct {
	Name          string // unique name
	Units         string
	Value         edgeproto.Udec64
	OptResMapKey  string // for opt res, original optresmap key
	OptResMapSpec string // for opt res, original optresmap val without count
}

func NewDecimalResVal(name, units string, value edgeproto.Udec64) *ResVal {
	return &ResVal{
		Name:  name,
		Units: units,
		Value: value,
	}
}

func NewWholeResVal(name, units string, value uint64) *ResVal {
	return &ResVal{
		Name:  name,
		Units: units,
		Value: edgeproto.Udec64{
			Whole: value,
		},
	}
}

type ResValMap map[string]*ResVal

func (s ResValMap) AddRes(name, units string, whole uint64, nanos uint32) {
	s.Add(NewDecimalResVal(name, units, *edgeproto.NewUdec64(whole, nanos)))
}

func (s ResValMap) Add(nres *ResVal) {
	s.AddMult(nres, 1)
}

func (s ResValMap) AddMult(nres *ResVal, factor uint32) {
	cp := *nres
	cp.Value.Mult(factor)
	existing, ok := s[nres.Name]
	if ok {
		existing.Value.Add(&cp.Value)
	} else {
		s[nres.Name] = &cp
	}
}

// AddVcpus is a convenience function for adding vcpus.
func (s ResValMap) AddVcpus(whole uint64, nanos uint32) {
	s.AddRes(cloudcommon.ResourceVcpus, "", whole, nanos)
}

// AddRam is a convenience function for adding ram in megabytes.
func (s ResValMap) AddRam(val uint64) {
	s.AddRes(cloudcommon.ResourceRamMb, cloudcommon.ResourceRamUnits, val, 0)
}

// AddDisk is a convenience function for adding disk in gigabytes.
func (s ResValMap) AddDisk(val uint64) {
	s.AddRes(cloudcommon.ResourceDiskGb, cloudcommon.ResourceDiskUnits, val, 0)
}

// AddOptResMap adds optional resource values.
func (s ResValMap) AddOptResMap(optResMap map[string]string, count uint32) error {
	for resName, val := range optResMap {
		if err := s.AddOptRes(resName, val, count); err != nil {
			return err
		}
	}
	return nil
}

// AddOptRes adds an optional resource value.
func (s ResValMap) AddOptRes(resName, val string, mult uint32) error {
	typ, alias, count, err := cloudcommon.ParseOptResVal(val)
	if err != nil {
		return err
	}
	// Note that the opt res key is too generic, i.e. "gpu".
	// A cluster may have different types of gpus,
	// especially if one large gpu is broken into smaller
	// configurations. So we need to create a key based on the
	// more specific details of the resource.
	parts := []string{resName}
	if typ != "" {
		parts = append(parts, typ)
	}
	if alias != "" {
		parts = append(parts, alias)
	}
	name := strings.Join(parts, ":")
	nres := NewWholeResVal(name, "", uint64(count)*uint64(mult))
	nres.OptResMapKey = resName
	// trim value from optresval and record it as spec
	lastColon := strings.LastIndex(val, ":")
	nres.OptResMapSpec = val[:lastColon]
	s.Add(nres)
	return nil
}

func (s ResValMap) AddAllMult(other ResValMap, factor uint32) {
	for _, oval := range other {
		s.AddMult(oval, factor)
	}
}

// Subtract the other resource from this resource.
// The value floors at zero rather than going negative.
// If the other value is not in this, it is ignored.
func (s ResValMap) SubFloor(nres *ResVal, underflow *bool) {
	existing, ok := s[nres.Name]
	if ok {
		existing.Value.SubFloor(&nres.Value, underflow)
	}
}

// Subtract the other resources from these resources.
// Values floor at zero rather than go negative.
// Values in other that are not in this are ignored.
func (s ResValMap) SubFloorAll(other ResValMap, underflow *bool) {
	for _, oval := range other {
		s.SubFloor(oval, underflow)
	}
}

func (s ResValMap) GetInt(resName string) uint64 {
	v, ok := s[resName]
	if !ok {
		return 0
	}
	return v.Value.Whole
}

func (s ResValMap) Clone() ResValMap {
	clone := ResValMap{}
	for _, v := range s {
		clone.Add(v)
	}
	return clone
}

// SortedKeys returns keys sorted ascending. This is helpful for
// ensuring deterministic error/info messages.
func (s ResValMap) SortedKeys() []string {
	keys := []string{}
	for k := range s {
		keys = append(keys, k)
	}
	slices.Sort(keys)
	return keys
}

func (s ResValMap) String() string {
	strs := []string{}
	for _, resName := range s.SortedKeys() {
		res := s[resName]
		strs = append(strs, fmt.Sprintf("%s %s%s", resName, res.Value.DecString(), res.Units))
	}
	return strings.Join(strs, ", ")
}

func (s ResValMap) AddNodeResources(nr *edgeproto.NodeResources, count uint32) error {
	if nr == nil {
		return nil
	}
	s.AddVcpus(nr.Vcpus*uint64(count), 0)
	s.AddRam(nr.Ram * uint64(count))
	s.AddDisk(nr.Disk * uint64(count))
	// optional resources
	return s.AddOptResMap(nr.OptResMap, count)
}

func (s ResValMap) AddNodePoolResources(npr *edgeproto.NodePoolResources) error {
	if npr == nil {
		return nil
	}
	s.AddVcpus(npr.TotalVcpus.Whole, npr.TotalVcpus.Nanos)
	s.AddRam(npr.TotalMemory)
	s.AddDisk(npr.TotalDisk)
	// optional resources
	return s.AddOptResMap(npr.TotalOptRes, 1)
}
