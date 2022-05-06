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

package vsphere

import (
	"context"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"sync"

	"github.com/edgexr/edge-cloud-infra/vmlayer"
	"github.com/edgexr/edge-cloud/log"
)

const TagFieldGroup = "group"
const TagFieldDomain = "domain"
const TagFieldIp = "ip"
const TagFieldSubnetName = "subnetname"
const TagFieldCidr = "cidr"
const TagFieldVlan = "vlan"
const TagFieldVmName = "vmname"
const TagFieldRole = "role"
const TagFieldFlavor = "flavor"
const TagFieldNetName = "netname"

const TagNotFound = "tag not found"
const TagAlreadyExists = "ALREADY_EXISTS"

type VMDomainTagContents struct {
	Vmname string
	Domain string
	Role   string
	Flavor string
}

type VMIpTagContents struct {
	Vmname  string
	Network string
	Ipaddr  string
	Domain  string
}

type SubnetTagContents struct {
	SubnetName string
	Cidr       string
	Vlan       uint32
	Domain     string
}

// vCenter has a bug in which if the tag query API is run while a tag delete is in progress, the query
// will return and error, even if the tag being deleted is just one of many.  To avoid this, lock around
// all tag operations.  These are fairly fast and so will not slow things down much to lock around.
var tagMux sync.Mutex

func (v *VSpherePlatform) GetTagFieldMap(tag string) (map[string]string, error) {
	fieldMap := make(map[string]string)
	ts := strings.Split(tag, ",")
	for _, field := range ts {
		fs := strings.Split(field, "=")
		if len(fs) != 2 {
			return nil, fmt.Errorf("incorrectly formatted tag: %s", tag)
		}
		fieldMap[fs[0]] = fs[1]
	}
	return fieldMap, nil
}

func (v *VSpherePlatform) GetValueForTagField(tag string, fieldName string) (string, error) {
	fm, err := v.GetTagFieldMap(tag)
	if err != nil {
		return "", err
	}
	value, ok := fm[fieldName]
	if !ok {
		return "", fmt.Errorf(TagNotFound)
	}
	return value, nil

}

func (v *VSpherePlatform) GetVMDomainTagCategory(ctx context.Context) string {
	return v.GetDatacenterName(ctx) + "-vmdomain"
}

func (v *VSpherePlatform) GetSubnetTagCategory(ctx context.Context) string {
	return v.GetDatacenterName(ctx) + "-subnet"
}

func (v *VSpherePlatform) GetVmIpTagCategory(ctx context.Context) string {
	return v.GetDatacenterName(ctx) + "-vmip"
}

// GetDomainFromTag get the domain from the tag which is always the last field
func (v *VSpherePlatform) GetDomainFromTag(ctx context.Context, tag string) (string, error) {
	return v.GetValueForTagField(tag, TagFieldDomain)
}

func (v *VSpherePlatform) GetVmIpTag(ctx context.Context, group, vmName, network, ipaddr string) string {
	return TagFieldGroup + "=" + group + "," + TagFieldVmName + "=" + vmName + "," + TagFieldNetName + "=" + network + "," + TagFieldIp + "=" + ipaddr + "," + TagFieldDomain + "=" + string(v.vmProperties.Domain)
}

// ParseVMIpTag returns vmname, network, ipaddr, domain
func (v *VSpherePlatform) ParseVMIpTag(ctx context.Context, tag string) (*VMIpTagContents, error) {
	var contents VMIpTagContents
	fm, err := v.GetTagFieldMap(tag)
	if err != nil {
		return nil, err
	}
	vmname, ok := fm[TagFieldVmName]
	if !ok {
		return nil, fmt.Errorf("No vmname in vmip tag")
	}
	contents.Vmname = vmname
	network, ok := fm[TagFieldNetName]
	if !ok {
		return nil, fmt.Errorf("No netname in vmip tag")
	}
	contents.Network = network
	ip, ok := fm[TagFieldIp]
	if !ok {
		return nil, fmt.Errorf("No ip in vmip tag")
	}
	contents.Ipaddr = ip
	domain, ok := fm[TagFieldDomain]
	if !ok {
		return nil, fmt.Errorf("No domain in vmip tag")
	}
	contents.Domain = domain
	return &contents, nil
}

func (v *VSpherePlatform) GetSubnetTag(ctx context.Context, group, subnetName, cidr string, vlan uint32) string {
	return TagFieldGroup + "=" + group + "," + TagFieldSubnetName + "=" + subnetName + "," + TagFieldCidr + "=" + cidr + "," + TagFieldVlan + "=" + fmt.Sprintf("%d", vlan) + "," + TagFieldDomain + "=" + string(v.vmProperties.Domain)
}

// ParseSubnetTag returns subnetName, cidr, vlan, domain
func (v *VSpherePlatform) ParseSubnetTag(ctx context.Context, tag string) (*SubnetTagContents, error) {
	var contents SubnetTagContents
	fm, err := v.GetTagFieldMap(tag)
	if err != nil {
		return nil, err
	}
	subnetName, ok := fm[TagFieldSubnetName]
	if !ok {
		return nil, fmt.Errorf("No subnetname in subnet tag")
	}
	contents.SubnetName = subnetName
	cidr, ok := fm[TagFieldCidr]
	if !ok {
		return nil, fmt.Errorf("No cidr in subnet tag")
	}
	contents.Cidr = cidr
	domain, ok := fm[TagFieldDomain]
	if !ok {
		return nil, fmt.Errorf("No domain in subnet tag")
	}
	contents.Domain = domain
	vlanstr, ok := fm[TagFieldVlan]
	if !ok {
		return nil, fmt.Errorf("No vlan in subnet tag")
	}
	vlan, err := strconv.ParseUint(vlanstr, 10, 32)
	if err != nil {
		return nil, fmt.Errorf("Fail to parse VLAN in subnet tag: %v", err)
	}
	contents.Vlan = uint32(vlan)
	return &contents, nil
}

func (v *VSpherePlatform) GetVmDomainTag(ctx context.Context, group, vmName, role, flavor string) string {
	return TagFieldGroup + "=" + group + "," +
		TagFieldVmName + "=" + vmName + "," +
		TagFieldRole + "=" + role + "," +
		TagFieldFlavor + "=" + flavor + "," +
		TagFieldDomain + "=" + string(v.vmProperties.Domain)
}

// ParseVMDomainTag returns vmname, domain, role, flavor
func (v *VSpherePlatform) ParseVMDomainTag(ctx context.Context, tag string) (*VMDomainTagContents, error) {
	var contents VMDomainTagContents
	fm, err := v.GetTagFieldMap(tag)
	if err != nil {
		return nil, err
	}
	vmName, ok := fm[TagFieldVmName]
	if !ok {
		return nil, fmt.Errorf("No vmname in vmdomain tag")
	}
	contents.Vmname = vmName
	domain, ok := fm[TagFieldDomain]
	if !ok {
		return nil, fmt.Errorf("No domain in vmdomain tag")
	}
	contents.Domain = domain
	role, ok := fm[TagFieldRole]
	if !ok {
		// optional
		log.SpanLog(ctx, log.DebugLevelInfra, "No role in vmdomain tag", "tag", tag)
	} else {
		contents.Role = role
	}
	flavor, ok := fm[TagFieldFlavor]
	if !ok {
		// optional
		log.SpanLog(ctx, log.DebugLevelInfra, "No flavor in vmdomain tag", "tag", tag)
	} else {
		contents.Flavor = flavor
	}
	return &contents, nil
}

// GetAllVmIpsFromTags returns a map of vmname to ip list
func (v *VSpherePlatform) GetAllVmIpsFromTags(ctx context.Context) (map[string][]string, error) {
	results := make(map[string][]string)
	tags, err := v.GetTagsForCategory(ctx, v.GetVmIpTagCategory(ctx), vmlayer.VMDomainAny)
	if err != nil {
		return nil, err
	}
	for _, tag := range tags {
		vmipTagContents, err := v.ParseVMIpTag(ctx, tag.Name)
		if err != nil {
			return nil, err
		}
		results[vmipTagContents.Vmname] = append(results[vmipTagContents.Vmname], vmipTagContents.Ipaddr)
	}
	return results, nil
}

func (v *VSpherePlatform) GetIpsFromTagsForVM(ctx context.Context, vmName string, sd *vmlayer.ServerDetail) error {
	log.SpanLog(ctx, log.DebugLevelInfra, "GetIpsFromTagsForVM", "vmName", vmName)
	tags, err := v.GetTagsForCategory(ctx, v.GetVmIpTagCategory(ctx), vmlayer.VMDomainAny)
	if err != nil {
		return err
	}
	for _, t := range tags {
		vmipTagContents, err := v.ParseVMIpTag(ctx, t.Name)
		if err != nil {
			return err
		}
		if vmipTagContents.Vmname != vmName {
			continue
		}

		// see if there is an existing port in the server details and update it
		found := false
		for i, s := range sd.Addresses {
			if s.Network == vmipTagContents.Network {
				log.SpanLog(ctx, log.DebugLevelInfra, "Updated address via tag", "contents", vmipTagContents)
				sd.Addresses[i].ExternalAddr = vmipTagContents.Ipaddr
				sd.Addresses[i].InternalAddr = vmipTagContents.Ipaddr
				found = true
			}
		}
		if !found {
			portName := vmlayer.GetPortName(vmName, vmipTagContents.Network)
			sip := vmlayer.ServerIP{
				InternalAddr: vmipTagContents.Ipaddr,
				ExternalAddr: vmipTagContents.Ipaddr,
				Network:      vmipTagContents.Network,
				PortName:     portName,
			}
			sd.Addresses = append(sd.Addresses, sip)
			log.SpanLog(ctx, log.DebugLevelInfra, "Added address via tag", "contents", vmipTagContents)
		}
	}
	return nil
}

func (v *VSpherePlatform) CreateTag(ctx context.Context, tag *vmlayer.TagOrchestrationParams) error {
	log.SpanLog(ctx, log.DebugLevelInfra, "CreateTag", "tag", tag)

	tagMux.Lock()
	defer tagMux.Unlock()

	out, err := v.TimedGovcCommand(ctx, "govc", "tags.create", "-c", tag.Category, tag.Name)
	if err != nil {
		if strings.Contains(string(out), TagAlreadyExists) {
			log.SpanLog(ctx, log.DebugLevelInfra, "Tag already exists", "tag", tag)
			return nil
		}
		return fmt.Errorf("Error in creating tag: %s - %v", tag.Name, err)
	}
	return nil
}

func (v *VSpherePlatform) DeleteTag(ctx context.Context, tagname string) error {
	log.SpanLog(ctx, log.DebugLevelInfra, "DeleteTag", "tagname", tagname)

	tagMux.Lock()
	defer tagMux.Unlock()

	out, err := v.TimedGovcCommand(ctx, "govc", "tags.rm", tagname)
	if err != nil {
		log.SpanLog(ctx, log.DebugLevelInfra, "Tag delete fail", "out", out, "err", err)
		return fmt.Errorf("Error in deleting tag: %s - %v", tagname, err)
	}
	return nil
}

func (v *VSpherePlatform) GetTagMatchingField(ctx context.Context, category, fieldName, fieldVal string) (*GovcTag, error) {
	log.SpanLog(ctx, log.DebugLevelInfra, "GetTagMatchingField", "category", category, "fieldName", fieldName, "fieldVal", fieldVal)
	tags, err := v.GetTagsForCategory(ctx, category, vmlayer.VMDomainAny)
	if err != nil {
		return nil, err
	}

	for _, t := range tags {
		val, err := v.GetValueForTagField(t.Name, fieldName)
		if err != nil {
			return nil, err
		}
		if val == fieldVal {
			return &t, nil
		}
	}
	return nil, fmt.Errorf(TagNotFound)
}

func (v *VSpherePlatform) GetTagsForCategory(ctx context.Context, category string, domainMatch vmlayer.VMDomain) ([]GovcTag, error) {
	log.SpanLog(ctx, log.DebugLevelInfra, "GetTagsForCategory", "category", category, "domainMatch", domainMatch)

	tagMux.Lock()
	defer tagMux.Unlock()

	out, err := v.TimedGovcCommand(ctx, "govc", "tags.ls", "-c", category, "-json")
	if err != nil {
		return nil, err
	}

	var tags []GovcTag
	var matchedTags []GovcTag
	err = json.Unmarshal(out, &tags)
	if err != nil {
		log.SpanLog(ctx, log.DebugLevelInfra, "GetTagsForCategory unmarshal fail", "out", string(out), "err", err)
		err = fmt.Errorf("cannot unmarshal govc subnet tags, %v", err)
		return nil, err
	}
	// due to an intermittent govc bug (or maybe a vsphere bug), sometimes the category id in the tag is a UUID instead
	// of a name so we will update it here before returning to get consistent results
	for _, t := range tags {
		domain, err := v.GetDomainFromTag(ctx, t.Name)
		if err != nil {
			return nil, err
		}
		if domainMatch == vmlayer.VMDomainAny || domain == string(domainMatch) {
			if t.Category != category {
				log.SpanLog(ctx, log.DebugLevelInfra, "Updating category for tag", "orig category", t.Category, "category", category)
				t.Category = category
			}
			matchedTags = append(matchedTags, t)
		}
	}
	return matchedTags, nil
}

func (v *VSpherePlatform) GetTagsMatchingField(ctx context.Context, fieldName string, fieldValue string, category string) ([]GovcTag, error) {
	var matchTags []GovcTag
	catTags, err := v.GetTagsForCategory(ctx, category, vmlayer.VMDomainAny)
	if err != nil {
		return nil, err
	}
	for _, t := range catTags {
		tagval, err := v.GetValueForTagField(t.Name, fieldName)
		if err == nil && tagval == fieldValue {
			matchTags = append(matchTags, t)
		}
	}
	return matchTags, nil
}

func (v *VSpherePlatform) GetTagCategories(ctx context.Context) ([]GovcTagCategory, error) {
	dcName := v.GetDatacenterName(ctx)

	out, err := v.TimedGovcCommand(ctx, "govc", "tags.category.ls", "-json")
	if err != nil {
		return nil, err
	}

	var foundcats []GovcTagCategory
	var returnedcats []GovcTagCategory
	err = json.Unmarshal(out, &foundcats)
	if err != nil {
		return nil, err

	}
	// exclude the ones not in our datacenter
	for _, c := range foundcats {
		if strings.HasPrefix(c.Name, dcName) {
			returnedcats = append(returnedcats, c)
		}
	}
	return returnedcats, err
}

func (v *VSpherePlatform) CreateTagCategory(ctx context.Context, category string) error {
	log.SpanLog(ctx, log.DebugLevelInfra, "CreateTagCategory", "category", category)
	out, err := v.TimedGovcCommand(ctx, "govc", "tags.category.create", category)
	if err != nil {
		if strings.Contains(string(out), TagAlreadyExists) {
			log.SpanLog(ctx, log.DebugLevelInfra, "Tag category already exists", "category", category)
			return nil
		}
		return fmt.Errorf("failed to create tag category: %s", category)
	}
	return nil
}

func (v *VSpherePlatform) CreateTagCategories(ctx context.Context) error {
	log.SpanLog(ctx, log.DebugLevelInfra, "CreateTagCategories")

	err := v.CreateTagCategory(ctx, v.GetVMDomainTagCategory(ctx))
	if err != nil {
		return err
	}
	err = v.CreateTagCategory(ctx, v.GetSubnetTagCategory(ctx))
	if err != nil {
		return err
	}
	err = v.CreateTagCategory(ctx, v.GetVmIpTagCategory(ctx))
	if err != nil {
		return err
	}
	return nil
}

func (v *VSpherePlatform) GetVmNamesFromTags(ctx context.Context, tags []GovcTag) (map[string]string, error) {
	names := make(map[string]string)
	for _, tag := range tags {
		vmDomainTagContents, err := v.ParseVMDomainTag(ctx, tag.Name)
		if err != nil {
			return nil, err
		}
		names[vmDomainTagContents.Vmname] = vmDomainTagContents.Vmname
	}
	return names, nil
}
