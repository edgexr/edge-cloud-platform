// Code generated by protoc-gen-gogo. DO NOT EDIT.
// source: alldata.proto

package edgeproto

import proto "github.com/gogo/protobuf/proto"
import fmt "fmt"
import math "math"
import _ "github.com/mobiledgex/edge-cloud/protogen"
import _ "github.com/gogo/protobuf/gogoproto"

import strings "strings"
import "github.com/google/go-cmp/cmp"
import "github.com/google/go-cmp/cmp/cmpopts"

import io "io"

// Reference imports to suppress errors if they are not otherwise used.
var _ = proto.Marshal
var _ = fmt.Errorf
var _ = math.Inf

// AllData contains all data that may be used for declarative
// create/delete, or as input for e2e tests.
// The order of fields here is important, as objects will be
// created in the order they are specified here, and deleted
// in the opposite order. The field ID (number) doesn't matter.
type AllData struct {
	Flavors                 []Flavor                 `protobuf:"bytes,2,rep,name=flavors" json:"flavors"`
	Settings                *Settings                `protobuf:"bytes,1,opt,name=settings" json:"settings,omitempty"`
	OperatorCodes           []OperatorCode           `protobuf:"bytes,4,rep,name=operator_codes,json=operatorCodes" json:"operator_codes"`
	ResTagTables            []ResTagTable            `protobuf:"bytes,6,rep,name=res_tag_tables,json=resTagTables" json:"res_tag_tables"`
	Cloudlets               []Cloudlet               `protobuf:"bytes,7,rep,name=cloudlets" json:"cloudlets"`
	CloudletInfos           []CloudletInfo           `protobuf:"bytes,8,rep,name=cloudlet_infos,json=cloudletInfos" json:"cloudlet_infos"`
	CloudletPools           []CloudletPool           `protobuf:"bytes,9,rep,name=cloudlet_pools,json=cloudletPools" json:"cloudlet_pools"`
	CloudletPoolMembers     []CloudletPoolMember     `protobuf:"bytes,10,rep,name=cloudlet_pool_members,json=cloudletPoolMembers" json:"cloudlet_pool_members"`
	AutoProvPolicies        []AutoProvPolicy         `protobuf:"bytes,11,rep,name=auto_prov_policies,json=autoProvPolicies" json:"auto_prov_policies"`
	AutoProvPolicyCloudlets []AutoProvPolicyCloudlet `protobuf:"bytes,12,rep,name=auto_prov_policy_cloudlets,json=autoProvPolicyCloudlets" json:"auto_prov_policy_cloudlets"`
	AutoScalePolicies       []AutoScalePolicy        `protobuf:"bytes,13,rep,name=auto_scale_policies,json=autoScalePolicies" json:"auto_scale_policies"`
	PrivacyPolicies         []PrivacyPolicy          `protobuf:"bytes,14,rep,name=privacy_policies,json=privacyPolicies" json:"privacy_policies"`
	ClusterInsts            []ClusterInst            `protobuf:"bytes,15,rep,name=cluster_insts,json=clusterInsts" json:"cluster_insts"`
	Apps                    []App                    `protobuf:"bytes,16,rep,name=apps" json:"apps"`
	AppInstances            []AppInst                `protobuf:"bytes,17,rep,name=app_instances,json=appInstances" json:"app_instances"`
	AppInstRefs             []AppInstRefs            `protobuf:"bytes,18,rep,name=app_inst_refs,json=appInstRefs" json:"app_inst_refs"`
}

func (m *AllData) Reset()                    { *m = AllData{} }
func (m *AllData) String() string            { return proto.CompactTextString(m) }
func (*AllData) ProtoMessage()               {}
func (*AllData) Descriptor() ([]byte, []int) { return fileDescriptorAlldata, []int{0} }

func init() {
	proto.RegisterType((*AllData)(nil), "edgeproto.AllData")
}
func (m *AllData) Marshal() (dAtA []byte, err error) {
	size := m.Size()
	dAtA = make([]byte, size)
	n, err := m.MarshalTo(dAtA)
	if err != nil {
		return nil, err
	}
	return dAtA[:n], nil
}

func (m *AllData) MarshalTo(dAtA []byte) (int, error) {
	var i int
	_ = i
	var l int
	_ = l
	if m.Settings != nil {
		dAtA[i] = 0xa
		i++
		i = encodeVarintAlldata(dAtA, i, uint64(m.Settings.Size()))
		n1, err := m.Settings.MarshalTo(dAtA[i:])
		if err != nil {
			return 0, err
		}
		i += n1
	}
	if len(m.Flavors) > 0 {
		for _, msg := range m.Flavors {
			dAtA[i] = 0x12
			i++
			i = encodeVarintAlldata(dAtA, i, uint64(msg.Size()))
			n, err := msg.MarshalTo(dAtA[i:])
			if err != nil {
				return 0, err
			}
			i += n
		}
	}
	if len(m.OperatorCodes) > 0 {
		for _, msg := range m.OperatorCodes {
			dAtA[i] = 0x22
			i++
			i = encodeVarintAlldata(dAtA, i, uint64(msg.Size()))
			n, err := msg.MarshalTo(dAtA[i:])
			if err != nil {
				return 0, err
			}
			i += n
		}
	}
	if len(m.ResTagTables) > 0 {
		for _, msg := range m.ResTagTables {
			dAtA[i] = 0x32
			i++
			i = encodeVarintAlldata(dAtA, i, uint64(msg.Size()))
			n, err := msg.MarshalTo(dAtA[i:])
			if err != nil {
				return 0, err
			}
			i += n
		}
	}
	if len(m.Cloudlets) > 0 {
		for _, msg := range m.Cloudlets {
			dAtA[i] = 0x3a
			i++
			i = encodeVarintAlldata(dAtA, i, uint64(msg.Size()))
			n, err := msg.MarshalTo(dAtA[i:])
			if err != nil {
				return 0, err
			}
			i += n
		}
	}
	if len(m.CloudletInfos) > 0 {
		for _, msg := range m.CloudletInfos {
			dAtA[i] = 0x42
			i++
			i = encodeVarintAlldata(dAtA, i, uint64(msg.Size()))
			n, err := msg.MarshalTo(dAtA[i:])
			if err != nil {
				return 0, err
			}
			i += n
		}
	}
	if len(m.CloudletPools) > 0 {
		for _, msg := range m.CloudletPools {
			dAtA[i] = 0x4a
			i++
			i = encodeVarintAlldata(dAtA, i, uint64(msg.Size()))
			n, err := msg.MarshalTo(dAtA[i:])
			if err != nil {
				return 0, err
			}
			i += n
		}
	}
	if len(m.CloudletPoolMembers) > 0 {
		for _, msg := range m.CloudletPoolMembers {
			dAtA[i] = 0x52
			i++
			i = encodeVarintAlldata(dAtA, i, uint64(msg.Size()))
			n, err := msg.MarshalTo(dAtA[i:])
			if err != nil {
				return 0, err
			}
			i += n
		}
	}
	if len(m.AutoProvPolicies) > 0 {
		for _, msg := range m.AutoProvPolicies {
			dAtA[i] = 0x5a
			i++
			i = encodeVarintAlldata(dAtA, i, uint64(msg.Size()))
			n, err := msg.MarshalTo(dAtA[i:])
			if err != nil {
				return 0, err
			}
			i += n
		}
	}
	if len(m.AutoProvPolicyCloudlets) > 0 {
		for _, msg := range m.AutoProvPolicyCloudlets {
			dAtA[i] = 0x62
			i++
			i = encodeVarintAlldata(dAtA, i, uint64(msg.Size()))
			n, err := msg.MarshalTo(dAtA[i:])
			if err != nil {
				return 0, err
			}
			i += n
		}
	}
	if len(m.AutoScalePolicies) > 0 {
		for _, msg := range m.AutoScalePolicies {
			dAtA[i] = 0x6a
			i++
			i = encodeVarintAlldata(dAtA, i, uint64(msg.Size()))
			n, err := msg.MarshalTo(dAtA[i:])
			if err != nil {
				return 0, err
			}
			i += n
		}
	}
	if len(m.PrivacyPolicies) > 0 {
		for _, msg := range m.PrivacyPolicies {
			dAtA[i] = 0x72
			i++
			i = encodeVarintAlldata(dAtA, i, uint64(msg.Size()))
			n, err := msg.MarshalTo(dAtA[i:])
			if err != nil {
				return 0, err
			}
			i += n
		}
	}
	if len(m.ClusterInsts) > 0 {
		for _, msg := range m.ClusterInsts {
			dAtA[i] = 0x7a
			i++
			i = encodeVarintAlldata(dAtA, i, uint64(msg.Size()))
			n, err := msg.MarshalTo(dAtA[i:])
			if err != nil {
				return 0, err
			}
			i += n
		}
	}
	if len(m.Apps) > 0 {
		for _, msg := range m.Apps {
			dAtA[i] = 0x82
			i++
			dAtA[i] = 0x1
			i++
			i = encodeVarintAlldata(dAtA, i, uint64(msg.Size()))
			n, err := msg.MarshalTo(dAtA[i:])
			if err != nil {
				return 0, err
			}
			i += n
		}
	}
	if len(m.AppInstances) > 0 {
		for _, msg := range m.AppInstances {
			dAtA[i] = 0x8a
			i++
			dAtA[i] = 0x1
			i++
			i = encodeVarintAlldata(dAtA, i, uint64(msg.Size()))
			n, err := msg.MarshalTo(dAtA[i:])
			if err != nil {
				return 0, err
			}
			i += n
		}
	}
	if len(m.AppInstRefs) > 0 {
		for _, msg := range m.AppInstRefs {
			dAtA[i] = 0x92
			i++
			dAtA[i] = 0x1
			i++
			i = encodeVarintAlldata(dAtA, i, uint64(msg.Size()))
			n, err := msg.MarshalTo(dAtA[i:])
			if err != nil {
				return 0, err
			}
			i += n
		}
	}
	return i, nil
}

func encodeVarintAlldata(dAtA []byte, offset int, v uint64) int {
	for v >= 1<<7 {
		dAtA[offset] = uint8(v&0x7f | 0x80)
		v >>= 7
		offset++
	}
	dAtA[offset] = uint8(v)
	return offset + 1
}
func (m *AllData) DeepCopyIn(src *AllData) {
	if src.Settings != nil {
		var tmp_Settings Settings
		tmp_Settings.DeepCopyIn(src.Settings)
		m.Settings = &tmp_Settings
	} else {
		m.Settings = nil
	}
	if src.Flavors != nil {
		m.Flavors = make([]Flavor, len(src.Flavors), len(src.Flavors))
		for ii, s := range src.Flavors {
			m.Flavors[ii].DeepCopyIn(&s)
		}
	} else {
		m.Flavors = nil
	}
	if src.OperatorCodes != nil {
		m.OperatorCodes = make([]OperatorCode, len(src.OperatorCodes), len(src.OperatorCodes))
		for ii, s := range src.OperatorCodes {
			m.OperatorCodes[ii].DeepCopyIn(&s)
		}
	} else {
		m.OperatorCodes = nil
	}
	if src.ResTagTables != nil {
		m.ResTagTables = make([]ResTagTable, len(src.ResTagTables), len(src.ResTagTables))
		for ii, s := range src.ResTagTables {
			m.ResTagTables[ii].DeepCopyIn(&s)
		}
	} else {
		m.ResTagTables = nil
	}
	if src.Cloudlets != nil {
		m.Cloudlets = make([]Cloudlet, len(src.Cloudlets), len(src.Cloudlets))
		for ii, s := range src.Cloudlets {
			m.Cloudlets[ii].DeepCopyIn(&s)
		}
	} else {
		m.Cloudlets = nil
	}
	if src.CloudletInfos != nil {
		m.CloudletInfos = make([]CloudletInfo, len(src.CloudletInfos), len(src.CloudletInfos))
		for ii, s := range src.CloudletInfos {
			m.CloudletInfos[ii].DeepCopyIn(&s)
		}
	} else {
		m.CloudletInfos = nil
	}
	if src.CloudletPools != nil {
		m.CloudletPools = make([]CloudletPool, len(src.CloudletPools), len(src.CloudletPools))
		for ii, s := range src.CloudletPools {
			m.CloudletPools[ii].DeepCopyIn(&s)
		}
	} else {
		m.CloudletPools = nil
	}
	if src.CloudletPoolMembers != nil {
		m.CloudletPoolMembers = make([]CloudletPoolMember, len(src.CloudletPoolMembers), len(src.CloudletPoolMembers))
		for ii, s := range src.CloudletPoolMembers {
			m.CloudletPoolMembers[ii].DeepCopyIn(&s)
		}
	} else {
		m.CloudletPoolMembers = nil
	}
	if src.AutoProvPolicies != nil {
		m.AutoProvPolicies = make([]AutoProvPolicy, len(src.AutoProvPolicies), len(src.AutoProvPolicies))
		for ii, s := range src.AutoProvPolicies {
			m.AutoProvPolicies[ii].DeepCopyIn(&s)
		}
	} else {
		m.AutoProvPolicies = nil
	}
	if src.AutoProvPolicyCloudlets != nil {
		m.AutoProvPolicyCloudlets = make([]AutoProvPolicyCloudlet, len(src.AutoProvPolicyCloudlets), len(src.AutoProvPolicyCloudlets))
		for ii, s := range src.AutoProvPolicyCloudlets {
			m.AutoProvPolicyCloudlets[ii].DeepCopyIn(&s)
		}
	} else {
		m.AutoProvPolicyCloudlets = nil
	}
	if src.AutoScalePolicies != nil {
		m.AutoScalePolicies = make([]AutoScalePolicy, len(src.AutoScalePolicies), len(src.AutoScalePolicies))
		for ii, s := range src.AutoScalePolicies {
			m.AutoScalePolicies[ii].DeepCopyIn(&s)
		}
	} else {
		m.AutoScalePolicies = nil
	}
	if src.PrivacyPolicies != nil {
		m.PrivacyPolicies = make([]PrivacyPolicy, len(src.PrivacyPolicies), len(src.PrivacyPolicies))
		for ii, s := range src.PrivacyPolicies {
			m.PrivacyPolicies[ii].DeepCopyIn(&s)
		}
	} else {
		m.PrivacyPolicies = nil
	}
	if src.ClusterInsts != nil {
		m.ClusterInsts = make([]ClusterInst, len(src.ClusterInsts), len(src.ClusterInsts))
		for ii, s := range src.ClusterInsts {
			m.ClusterInsts[ii].DeepCopyIn(&s)
		}
	} else {
		m.ClusterInsts = nil
	}
	if src.Apps != nil {
		m.Apps = make([]App, len(src.Apps), len(src.Apps))
		for ii, s := range src.Apps {
			m.Apps[ii].DeepCopyIn(&s)
		}
	} else {
		m.Apps = nil
	}
	if src.AppInstances != nil {
		m.AppInstances = make([]AppInst, len(src.AppInstances), len(src.AppInstances))
		for ii, s := range src.AppInstances {
			m.AppInstances[ii].DeepCopyIn(&s)
		}
	} else {
		m.AppInstances = nil
	}
	if src.AppInstRefs != nil {
		m.AppInstRefs = make([]AppInstRefs, len(src.AppInstRefs), len(src.AppInstRefs))
		for ii, s := range src.AppInstRefs {
			m.AppInstRefs[ii].DeepCopyIn(&s)
		}
	} else {
		m.AppInstRefs = nil
	}
}

// Helper method to check that enums have valid values
func (m *AllData) ValidateEnums() error {
	if err := m.Settings.ValidateEnums(); err != nil {
		return err
	}
	for _, e := range m.Flavors {
		if err := e.ValidateEnums(); err != nil {
			return err
		}
	}
	for _, e := range m.OperatorCodes {
		if err := e.ValidateEnums(); err != nil {
			return err
		}
	}
	for _, e := range m.ResTagTables {
		if err := e.ValidateEnums(); err != nil {
			return err
		}
	}
	for _, e := range m.Cloudlets {
		if err := e.ValidateEnums(); err != nil {
			return err
		}
	}
	for _, e := range m.CloudletInfos {
		if err := e.ValidateEnums(); err != nil {
			return err
		}
	}
	for _, e := range m.CloudletPools {
		if err := e.ValidateEnums(); err != nil {
			return err
		}
	}
	for _, e := range m.CloudletPoolMembers {
		if err := e.ValidateEnums(); err != nil {
			return err
		}
	}
	for _, e := range m.AutoProvPolicies {
		if err := e.ValidateEnums(); err != nil {
			return err
		}
	}
	for _, e := range m.AutoProvPolicyCloudlets {
		if err := e.ValidateEnums(); err != nil {
			return err
		}
	}
	for _, e := range m.AutoScalePolicies {
		if err := e.ValidateEnums(); err != nil {
			return err
		}
	}
	for _, e := range m.PrivacyPolicies {
		if err := e.ValidateEnums(); err != nil {
			return err
		}
	}
	for _, e := range m.ClusterInsts {
		if err := e.ValidateEnums(); err != nil {
			return err
		}
	}
	for _, e := range m.Apps {
		if err := e.ValidateEnums(); err != nil {
			return err
		}
	}
	for _, e := range m.AppInstances {
		if err := e.ValidateEnums(); err != nil {
			return err
		}
	}
	for _, e := range m.AppInstRefs {
		if err := e.ValidateEnums(); err != nil {
			return err
		}
	}
	return nil
}

func IgnoreAllDataFields(taglist string) cmp.Option {
	names := []string{}
	tags := make(map[string]struct{})
	for _, tag := range strings.Split(taglist, ",") {
		tags[tag] = struct{}{}
	}
	if _, found := tags["nocmp"]; found {
		names = append(names, "Cloudlets.Errors")
	}
	if _, found := tags["nocmp"]; found {
		names = append(names, "Cloudlets.Status")
	}
	if _, found := tags["nocmp"]; found {
		names = append(names, "Cloudlets.State")
	}
	if _, found := tags["nocmp"]; found {
		names = append(names, "Cloudlets.CrmOverride")
	}
	if _, found := tags["nocmp"]; found {
		names = append(names, "Cloudlets.DeploymentLocal")
	}
	if _, found := tags["nocmp"]; found {
		names = append(names, "Cloudlets.NotifySrvAddr")
	}
	if _, found := tags["nocmp"]; found {
		names = append(names, "Cloudlets.Config")
	}
	if _, found := tags["nocmp"]; found {
		names = append(names, "Cloudlets.Deployment")
	}
	if _, found := tags["nocmp"]; found {
		names = append(names, "CloudletInfos.NotifyId")
	}
	if _, found := tags["nocmp"]; found {
		names = append(names, "CloudletInfos.Controller")
	}
	if _, found := tags["nocmp"]; found {
		names = append(names, "ClusterInsts.State")
	}
	if _, found := tags["nocmp"]; found {
		names = append(names, "ClusterInsts.Errors")
	}
	if _, found := tags["nocmp"]; found {
		names = append(names, "ClusterInsts.CrmOverride")
	}
	if _, found := tags["nocmp"]; found {
		names = append(names, "ClusterInsts.AllocatedIp")
	}
	if _, found := tags["nocmp"]; found {
		names = append(names, "ClusterInsts.NodeFlavor")
	}
	if _, found := tags["nocmp"]; found {
		names = append(names, "ClusterInsts.ExternalVolumeSize")
	}
	if _, found := tags["nocmp"]; found {
		names = append(names, "ClusterInsts.ImageName")
	}
	if _, found := tags["nocmp"]; found {
		names = append(names, "ClusterInsts.MasterNodeFlavor")
	}
	if _, found := tags["nocmp"]; found {
		names = append(names, "ClusterInsts.SkipCrmCleanupOnFailure")
	}
	if _, found := tags["nocmp"]; found {
		names = append(names, "Apps.DeploymentManifest")
	}
	if _, found := tags["nocmp"]; found {
		names = append(names, "Apps.DeploymentGenerator")
	}
	if _, found := tags["nocmp"]; found {
		names = append(names, "Apps.DelOpt")
	}
	if _, found := tags["nocmp"]; found {
		names = append(names, "Apps.Revision")
	}
	if _, found := tags["nocmp"]; found {
		names = append(names, "Apps.DeletePrepare")
	}
	if _, found := tags["nocmp"]; found {
		names = append(names, "AppInstances.Uri")
	}
	if _, found := tags["nocmp"]; found {
		names = append(names, "AppInstances.State")
	}
	if _, found := tags["nocmp"]; found {
		names = append(names, "AppInstances.Errors")
	}
	if _, found := tags["nocmp"]; found {
		names = append(names, "AppInstances.CrmOverride")
	}
	if _, found := tags["nocmp"]; found {
		names = append(names, "AppInstances.RuntimeInfo.ContainerIds")
	}
	if _, found := tags["timestamp"]; found {
		names = append(names, "AppInstances.CreatedAt")
	}
	if _, found := tags["nocmp"]; found {
		names = append(names, "AppInstances.Revision")
	}
	if _, found := tags["nocmp"]; found {
		names = append(names, "AppInstances.ForceUpdate")
	}
	if _, found := tags["nocmp"]; found {
		names = append(names, "AppInstances.UpdateMultiple")
	}
	if _, found := tags["nocmp"]; found {
		names = append(names, "AppInstances.HealthCheck")
	}
	if _, found := tags["nocmp"]; found {
		names = append(names, "AppInstances.PowerState")
	}
	if _, found := tags["nocmp"]; found {
		names = append(names, "AppInstances.ExternalVolumeSize")
	}
	if _, found := tags["nocmp"]; found {
		names = append(names, "AppInstances.AvailabilityZone")
	}
	if _, found := tags["nocmp"]; found {
		names = append(names, "AppInstances.VmFlavor")
	}
	if _, found := tags["nocmp"]; found {
		names = append(names, "AppInstances.OptRes")
	}
	return cmpopts.IgnoreFields(AllData{}, names...)
}

func (m *AllData) Size() (n int) {
	var l int
	_ = l
	if m.Settings != nil {
		l = m.Settings.Size()
		n += 1 + l + sovAlldata(uint64(l))
	}
	if len(m.Flavors) > 0 {
		for _, e := range m.Flavors {
			l = e.Size()
			n += 1 + l + sovAlldata(uint64(l))
		}
	}
	if len(m.OperatorCodes) > 0 {
		for _, e := range m.OperatorCodes {
			l = e.Size()
			n += 1 + l + sovAlldata(uint64(l))
		}
	}
	if len(m.ResTagTables) > 0 {
		for _, e := range m.ResTagTables {
			l = e.Size()
			n += 1 + l + sovAlldata(uint64(l))
		}
	}
	if len(m.Cloudlets) > 0 {
		for _, e := range m.Cloudlets {
			l = e.Size()
			n += 1 + l + sovAlldata(uint64(l))
		}
	}
	if len(m.CloudletInfos) > 0 {
		for _, e := range m.CloudletInfos {
			l = e.Size()
			n += 1 + l + sovAlldata(uint64(l))
		}
	}
	if len(m.CloudletPools) > 0 {
		for _, e := range m.CloudletPools {
			l = e.Size()
			n += 1 + l + sovAlldata(uint64(l))
		}
	}
	if len(m.CloudletPoolMembers) > 0 {
		for _, e := range m.CloudletPoolMembers {
			l = e.Size()
			n += 1 + l + sovAlldata(uint64(l))
		}
	}
	if len(m.AutoProvPolicies) > 0 {
		for _, e := range m.AutoProvPolicies {
			l = e.Size()
			n += 1 + l + sovAlldata(uint64(l))
		}
	}
	if len(m.AutoProvPolicyCloudlets) > 0 {
		for _, e := range m.AutoProvPolicyCloudlets {
			l = e.Size()
			n += 1 + l + sovAlldata(uint64(l))
		}
	}
	if len(m.AutoScalePolicies) > 0 {
		for _, e := range m.AutoScalePolicies {
			l = e.Size()
			n += 1 + l + sovAlldata(uint64(l))
		}
	}
	if len(m.PrivacyPolicies) > 0 {
		for _, e := range m.PrivacyPolicies {
			l = e.Size()
			n += 1 + l + sovAlldata(uint64(l))
		}
	}
	if len(m.ClusterInsts) > 0 {
		for _, e := range m.ClusterInsts {
			l = e.Size()
			n += 1 + l + sovAlldata(uint64(l))
		}
	}
	if len(m.Apps) > 0 {
		for _, e := range m.Apps {
			l = e.Size()
			n += 2 + l + sovAlldata(uint64(l))
		}
	}
	if len(m.AppInstances) > 0 {
		for _, e := range m.AppInstances {
			l = e.Size()
			n += 2 + l + sovAlldata(uint64(l))
		}
	}
	if len(m.AppInstRefs) > 0 {
		for _, e := range m.AppInstRefs {
			l = e.Size()
			n += 2 + l + sovAlldata(uint64(l))
		}
	}
	return n
}

func sovAlldata(x uint64) (n int) {
	for {
		n++
		x >>= 7
		if x == 0 {
			break
		}
	}
	return n
}
func sozAlldata(x uint64) (n int) {
	return sovAlldata(uint64((x << 1) ^ uint64((int64(x) >> 63))))
}
func (m *AllData) Unmarshal(dAtA []byte) error {
	l := len(dAtA)
	iNdEx := 0
	for iNdEx < l {
		preIndex := iNdEx
		var wire uint64
		for shift := uint(0); ; shift += 7 {
			if shift >= 64 {
				return ErrIntOverflowAlldata
			}
			if iNdEx >= l {
				return io.ErrUnexpectedEOF
			}
			b := dAtA[iNdEx]
			iNdEx++
			wire |= (uint64(b) & 0x7F) << shift
			if b < 0x80 {
				break
			}
		}
		fieldNum := int32(wire >> 3)
		wireType := int(wire & 0x7)
		if wireType == 4 {
			return fmt.Errorf("proto: AllData: wiretype end group for non-group")
		}
		if fieldNum <= 0 {
			return fmt.Errorf("proto: AllData: illegal tag %d (wire type %d)", fieldNum, wire)
		}
		switch fieldNum {
		case 1:
			if wireType != 2 {
				return fmt.Errorf("proto: wrong wireType = %d for field Settings", wireType)
			}
			var msglen int
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowAlldata
				}
				if iNdEx >= l {
					return io.ErrUnexpectedEOF
				}
				b := dAtA[iNdEx]
				iNdEx++
				msglen |= (int(b) & 0x7F) << shift
				if b < 0x80 {
					break
				}
			}
			if msglen < 0 {
				return ErrInvalidLengthAlldata
			}
			postIndex := iNdEx + msglen
			if postIndex > l {
				return io.ErrUnexpectedEOF
			}
			if m.Settings == nil {
				m.Settings = &Settings{}
			}
			if err := m.Settings.Unmarshal(dAtA[iNdEx:postIndex]); err != nil {
				return err
			}
			iNdEx = postIndex
		case 2:
			if wireType != 2 {
				return fmt.Errorf("proto: wrong wireType = %d for field Flavors", wireType)
			}
			var msglen int
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowAlldata
				}
				if iNdEx >= l {
					return io.ErrUnexpectedEOF
				}
				b := dAtA[iNdEx]
				iNdEx++
				msglen |= (int(b) & 0x7F) << shift
				if b < 0x80 {
					break
				}
			}
			if msglen < 0 {
				return ErrInvalidLengthAlldata
			}
			postIndex := iNdEx + msglen
			if postIndex > l {
				return io.ErrUnexpectedEOF
			}
			m.Flavors = append(m.Flavors, Flavor{})
			if err := m.Flavors[len(m.Flavors)-1].Unmarshal(dAtA[iNdEx:postIndex]); err != nil {
				return err
			}
			iNdEx = postIndex
		case 4:
			if wireType != 2 {
				return fmt.Errorf("proto: wrong wireType = %d for field OperatorCodes", wireType)
			}
			var msglen int
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowAlldata
				}
				if iNdEx >= l {
					return io.ErrUnexpectedEOF
				}
				b := dAtA[iNdEx]
				iNdEx++
				msglen |= (int(b) & 0x7F) << shift
				if b < 0x80 {
					break
				}
			}
			if msglen < 0 {
				return ErrInvalidLengthAlldata
			}
			postIndex := iNdEx + msglen
			if postIndex > l {
				return io.ErrUnexpectedEOF
			}
			m.OperatorCodes = append(m.OperatorCodes, OperatorCode{})
			if err := m.OperatorCodes[len(m.OperatorCodes)-1].Unmarshal(dAtA[iNdEx:postIndex]); err != nil {
				return err
			}
			iNdEx = postIndex
		case 6:
			if wireType != 2 {
				return fmt.Errorf("proto: wrong wireType = %d for field ResTagTables", wireType)
			}
			var msglen int
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowAlldata
				}
				if iNdEx >= l {
					return io.ErrUnexpectedEOF
				}
				b := dAtA[iNdEx]
				iNdEx++
				msglen |= (int(b) & 0x7F) << shift
				if b < 0x80 {
					break
				}
			}
			if msglen < 0 {
				return ErrInvalidLengthAlldata
			}
			postIndex := iNdEx + msglen
			if postIndex > l {
				return io.ErrUnexpectedEOF
			}
			m.ResTagTables = append(m.ResTagTables, ResTagTable{})
			if err := m.ResTagTables[len(m.ResTagTables)-1].Unmarshal(dAtA[iNdEx:postIndex]); err != nil {
				return err
			}
			iNdEx = postIndex
		case 7:
			if wireType != 2 {
				return fmt.Errorf("proto: wrong wireType = %d for field Cloudlets", wireType)
			}
			var msglen int
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowAlldata
				}
				if iNdEx >= l {
					return io.ErrUnexpectedEOF
				}
				b := dAtA[iNdEx]
				iNdEx++
				msglen |= (int(b) & 0x7F) << shift
				if b < 0x80 {
					break
				}
			}
			if msglen < 0 {
				return ErrInvalidLengthAlldata
			}
			postIndex := iNdEx + msglen
			if postIndex > l {
				return io.ErrUnexpectedEOF
			}
			m.Cloudlets = append(m.Cloudlets, Cloudlet{})
			if err := m.Cloudlets[len(m.Cloudlets)-1].Unmarshal(dAtA[iNdEx:postIndex]); err != nil {
				return err
			}
			iNdEx = postIndex
		case 8:
			if wireType != 2 {
				return fmt.Errorf("proto: wrong wireType = %d for field CloudletInfos", wireType)
			}
			var msglen int
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowAlldata
				}
				if iNdEx >= l {
					return io.ErrUnexpectedEOF
				}
				b := dAtA[iNdEx]
				iNdEx++
				msglen |= (int(b) & 0x7F) << shift
				if b < 0x80 {
					break
				}
			}
			if msglen < 0 {
				return ErrInvalidLengthAlldata
			}
			postIndex := iNdEx + msglen
			if postIndex > l {
				return io.ErrUnexpectedEOF
			}
			m.CloudletInfos = append(m.CloudletInfos, CloudletInfo{})
			if err := m.CloudletInfos[len(m.CloudletInfos)-1].Unmarshal(dAtA[iNdEx:postIndex]); err != nil {
				return err
			}
			iNdEx = postIndex
		case 9:
			if wireType != 2 {
				return fmt.Errorf("proto: wrong wireType = %d for field CloudletPools", wireType)
			}
			var msglen int
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowAlldata
				}
				if iNdEx >= l {
					return io.ErrUnexpectedEOF
				}
				b := dAtA[iNdEx]
				iNdEx++
				msglen |= (int(b) & 0x7F) << shift
				if b < 0x80 {
					break
				}
			}
			if msglen < 0 {
				return ErrInvalidLengthAlldata
			}
			postIndex := iNdEx + msglen
			if postIndex > l {
				return io.ErrUnexpectedEOF
			}
			m.CloudletPools = append(m.CloudletPools, CloudletPool{})
			if err := m.CloudletPools[len(m.CloudletPools)-1].Unmarshal(dAtA[iNdEx:postIndex]); err != nil {
				return err
			}
			iNdEx = postIndex
		case 10:
			if wireType != 2 {
				return fmt.Errorf("proto: wrong wireType = %d for field CloudletPoolMembers", wireType)
			}
			var msglen int
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowAlldata
				}
				if iNdEx >= l {
					return io.ErrUnexpectedEOF
				}
				b := dAtA[iNdEx]
				iNdEx++
				msglen |= (int(b) & 0x7F) << shift
				if b < 0x80 {
					break
				}
			}
			if msglen < 0 {
				return ErrInvalidLengthAlldata
			}
			postIndex := iNdEx + msglen
			if postIndex > l {
				return io.ErrUnexpectedEOF
			}
			m.CloudletPoolMembers = append(m.CloudletPoolMembers, CloudletPoolMember{})
			if err := m.CloudletPoolMembers[len(m.CloudletPoolMembers)-1].Unmarshal(dAtA[iNdEx:postIndex]); err != nil {
				return err
			}
			iNdEx = postIndex
		case 11:
			if wireType != 2 {
				return fmt.Errorf("proto: wrong wireType = %d for field AutoProvPolicies", wireType)
			}
			var msglen int
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowAlldata
				}
				if iNdEx >= l {
					return io.ErrUnexpectedEOF
				}
				b := dAtA[iNdEx]
				iNdEx++
				msglen |= (int(b) & 0x7F) << shift
				if b < 0x80 {
					break
				}
			}
			if msglen < 0 {
				return ErrInvalidLengthAlldata
			}
			postIndex := iNdEx + msglen
			if postIndex > l {
				return io.ErrUnexpectedEOF
			}
			m.AutoProvPolicies = append(m.AutoProvPolicies, AutoProvPolicy{})
			if err := m.AutoProvPolicies[len(m.AutoProvPolicies)-1].Unmarshal(dAtA[iNdEx:postIndex]); err != nil {
				return err
			}
			iNdEx = postIndex
		case 12:
			if wireType != 2 {
				return fmt.Errorf("proto: wrong wireType = %d for field AutoProvPolicyCloudlets", wireType)
			}
			var msglen int
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowAlldata
				}
				if iNdEx >= l {
					return io.ErrUnexpectedEOF
				}
				b := dAtA[iNdEx]
				iNdEx++
				msglen |= (int(b) & 0x7F) << shift
				if b < 0x80 {
					break
				}
			}
			if msglen < 0 {
				return ErrInvalidLengthAlldata
			}
			postIndex := iNdEx + msglen
			if postIndex > l {
				return io.ErrUnexpectedEOF
			}
			m.AutoProvPolicyCloudlets = append(m.AutoProvPolicyCloudlets, AutoProvPolicyCloudlet{})
			if err := m.AutoProvPolicyCloudlets[len(m.AutoProvPolicyCloudlets)-1].Unmarshal(dAtA[iNdEx:postIndex]); err != nil {
				return err
			}
			iNdEx = postIndex
		case 13:
			if wireType != 2 {
				return fmt.Errorf("proto: wrong wireType = %d for field AutoScalePolicies", wireType)
			}
			var msglen int
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowAlldata
				}
				if iNdEx >= l {
					return io.ErrUnexpectedEOF
				}
				b := dAtA[iNdEx]
				iNdEx++
				msglen |= (int(b) & 0x7F) << shift
				if b < 0x80 {
					break
				}
			}
			if msglen < 0 {
				return ErrInvalidLengthAlldata
			}
			postIndex := iNdEx + msglen
			if postIndex > l {
				return io.ErrUnexpectedEOF
			}
			m.AutoScalePolicies = append(m.AutoScalePolicies, AutoScalePolicy{})
			if err := m.AutoScalePolicies[len(m.AutoScalePolicies)-1].Unmarshal(dAtA[iNdEx:postIndex]); err != nil {
				return err
			}
			iNdEx = postIndex
		case 14:
			if wireType != 2 {
				return fmt.Errorf("proto: wrong wireType = %d for field PrivacyPolicies", wireType)
			}
			var msglen int
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowAlldata
				}
				if iNdEx >= l {
					return io.ErrUnexpectedEOF
				}
				b := dAtA[iNdEx]
				iNdEx++
				msglen |= (int(b) & 0x7F) << shift
				if b < 0x80 {
					break
				}
			}
			if msglen < 0 {
				return ErrInvalidLengthAlldata
			}
			postIndex := iNdEx + msglen
			if postIndex > l {
				return io.ErrUnexpectedEOF
			}
			m.PrivacyPolicies = append(m.PrivacyPolicies, PrivacyPolicy{})
			if err := m.PrivacyPolicies[len(m.PrivacyPolicies)-1].Unmarshal(dAtA[iNdEx:postIndex]); err != nil {
				return err
			}
			iNdEx = postIndex
		case 15:
			if wireType != 2 {
				return fmt.Errorf("proto: wrong wireType = %d for field ClusterInsts", wireType)
			}
			var msglen int
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowAlldata
				}
				if iNdEx >= l {
					return io.ErrUnexpectedEOF
				}
				b := dAtA[iNdEx]
				iNdEx++
				msglen |= (int(b) & 0x7F) << shift
				if b < 0x80 {
					break
				}
			}
			if msglen < 0 {
				return ErrInvalidLengthAlldata
			}
			postIndex := iNdEx + msglen
			if postIndex > l {
				return io.ErrUnexpectedEOF
			}
			m.ClusterInsts = append(m.ClusterInsts, ClusterInst{})
			if err := m.ClusterInsts[len(m.ClusterInsts)-1].Unmarshal(dAtA[iNdEx:postIndex]); err != nil {
				return err
			}
			iNdEx = postIndex
		case 16:
			if wireType != 2 {
				return fmt.Errorf("proto: wrong wireType = %d for field Apps", wireType)
			}
			var msglen int
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowAlldata
				}
				if iNdEx >= l {
					return io.ErrUnexpectedEOF
				}
				b := dAtA[iNdEx]
				iNdEx++
				msglen |= (int(b) & 0x7F) << shift
				if b < 0x80 {
					break
				}
			}
			if msglen < 0 {
				return ErrInvalidLengthAlldata
			}
			postIndex := iNdEx + msglen
			if postIndex > l {
				return io.ErrUnexpectedEOF
			}
			m.Apps = append(m.Apps, App{})
			if err := m.Apps[len(m.Apps)-1].Unmarshal(dAtA[iNdEx:postIndex]); err != nil {
				return err
			}
			iNdEx = postIndex
		case 17:
			if wireType != 2 {
				return fmt.Errorf("proto: wrong wireType = %d for field AppInstances", wireType)
			}
			var msglen int
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowAlldata
				}
				if iNdEx >= l {
					return io.ErrUnexpectedEOF
				}
				b := dAtA[iNdEx]
				iNdEx++
				msglen |= (int(b) & 0x7F) << shift
				if b < 0x80 {
					break
				}
			}
			if msglen < 0 {
				return ErrInvalidLengthAlldata
			}
			postIndex := iNdEx + msglen
			if postIndex > l {
				return io.ErrUnexpectedEOF
			}
			m.AppInstances = append(m.AppInstances, AppInst{})
			if err := m.AppInstances[len(m.AppInstances)-1].Unmarshal(dAtA[iNdEx:postIndex]); err != nil {
				return err
			}
			iNdEx = postIndex
		case 18:
			if wireType != 2 {
				return fmt.Errorf("proto: wrong wireType = %d for field AppInstRefs", wireType)
			}
			var msglen int
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowAlldata
				}
				if iNdEx >= l {
					return io.ErrUnexpectedEOF
				}
				b := dAtA[iNdEx]
				iNdEx++
				msglen |= (int(b) & 0x7F) << shift
				if b < 0x80 {
					break
				}
			}
			if msglen < 0 {
				return ErrInvalidLengthAlldata
			}
			postIndex := iNdEx + msglen
			if postIndex > l {
				return io.ErrUnexpectedEOF
			}
			m.AppInstRefs = append(m.AppInstRefs, AppInstRefs{})
			if err := m.AppInstRefs[len(m.AppInstRefs)-1].Unmarshal(dAtA[iNdEx:postIndex]); err != nil {
				return err
			}
			iNdEx = postIndex
		default:
			iNdEx = preIndex
			skippy, err := skipAlldata(dAtA[iNdEx:])
			if err != nil {
				return err
			}
			if skippy < 0 {
				return ErrInvalidLengthAlldata
			}
			if (iNdEx + skippy) > l {
				return io.ErrUnexpectedEOF
			}
			iNdEx += skippy
		}
	}

	if iNdEx > l {
		return io.ErrUnexpectedEOF
	}
	return nil
}
func skipAlldata(dAtA []byte) (n int, err error) {
	l := len(dAtA)
	iNdEx := 0
	for iNdEx < l {
		var wire uint64
		for shift := uint(0); ; shift += 7 {
			if shift >= 64 {
				return 0, ErrIntOverflowAlldata
			}
			if iNdEx >= l {
				return 0, io.ErrUnexpectedEOF
			}
			b := dAtA[iNdEx]
			iNdEx++
			wire |= (uint64(b) & 0x7F) << shift
			if b < 0x80 {
				break
			}
		}
		wireType := int(wire & 0x7)
		switch wireType {
		case 0:
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return 0, ErrIntOverflowAlldata
				}
				if iNdEx >= l {
					return 0, io.ErrUnexpectedEOF
				}
				iNdEx++
				if dAtA[iNdEx-1] < 0x80 {
					break
				}
			}
			return iNdEx, nil
		case 1:
			iNdEx += 8
			return iNdEx, nil
		case 2:
			var length int
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return 0, ErrIntOverflowAlldata
				}
				if iNdEx >= l {
					return 0, io.ErrUnexpectedEOF
				}
				b := dAtA[iNdEx]
				iNdEx++
				length |= (int(b) & 0x7F) << shift
				if b < 0x80 {
					break
				}
			}
			iNdEx += length
			if length < 0 {
				return 0, ErrInvalidLengthAlldata
			}
			return iNdEx, nil
		case 3:
			for {
				var innerWire uint64
				var start int = iNdEx
				for shift := uint(0); ; shift += 7 {
					if shift >= 64 {
						return 0, ErrIntOverflowAlldata
					}
					if iNdEx >= l {
						return 0, io.ErrUnexpectedEOF
					}
					b := dAtA[iNdEx]
					iNdEx++
					innerWire |= (uint64(b) & 0x7F) << shift
					if b < 0x80 {
						break
					}
				}
				innerWireType := int(innerWire & 0x7)
				if innerWireType == 4 {
					break
				}
				next, err := skipAlldata(dAtA[start:])
				if err != nil {
					return 0, err
				}
				iNdEx = start + next
			}
			return iNdEx, nil
		case 4:
			return iNdEx, nil
		case 5:
			iNdEx += 4
			return iNdEx, nil
		default:
			return 0, fmt.Errorf("proto: illegal wireType %d", wireType)
		}
	}
	panic("unreachable")
}

var (
	ErrInvalidLengthAlldata = fmt.Errorf("proto: negative length found during unmarshaling")
	ErrIntOverflowAlldata   = fmt.Errorf("proto: integer overflow")
)

func init() { proto.RegisterFile("alldata.proto", fileDescriptorAlldata) }

var fileDescriptorAlldata = []byte{
	// 651 bytes of a gzipped FileDescriptorProto
	0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0xff, 0x74, 0x94, 0xcd, 0x6e, 0x13, 0x31,
	0x10, 0xc7, 0x1b, 0xa8, 0xda, 0xc4, 0xf9, 0x68, 0xe2, 0xb4, 0xd4, 0x44, 0x22, 0x14, 0x4e, 0xbd,
	0x90, 0x88, 0x72, 0x00, 0x21, 0x21, 0xd1, 0x0f, 0x21, 0xf5, 0x50, 0x11, 0xa5, 0x95, 0x38, 0xae,
	0x9c, 0x8d, 0xb3, 0xac, 0xe4, 0xac, 0x2d, 0x8f, 0x13, 0xd1, 0x37, 0xe1, 0xc8, 0xe3, 0xf4, 0xc8,
	0x13, 0xf0, 0xd1, 0x87, 0xe8, 0x19, 0xd9, 0x6b, 0x77, 0xbd, 0x09, 0xbd, 0x44, 0xf6, 0x7f, 0xe6,
	0xff, 0xb3, 0x67, 0x76, 0x1c, 0xd4, 0xa4, 0x9c, 0x4f, 0xa9, 0xa6, 0x03, 0xa9, 0x84, 0x16, 0xb8,
	0xc6, 0xa6, 0x09, 0xb3, 0xcb, 0xde, 0xbb, 0x24, 0xd5, 0x5f, 0x17, 0x93, 0x41, 0x2c, 0xe6, 0xc3,
	0xb9, 0x98, 0xa4, 0xdc, 0x84, 0xbe, 0x0d, 0xcd, 0xef, 0xab, 0x98, 0x8b, 0xc5, 0x74, 0x68, 0xf3,
	0x12, 0x96, 0xdd, 0x2f, 0x72, 0x48, 0xaf, 0x05, 0x4c, 0xeb, 0x34, 0x4b, 0xc0, 0xed, 0x1b, 0x33,
	0x4e, 0x97, 0x42, 0xb9, 0x1d, 0x16, 0x92, 0x29, 0xaa, 0x85, 0x8a, 0xc5, 0x94, 0x39, 0xad, 0xa3,
	0x18, 0x68, 0x9a, 0x68, 0x3a, 0xe1, 0x5e, 0x6a, 0xd9, 0x33, 0x38, 0xd3, 0xde, 0xe6, 0xf7, 0x52,
	0x08, 0xee, 0xb4, 0x5d, 0xba, 0xd0, 0x42, 0x2a, 0xb1, 0x94, 0x82, 0xa7, 0xf1, 0xb5, 0x53, 0xf7,
	0x8c, 0x0a, 0x31, 0xe5, 0xac, 0x24, 0x77, 0xa5, 0x4a, 0x97, 0x34, 0xbe, 0x2e, 0x89, 0x9d, 0x98,
	0x2f, 0x40, 0x33, 0x95, 0x66, 0xe0, 0x0f, 0xaa, 0x51, 0x29, 0xdd, 0xb2, 0x49, 0xa5, 0x0c, 0x22,
	0x48, 0xb1, 0x99, 0xaf, 0x69, 0x37, 0x11, 0x89, 0xb0, 0xcb, 0xa1, 0x59, 0xe5, 0xea, 0xcb, 0xdf,
	0x55, 0xb4, 0x7d, 0xcc, 0xf9, 0x19, 0xd5, 0x14, 0x0f, 0x51, 0xd5, 0xf7, 0x81, 0x54, 0x0e, 0x2a,
	0x87, 0xf5, 0xa3, 0xee, 0xe0, 0xbe, 0xbb, 0x83, 0x4b, 0x17, 0x1a, 0xdf, 0x27, 0xe1, 0xd7, 0x68,
	0x3b, 0x6f, 0x14, 0x90, 0x47, 0x07, 0x8f, 0x0f, 0xeb, 0x47, 0x9d, 0x20, 0xff, 0x93, 0x8d, 0x9c,
	0x6c, 0xde, 0xfc, 0x7a, 0xbe, 0x31, 0xf6, 0x79, 0xf8, 0x0c, 0xb5, 0x7c, 0x37, 0x23, 0xd3, 0x4e,
	0x20, 0x9b, 0xd6, 0xb9, 0x1f, 0x38, 0x3f, 0xbb, 0x84, 0x53, 0x31, 0x65, 0xce, 0xdf, 0x14, 0x81,
	0x06, 0xf8, 0x04, 0xb5, 0x14, 0x83, 0x48, 0xd3, 0x24, 0xb2, 0x5f, 0x00, 0xc8, 0x96, 0xa5, 0x3c,
	0x09, 0x28, 0x63, 0x06, 0x57, 0x34, 0xb9, 0x32, 0x61, 0x07, 0x69, 0xa8, 0x42, 0x02, 0xfc, 0x16,
	0xd5, 0xfc, 0x07, 0x02, 0xb2, 0x6d, 0xed, 0x61, 0xb9, 0xa7, 0x2e, 0xe6, 0xbc, 0x45, 0xae, 0x29,
	0xc1, 0x6f, 0xa2, 0x34, 0x9b, 0x09, 0x20, 0xd5, 0xb5, 0x12, 0xbc, 0xfb, 0x3c, 0x9b, 0x09, 0x5f,
	0x42, 0x1c, 0x68, 0x65, 0x8a, 0x19, 0x10, 0x20, 0xb5, 0x07, 0x29, 0x23, 0x21, 0xf8, 0x2a, 0xc5,
	0x68, 0x80, 0xbf, 0xa0, 0xbd, 0x12, 0x25, 0x9a, 0xb3, 0xf9, 0x84, 0x29, 0x20, 0xc8, 0xc2, 0x9e,
	0x3d, 0x00, 0xbb, 0xb0, 0x59, 0x0e, 0xd9, 0x8d, 0xd7, 0x22, 0x80, 0x2f, 0x10, 0x36, 0x43, 0x19,
	0x99, 0x59, 0x8d, 0xec, 0x00, 0xa6, 0x0c, 0x48, 0xdd, 0x52, 0x9f, 0x06, 0xd4, 0xe3, 0x85, 0x16,
	0x23, 0x25, 0x96, 0x23, 0x3b, 0xa3, 0x8e, 0xd8, 0xa6, 0xa1, 0x9a, 0x32, 0xc0, 0x53, 0xd4, 0x5b,
	0xc1, 0x5d, 0x47, 0x45, 0xf7, 0x1b, 0x16, 0xfb, 0xe2, 0x41, 0xec, 0xca, 0xb7, 0xd8, 0xa7, 0xff,
	0x8d, 0x02, 0x1e, 0xa1, 0xae, 0x3d, 0xc5, 0x3e, 0xa5, 0xe2, 0xd6, 0x4d, 0x8b, 0xef, 0xad, 0xe0,
	0x2f, 0x4d, 0x52, 0xe9, 0xda, 0x1d, 0x5a, 0x92, 0xcd, 0xbd, 0xcf, 0x51, 0xdb, 0x3d, 0xc2, 0x02,
	0xd7, 0xb2, 0x38, 0x12, 0xe0, 0x46, 0x79, 0x4a, 0x09, 0xb6, 0x23, 0x03, 0xd1, 0xa0, 0x8e, 0x51,
	0xd3, 0x3d, 0xdd, 0xc8, 0xbc, 0x50, 0x20, 0x3b, 0x6b, 0x23, 0x7b, 0x9a, 0xc7, 0xcf, 0x33, 0xf0,
	0xa5, 0x36, 0xe2, 0x42, 0x02, 0x7c, 0x88, 0x36, 0xa9, 0x94, 0x40, 0xda, 0xd6, 0xd9, 0x0a, 0x0b,
	0x92, 0xd2, 0x39, 0x6c, 0x06, 0xfe, 0x80, 0xcc, 0x3f, 0x81, 0x3d, 0x88, 0x66, 0x31, 0x03, 0xd2,
	0xb1, 0x16, 0x5c, 0xb6, 0x84, 0x07, 0xd1, 0x7c, 0x6b, 0xb3, 0xf1, 0xc7, 0xc2, 0x1e, 0x99, 0xbf,
	0x10, 0x82, 0xd7, 0xee, 0xea, 0xec, 0x63, 0x36, 0x03, 0x87, 0xa8, 0xd3, 0x42, 0x7a, 0x5f, 0xfd,
	0x7e, 0x47, 0x2a, 0x3f, 0xee, 0xc8, 0xc6, 0x49, 0xfb, 0xe6, 0x6f, 0x7f, 0xe3, 0xe6, 0xb6, 0x5f,
	0xf9, 0x79, 0xdb, 0xaf, 0xfc, 0xb9, 0xed, 0x57, 0x26, 0x5b, 0x96, 0xf0, 0xe6, 0x5f, 0x00, 0x00,
	0x00, 0xff, 0xff, 0x62, 0x82, 0xe4, 0x30, 0xca, 0x05, 0x00, 0x00,
}
