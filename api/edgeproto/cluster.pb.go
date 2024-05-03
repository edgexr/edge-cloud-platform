// Code generated by protoc-gen-gogo. DO NOT EDIT.
// source: cluster.proto

package edgeproto

import (
	"encoding/json"
	fmt "fmt"
	"github.com/edgexr/edge-cloud-platform/pkg/log"
	_ "github.com/edgexr/edge-cloud-platform/tools/protogen"
	_ "github.com/gogo/protobuf/gogoproto"
	proto "github.com/gogo/protobuf/proto"
	io "io"
	math "math"
	math_bits "math/bits"
	reflect "reflect"
	strings "strings"
)

// Reference imports to suppress errors if they are not otherwise used.
var _ = proto.Marshal
var _ = fmt.Errorf
var _ = math.Inf

// This is a compile-time assertion to ensure that this generated file
// is compatible with the proto package it is being compiled against.
// A compilation error at this line likely means your copy of the
// proto package needs to be updated.
const _ = proto.GoGoProtoPackageIsVersion3 // please upgrade the proto package

// (_deprecated_) ClusterKeyV1 uniquely identifies a Cluster.
type ClusterKeyV1 struct {
	// Cluster name
	Name string `protobuf:"bytes,1,opt,name=name,proto3" json:"name,omitempty"`
}

func (m *ClusterKeyV1) Reset()         { *m = ClusterKeyV1{} }
func (m *ClusterKeyV1) String() string { return proto.CompactTextString(m) }
func (*ClusterKeyV1) ProtoMessage()    {}
func (*ClusterKeyV1) Descriptor() ([]byte, []int) {
	return fileDescriptor_3cfb3b8ec240c376, []int{0}
}
func (m *ClusterKeyV1) XXX_Unmarshal(b []byte) error {
	return m.Unmarshal(b)
}
func (m *ClusterKeyV1) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	if deterministic {
		return xxx_messageInfo_ClusterKeyV1.Marshal(b, m, deterministic)
	} else {
		b = b[:cap(b)]
		n, err := m.MarshalToSizedBuffer(b)
		if err != nil {
			return nil, err
		}
		return b[:n], nil
	}
}
func (m *ClusterKeyV1) XXX_Merge(src proto.Message) {
	xxx_messageInfo_ClusterKeyV1.Merge(m, src)
}
func (m *ClusterKeyV1) XXX_Size() int {
	return m.Size()
}
func (m *ClusterKeyV1) XXX_DiscardUnknown() {
	xxx_messageInfo_ClusterKeyV1.DiscardUnknown(m)
}

var xxx_messageInfo_ClusterKeyV1 proto.InternalMessageInfo

// ClusterKey uniquely identifies a Cluster.
type ClusterKey struct {
	// Cluster name
	Name string `protobuf:"bytes,1,opt,name=name,proto3" json:"name,omitempty"`
	// Name of the organization that this cluster belongs to
	Organization string `protobuf:"bytes,2,opt,name=organization,proto3" json:"organization,omitempty"`
}

func (m *ClusterKey) Reset()         { *m = ClusterKey{} }
func (m *ClusterKey) String() string { return proto.CompactTextString(m) }
func (*ClusterKey) ProtoMessage()    {}
func (*ClusterKey) Descriptor() ([]byte, []int) {
	return fileDescriptor_3cfb3b8ec240c376, []int{1}
}
func (m *ClusterKey) XXX_Unmarshal(b []byte) error {
	return m.Unmarshal(b)
}
func (m *ClusterKey) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	if deterministic {
		return xxx_messageInfo_ClusterKey.Marshal(b, m, deterministic)
	} else {
		b = b[:cap(b)]
		n, err := m.MarshalToSizedBuffer(b)
		if err != nil {
			return nil, err
		}
		return b[:n], nil
	}
}
func (m *ClusterKey) XXX_Merge(src proto.Message) {
	xxx_messageInfo_ClusterKey.Merge(m, src)
}
func (m *ClusterKey) XXX_Size() int {
	return m.Size()
}
func (m *ClusterKey) XXX_DiscardUnknown() {
	xxx_messageInfo_ClusterKey.DiscardUnknown(m)
}

var xxx_messageInfo_ClusterKey proto.InternalMessageInfo

func init() {
	proto.RegisterType((*ClusterKeyV1)(nil), "edgeproto.ClusterKeyV1")
	proto.RegisterType((*ClusterKey)(nil), "edgeproto.ClusterKey")
}

func init() { proto.RegisterFile("cluster.proto", fileDescriptor_3cfb3b8ec240c376) }

var fileDescriptor_3cfb3b8ec240c376 = []byte{
	// 220 bytes of a gzipped FileDescriptorProto
	0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0xff, 0xe2, 0xe2, 0x4d, 0xce, 0x29, 0x2d,
	0x2e, 0x49, 0x2d, 0xd2, 0x2b, 0x28, 0xca, 0x2f, 0xc9, 0x17, 0xe2, 0x4c, 0x4d, 0x49, 0x4f, 0x05,
	0x33, 0xa5, 0x64, 0x4b, 0xf2, 0xf3, 0x73, 0x8a, 0xf5, 0xc1, 0x9c, 0xf4, 0xd4, 0x3c, 0x38, 0x03,
	0xa2, 0x52, 0x4a, 0x24, 0x3d, 0x3f, 0x3d, 0x1f, 0xcc, 0xd4, 0x07, 0xb1, 0x20, 0xa2, 0x4a, 0x8e,
	0x5c, 0x3c, 0xce, 0x10, 0x03, 0xbd, 0x53, 0x2b, 0xc3, 0x0c, 0x85, 0x94, 0xb9, 0x58, 0xf2, 0x12,
	0x73, 0x53, 0x25, 0x18, 0x15, 0x18, 0x35, 0x38, 0x9d, 0xf8, 0x77, 0x7d, 0x93, 0x60, 0x87, 0x5a,
	0x78, 0xe1, 0x9b, 0x04, 0x63, 0x10, 0x58, 0xd2, 0x8a, 0xe7, 0xc5, 0x67, 0x09, 0xc6, 0x1f, 0x9f,
	0x25, 0x18, 0x37, 0x2c, 0x90, 0x67, 0x54, 0xca, 0xe7, 0xe2, 0x42, 0x18, 0x21, 0x24, 0x8f, 0x62,
	0x00, 0x37, 0x92, 0x01, 0x10, 0xcd, 0x42, 0x46, 0x5c, 0x3c, 0xf9, 0x45, 0xe9, 0x89, 0x79, 0x99,
	0x55, 0x89, 0x25, 0x99, 0xf9, 0x79, 0x12, 0x4c, 0x60, 0x85, 0x7c, 0xbb, 0xbe, 0x49, 0x70, 0x41,
	0x15, 0xe6, 0x17, 0xa5, 0x07, 0xa1, 0xa8, 0x41, 0xb5, 0xd0, 0x49, 0xe6, 0xc4, 0x43, 0x39, 0x86,
	0x13, 0x8f, 0xe4, 0x18, 0x2f, 0x3c, 0x92, 0x63, 0x7c, 0xf0, 0x48, 0x8e, 0x71, 0xc2, 0x63, 0x39,
	0x86, 0x0b, 0x8f, 0xe5, 0x18, 0x6e, 0x3c, 0x96, 0x63, 0x48, 0x62, 0x03, 0x7b, 0xcc, 0x18, 0x10,
	0x00, 0x00, 0xff, 0xff, 0xb2, 0x97, 0x76, 0x64, 0x29, 0x01, 0x00, 0x00,
}

func (this *ClusterKeyV1) GoString() string {
	if this == nil {
		return "nil"
	}
	s := make([]string, 0, 5)
	s = append(s, "&edgeproto.ClusterKeyV1{")
	s = append(s, "Name: "+fmt.Sprintf("%#v", this.Name)+",\n")
	s = append(s, "}")
	return strings.Join(s, "")
}
func (this *ClusterKey) GoString() string {
	if this == nil {
		return "nil"
	}
	s := make([]string, 0, 6)
	s = append(s, "&edgeproto.ClusterKey{")
	s = append(s, "Name: "+fmt.Sprintf("%#v", this.Name)+",\n")
	s = append(s, "Organization: "+fmt.Sprintf("%#v", this.Organization)+",\n")
	s = append(s, "}")
	return strings.Join(s, "")
}
func valueToGoStringCluster(v interface{}, typ string) string {
	rv := reflect.ValueOf(v)
	if rv.IsNil() {
		return "nil"
	}
	pv := reflect.Indirect(rv).Interface()
	return fmt.Sprintf("func(v %v) *%v { return &v } ( %#v )", typ, typ, pv)
}
func (m *ClusterKeyV1) Marshal() (dAtA []byte, err error) {
	size := m.Size()
	dAtA = make([]byte, size)
	n, err := m.MarshalToSizedBuffer(dAtA[:size])
	if err != nil {
		return nil, err
	}
	return dAtA[:n], nil
}

func (m *ClusterKeyV1) MarshalTo(dAtA []byte) (int, error) {
	size := m.Size()
	return m.MarshalToSizedBuffer(dAtA[:size])
}

func (m *ClusterKeyV1) MarshalToSizedBuffer(dAtA []byte) (int, error) {
	i := len(dAtA)
	_ = i
	var l int
	_ = l
	if len(m.Name) > 0 {
		i -= len(m.Name)
		copy(dAtA[i:], m.Name)
		i = encodeVarintCluster(dAtA, i, uint64(len(m.Name)))
		i--
		dAtA[i] = 0xa
	}
	return len(dAtA) - i, nil
}

func (m *ClusterKey) Marshal() (dAtA []byte, err error) {
	size := m.Size()
	dAtA = make([]byte, size)
	n, err := m.MarshalToSizedBuffer(dAtA[:size])
	if err != nil {
		return nil, err
	}
	return dAtA[:n], nil
}

func (m *ClusterKey) MarshalTo(dAtA []byte) (int, error) {
	size := m.Size()
	return m.MarshalToSizedBuffer(dAtA[:size])
}

func (m *ClusterKey) MarshalToSizedBuffer(dAtA []byte) (int, error) {
	i := len(dAtA)
	_ = i
	var l int
	_ = l
	if len(m.Organization) > 0 {
		i -= len(m.Organization)
		copy(dAtA[i:], m.Organization)
		i = encodeVarintCluster(dAtA, i, uint64(len(m.Organization)))
		i--
		dAtA[i] = 0x12
	}
	if len(m.Name) > 0 {
		i -= len(m.Name)
		copy(dAtA[i:], m.Name)
		i = encodeVarintCluster(dAtA, i, uint64(len(m.Name)))
		i--
		dAtA[i] = 0xa
	}
	return len(dAtA) - i, nil
}

func encodeVarintCluster(dAtA []byte, offset int, v uint64) int {
	offset -= sovCluster(v)
	base := offset
	for v >= 1<<7 {
		dAtA[offset] = uint8(v&0x7f | 0x80)
		v >>= 7
		offset++
	}
	dAtA[offset] = uint8(v)
	return base
}
func (m *ClusterKeyV1) Matches(o *ClusterKeyV1, fopts ...MatchOpt) bool {
	opts := MatchOptions{}
	applyMatchOptions(&opts, fopts...)
	if o == nil {
		if opts.Filter {
			return true
		}
		return false
	}
	if !opts.Filter || o.Name != "" {
		if o.Name != m.Name {
			return false
		}
	}
	return true
}

func (m *ClusterKeyV1) Clone() *ClusterKeyV1 {
	cp := &ClusterKeyV1{}
	cp.DeepCopyIn(m)
	return cp
}

func (m *ClusterKeyV1) CopyInFields(src *ClusterKeyV1) int {
	changed := 0
	if m.Name != src.Name {
		m.Name = src.Name
		changed++
	}
	return changed
}

func (m *ClusterKeyV1) DeepCopyIn(src *ClusterKeyV1) {
	m.Name = src.Name
}

func (m *ClusterKeyV1) GetKeyString() string {
	key, err := json.Marshal(m)
	if err != nil {
		log.FatalLog("Failed to marshal ClusterKeyV1 key string", "obj", m)
	}
	return string(key)
}

func ClusterKeyV1StringParse(str string, key *ClusterKeyV1) {
	err := json.Unmarshal([]byte(str), key)
	if err != nil {
		log.FatalLog("Failed to unmarshal ClusterKeyV1 key string", "str", str)
	}
}

func (m *ClusterKeyV1) NotFoundError() error {
	return fmt.Errorf("ClusterKeyV1 key %s not found", m.GetKeyString())
}

func (m *ClusterKeyV1) ExistsError() error {
	return fmt.Errorf("ClusterKeyV1 key %s already exists", m.GetKeyString())
}

func (m *ClusterKeyV1) BeingDeletedError() error {
	return fmt.Errorf("ClusterKeyV1 %s is being deleted", m.GetKeyString())
}

var ClusterKeyV1TagName = "cluster"

func (m *ClusterKeyV1) GetTags() map[string]string {
	tags := make(map[string]string)
	m.AddTags(tags)
	return tags
}

func (m *ClusterKeyV1) AddTagsByFunc(addTag AddTagFunc) {
	addTag("cluster", m.Name)
}

func (m *ClusterKeyV1) AddTags(tags map[string]string) {
	tagMap := TagMap(tags)
	m.AddTagsByFunc(tagMap.AddTag)
}

// Helper method to check that enums have valid values
func (m *ClusterKeyV1) ValidateEnums() error {
	return nil
}

func (s *ClusterKeyV1) ClearTagged(tags map[string]struct{}) {
}

func (m *ClusterKey) Matches(o *ClusterKey, fopts ...MatchOpt) bool {
	opts := MatchOptions{}
	applyMatchOptions(&opts, fopts...)
	if o == nil {
		if opts.Filter {
			return true
		}
		return false
	}
	if !opts.Filter || o.Name != "" {
		if o.Name != m.Name {
			return false
		}
	}
	if !opts.Filter || o.Organization != "" {
		if o.Organization != m.Organization {
			return false
		}
	}
	return true
}

func (m *ClusterKey) Clone() *ClusterKey {
	cp := &ClusterKey{}
	cp.DeepCopyIn(m)
	return cp
}

func (m *ClusterKey) CopyInFields(src *ClusterKey) int {
	changed := 0
	if m.Name != src.Name {
		m.Name = src.Name
		changed++
	}
	if m.Organization != src.Organization {
		m.Organization = src.Organization
		changed++
	}
	return changed
}

func (m *ClusterKey) DeepCopyIn(src *ClusterKey) {
	m.Name = src.Name
	m.Organization = src.Organization
}

func (m *ClusterKey) GetKeyString() string {
	key, err := json.Marshal(m)
	if err != nil {
		log.FatalLog("Failed to marshal ClusterKey key string", "obj", m)
	}
	return string(key)
}

func ClusterKeyStringParse(str string, key *ClusterKey) {
	err := json.Unmarshal([]byte(str), key)
	if err != nil {
		log.FatalLog("Failed to unmarshal ClusterKey key string", "str", str)
	}
}

func (m *ClusterKey) NotFoundError() error {
	return fmt.Errorf("Cluster key %s not found", m.GetKeyString())
}

func (m *ClusterKey) ExistsError() error {
	return fmt.Errorf("Cluster key %s already exists", m.GetKeyString())
}

func (m *ClusterKey) BeingDeletedError() error {
	return fmt.Errorf("Cluster %s is being deleted", m.GetKeyString())
}

var ClusterKeyTagName = "cluster"
var ClusterKeyTagOrganization = "clusterorg"

func (m *ClusterKey) GetTags() map[string]string {
	tags := make(map[string]string)
	m.AddTags(tags)
	return tags
}

func (m *ClusterKey) AddTagsByFunc(addTag AddTagFunc) {
	addTag("cluster", m.Name)
	addTag("clusterorg", m.Organization)
}

func (m *ClusterKey) AddTags(tags map[string]string) {
	tagMap := TagMap(tags)
	m.AddTagsByFunc(tagMap.AddTag)
}

// Helper method to check that enums have valid values
func (m *ClusterKey) ValidateEnums() error {
	return nil
}

func (s *ClusterKey) ClearTagged(tags map[string]struct{}) {
}

func (m *ClusterKeyV1) Size() (n int) {
	if m == nil {
		return 0
	}
	var l int
	_ = l
	l = len(m.Name)
	if l > 0 {
		n += 1 + l + sovCluster(uint64(l))
	}
	return n
}

func (m *ClusterKey) Size() (n int) {
	if m == nil {
		return 0
	}
	var l int
	_ = l
	l = len(m.Name)
	if l > 0 {
		n += 1 + l + sovCluster(uint64(l))
	}
	l = len(m.Organization)
	if l > 0 {
		n += 1 + l + sovCluster(uint64(l))
	}
	return n
}

func sovCluster(x uint64) (n int) {
	return (math_bits.Len64(x|1) + 6) / 7
}
func sozCluster(x uint64) (n int) {
	return sovCluster(uint64((x << 1) ^ uint64((int64(x) >> 63))))
}
func (m *ClusterKeyV1) Unmarshal(dAtA []byte) error {
	l := len(dAtA)
	iNdEx := 0
	for iNdEx < l {
		preIndex := iNdEx
		var wire uint64
		for shift := uint(0); ; shift += 7 {
			if shift >= 64 {
				return ErrIntOverflowCluster
			}
			if iNdEx >= l {
				return io.ErrUnexpectedEOF
			}
			b := dAtA[iNdEx]
			iNdEx++
			wire |= uint64(b&0x7F) << shift
			if b < 0x80 {
				break
			}
		}
		fieldNum := int32(wire >> 3)
		wireType := int(wire & 0x7)
		if wireType == 4 {
			return fmt.Errorf("proto: ClusterKeyV1: wiretype end group for non-group")
		}
		if fieldNum <= 0 {
			return fmt.Errorf("proto: ClusterKeyV1: illegal tag %d (wire type %d)", fieldNum, wire)
		}
		switch fieldNum {
		case 1:
			if wireType != 2 {
				return fmt.Errorf("proto: wrong wireType = %d for field Name", wireType)
			}
			var stringLen uint64
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowCluster
				}
				if iNdEx >= l {
					return io.ErrUnexpectedEOF
				}
				b := dAtA[iNdEx]
				iNdEx++
				stringLen |= uint64(b&0x7F) << shift
				if b < 0x80 {
					break
				}
			}
			intStringLen := int(stringLen)
			if intStringLen < 0 {
				return ErrInvalidLengthCluster
			}
			postIndex := iNdEx + intStringLen
			if postIndex < 0 {
				return ErrInvalidLengthCluster
			}
			if postIndex > l {
				return io.ErrUnexpectedEOF
			}
			m.Name = string(dAtA[iNdEx:postIndex])
			iNdEx = postIndex
		default:
			iNdEx = preIndex
			skippy, err := skipCluster(dAtA[iNdEx:])
			if err != nil {
				return err
			}
			if (skippy < 0) || (iNdEx+skippy) < 0 {
				return ErrInvalidLengthCluster
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
func (m *ClusterKey) Unmarshal(dAtA []byte) error {
	l := len(dAtA)
	iNdEx := 0
	for iNdEx < l {
		preIndex := iNdEx
		var wire uint64
		for shift := uint(0); ; shift += 7 {
			if shift >= 64 {
				return ErrIntOverflowCluster
			}
			if iNdEx >= l {
				return io.ErrUnexpectedEOF
			}
			b := dAtA[iNdEx]
			iNdEx++
			wire |= uint64(b&0x7F) << shift
			if b < 0x80 {
				break
			}
		}
		fieldNum := int32(wire >> 3)
		wireType := int(wire & 0x7)
		if wireType == 4 {
			return fmt.Errorf("proto: ClusterKey: wiretype end group for non-group")
		}
		if fieldNum <= 0 {
			return fmt.Errorf("proto: ClusterKey: illegal tag %d (wire type %d)", fieldNum, wire)
		}
		switch fieldNum {
		case 1:
			if wireType != 2 {
				return fmt.Errorf("proto: wrong wireType = %d for field Name", wireType)
			}
			var stringLen uint64
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowCluster
				}
				if iNdEx >= l {
					return io.ErrUnexpectedEOF
				}
				b := dAtA[iNdEx]
				iNdEx++
				stringLen |= uint64(b&0x7F) << shift
				if b < 0x80 {
					break
				}
			}
			intStringLen := int(stringLen)
			if intStringLen < 0 {
				return ErrInvalidLengthCluster
			}
			postIndex := iNdEx + intStringLen
			if postIndex < 0 {
				return ErrInvalidLengthCluster
			}
			if postIndex > l {
				return io.ErrUnexpectedEOF
			}
			m.Name = string(dAtA[iNdEx:postIndex])
			iNdEx = postIndex
		case 2:
			if wireType != 2 {
				return fmt.Errorf("proto: wrong wireType = %d for field Organization", wireType)
			}
			var stringLen uint64
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowCluster
				}
				if iNdEx >= l {
					return io.ErrUnexpectedEOF
				}
				b := dAtA[iNdEx]
				iNdEx++
				stringLen |= uint64(b&0x7F) << shift
				if b < 0x80 {
					break
				}
			}
			intStringLen := int(stringLen)
			if intStringLen < 0 {
				return ErrInvalidLengthCluster
			}
			postIndex := iNdEx + intStringLen
			if postIndex < 0 {
				return ErrInvalidLengthCluster
			}
			if postIndex > l {
				return io.ErrUnexpectedEOF
			}
			m.Organization = string(dAtA[iNdEx:postIndex])
			iNdEx = postIndex
		default:
			iNdEx = preIndex
			skippy, err := skipCluster(dAtA[iNdEx:])
			if err != nil {
				return err
			}
			if (skippy < 0) || (iNdEx+skippy) < 0 {
				return ErrInvalidLengthCluster
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
func skipCluster(dAtA []byte) (n int, err error) {
	l := len(dAtA)
	iNdEx := 0
	depth := 0
	for iNdEx < l {
		var wire uint64
		for shift := uint(0); ; shift += 7 {
			if shift >= 64 {
				return 0, ErrIntOverflowCluster
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
					return 0, ErrIntOverflowCluster
				}
				if iNdEx >= l {
					return 0, io.ErrUnexpectedEOF
				}
				iNdEx++
				if dAtA[iNdEx-1] < 0x80 {
					break
				}
			}
		case 1:
			iNdEx += 8
		case 2:
			var length int
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return 0, ErrIntOverflowCluster
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
			if length < 0 {
				return 0, ErrInvalidLengthCluster
			}
			iNdEx += length
		case 3:
			depth++
		case 4:
			if depth == 0 {
				return 0, ErrUnexpectedEndOfGroupCluster
			}
			depth--
		case 5:
			iNdEx += 4
		default:
			return 0, fmt.Errorf("proto: illegal wireType %d", wireType)
		}
		if iNdEx < 0 {
			return 0, ErrInvalidLengthCluster
		}
		if depth == 0 {
			return iNdEx, nil
		}
	}
	return 0, io.ErrUnexpectedEOF
}

var (
	ErrInvalidLengthCluster        = fmt.Errorf("proto: negative length found during unmarshaling")
	ErrIntOverflowCluster          = fmt.Errorf("proto: integer overflow")
	ErrUnexpectedEndOfGroupCluster = fmt.Errorf("proto: unexpected end of group")
)
