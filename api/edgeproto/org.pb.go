// Code generated by protoc-gen-gogo. DO NOT EDIT.
// source: org.proto

package edgeproto

import (
	context "context"
	fmt "fmt"
	_ "github.com/edgexr/edge-cloud-platform/protogen"
	_ "github.com/gogo/googleapis/google/api"
	_ "github.com/gogo/protobuf/gogoproto"
	proto "github.com/gogo/protobuf/proto"
	grpc "google.golang.org/grpc"
	codes "google.golang.org/grpc/codes"
	status "google.golang.org/grpc/status"
	io "io"
	math "math"
	math_bits "math/bits"
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

type Organization struct {
	// Organization name
	Name string `protobuf:"bytes,1,opt,name=name,proto3" json:"name,omitempty"`
}

func (m *Organization) Reset()         { *m = Organization{} }
func (m *Organization) String() string { return proto.CompactTextString(m) }
func (*Organization) ProtoMessage()    {}
func (*Organization) Descriptor() ([]byte, []int) {
	return fileDescriptor_ccb462779e28924f, []int{0}
}
func (m *Organization) XXX_Unmarshal(b []byte) error {
	return m.Unmarshal(b)
}
func (m *Organization) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	if deterministic {
		return xxx_messageInfo_Organization.Marshal(b, m, deterministic)
	} else {
		b = b[:cap(b)]
		n, err := m.MarshalToSizedBuffer(b)
		if err != nil {
			return nil, err
		}
		return b[:n], nil
	}
}
func (m *Organization) XXX_Merge(src proto.Message) {
	xxx_messageInfo_Organization.Merge(m, src)
}
func (m *Organization) XXX_Size() int {
	return m.Size()
}
func (m *Organization) XXX_DiscardUnknown() {
	xxx_messageInfo_Organization.DiscardUnknown(m)
}

var xxx_messageInfo_Organization proto.InternalMessageInfo

type OrganizationData struct {
	Orgs []Organization `protobuf:"bytes,1,rep,name=orgs,proto3" json:"orgs"`
}

func (m *OrganizationData) Reset()         { *m = OrganizationData{} }
func (m *OrganizationData) String() string { return proto.CompactTextString(m) }
func (*OrganizationData) ProtoMessage()    {}
func (*OrganizationData) Descriptor() ([]byte, []int) {
	return fileDescriptor_ccb462779e28924f, []int{1}
}
func (m *OrganizationData) XXX_Unmarshal(b []byte) error {
	return m.Unmarshal(b)
}
func (m *OrganizationData) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	if deterministic {
		return xxx_messageInfo_OrganizationData.Marshal(b, m, deterministic)
	} else {
		b = b[:cap(b)]
		n, err := m.MarshalToSizedBuffer(b)
		if err != nil {
			return nil, err
		}
		return b[:n], nil
	}
}
func (m *OrganizationData) XXX_Merge(src proto.Message) {
	xxx_messageInfo_OrganizationData.Merge(m, src)
}
func (m *OrganizationData) XXX_Size() int {
	return m.Size()
}
func (m *OrganizationData) XXX_DiscardUnknown() {
	xxx_messageInfo_OrganizationData.DiscardUnknown(m)
}

var xxx_messageInfo_OrganizationData proto.InternalMessageInfo

func init() {
	proto.RegisterType((*Organization)(nil), "edgeproto.Organization")
	proto.RegisterType((*OrganizationData)(nil), "edgeproto.OrganizationData")
}

func init() { proto.RegisterFile("org.proto", fileDescriptor_ccb462779e28924f) }

var fileDescriptor_ccb462779e28924f = []byte{
	// 309 bytes of a gzipped FileDescriptorProto
	0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0xff, 0x74, 0x90, 0xb1, 0x4a, 0x03, 0x31,
	0x1c, 0xc6, 0x2f, 0x7a, 0x88, 0x8d, 0x05, 0xed, 0x29, 0x78, 0x1c, 0x25, 0x96, 0x9b, 0x8a, 0xd0,
	0x0b, 0xd6, 0xad, 0xe0, 0x60, 0x71, 0x71, 0x2a, 0x14, 0x9c, 0x25, 0x6d, 0x63, 0x0c, 0x5c, 0xf3,
	0x3f, 0x72, 0x39, 0x28, 0x8e, 0x3e, 0x41, 0xc1, 0xc5, 0xd1, 0xc7, 0xe9, 0x58, 0x70, 0x71, 0x12,
	0xed, 0xf9, 0x0a, 0x76, 0x96, 0xa6, 0xa5, 0x64, 0x71, 0xca, 0x8f, 0xef, 0xfb, 0xe5, 0x83, 0x04,
	0x57, 0x40, 0x8b, 0x24, 0xd3, 0x60, 0x20, 0xa8, 0xf0, 0x91, 0xe0, 0x16, 0xa3, 0xaa, 0xe6, 0x79,
	0x91, 0x9a, 0x75, 0x11, 0x5d, 0x09, 0x69, 0x1e, 0x8b, 0x41, 0x32, 0x84, 0x31, 0x5d, 0x39, 0x13,
	0x6d, 0x8f, 0xd6, 0x30, 0x85, 0x62, 0xd4, 0xca, 0x52, 0x66, 0x1e, 0x40, 0x8f, 0xa9, 0x95, 0x05,
	0x57, 0x5b, 0xd8, 0x5c, 0xaf, 0x0b, 0x00, 0x91, 0x72, 0xca, 0x32, 0x49, 0x99, 0x52, 0x60, 0x98,
	0x91, 0xa0, 0xf2, 0x4d, 0x7b, 0x22, 0x40, 0x80, 0x45, 0xba, 0xa2, 0x75, 0x1a, 0xc7, 0xb8, 0xda,
	0xd3, 0x82, 0x29, 0xf9, 0x64, 0xe5, 0x20, 0xc0, 0xbe, 0x62, 0x63, 0x1e, 0xa2, 0x06, 0x6a, 0x56,
	0xfa, 0x96, 0xe3, 0x1e, 0x3e, 0x72, 0x9d, 0x1b, 0x66, 0x58, 0x70, 0x81, 0x7d, 0xd0, 0x22, 0x0f,
	0x51, 0x63, 0xb7, 0x79, 0xd0, 0x3e, 0x4d, 0xb6, 0x4f, 0x4a, 0x5c, 0xb5, 0xeb, 0xcf, 0x3e, 0xcf,
	0xbc, 0xbe, 0x55, 0x3b, 0xfb, 0xaf, 0xcb, 0x10, 0xbd, 0x2d, 0x43, 0xaf, 0x3d, 0xc1, 0x87, 0xae,
	0x75, 0x9d, 0xc9, 0xe0, 0x1e, 0xd7, 0xdc, 0xe8, 0x56, 0xdd, 0xe5, 0x3c, 0xf8, 0x6f, 0x36, 0xaa,
	0x39, 0x45, 0xdf, 0xfe, 0x60, 0x4c, 0x9e, 0xdf, 0x7f, 0x5e, 0x76, 0xc2, 0xf8, 0x98, 0x4a, 0x55,
	0xe4, 0x9c, 0x82, 0xe3, 0x77, 0xd0, 0x79, 0xe4, 0x4f, 0x7f, 0x43, 0xd4, 0xad, 0xcf, 0xbe, 0x89,
	0x37, 0x5b, 0x10, 0x34, 0x5f, 0x10, 0xf4, 0xb5, 0x20, 0x68, 0x5a, 0x12, 0x6f, 0x5e, 0x12, 0xef,
	0xa3, 0x24, 0xde, 0x60, 0xcf, 0x2e, 0x5e, 0xfe, 0x05, 0x00, 0x00, 0xff, 0xff, 0xdb, 0x0e, 0x46,
	0x70, 0xac, 0x01, 0x00, 0x00,
}

// Reference imports to suppress errors if they are not otherwise used.
var _ context.Context
var _ grpc.ClientConn

// This is a compile-time assertion to ensure that this generated file
// is compatible with the grpc package it is being compiled against.
const _ = grpc.SupportPackageIsVersion4

// OrganizationApiClient is the client API for OrganizationApi service.
//
// For semantics around ctx use and closing/ending streaming RPCs, please refer to https://godoc.org/google.golang.org/grpc#ClientConn.NewStream.
type OrganizationApiClient interface {
	// Check if an Organization is in use.
	OrganizationInUse(ctx context.Context, in *Organization, opts ...grpc.CallOption) (*Result, error)
}

type organizationApiClient struct {
	cc *grpc.ClientConn
}

func NewOrganizationApiClient(cc *grpc.ClientConn) OrganizationApiClient {
	return &organizationApiClient{cc}
}

func (c *organizationApiClient) OrganizationInUse(ctx context.Context, in *Organization, opts ...grpc.CallOption) (*Result, error) {
	out := new(Result)
	err := c.cc.Invoke(ctx, "/edgeproto.OrganizationApi/OrganizationInUse", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

// OrganizationApiServer is the server API for OrganizationApi service.
type OrganizationApiServer interface {
	// Check if an Organization is in use.
	OrganizationInUse(context.Context, *Organization) (*Result, error)
}

// UnimplementedOrganizationApiServer can be embedded to have forward compatible implementations.
type UnimplementedOrganizationApiServer struct {
}

func (*UnimplementedOrganizationApiServer) OrganizationInUse(ctx context.Context, req *Organization) (*Result, error) {
	return nil, status.Errorf(codes.Unimplemented, "method OrganizationInUse not implemented")
}

func RegisterOrganizationApiServer(s *grpc.Server, srv OrganizationApiServer) {
	s.RegisterService(&_OrganizationApi_serviceDesc, srv)
}

func _OrganizationApi_OrganizationInUse_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(Organization)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(OrganizationApiServer).OrganizationInUse(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/edgeproto.OrganizationApi/OrganizationInUse",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(OrganizationApiServer).OrganizationInUse(ctx, req.(*Organization))
	}
	return interceptor(ctx, in, info, handler)
}

var _OrganizationApi_serviceDesc = grpc.ServiceDesc{
	ServiceName: "edgeproto.OrganizationApi",
	HandlerType: (*OrganizationApiServer)(nil),
	Methods: []grpc.MethodDesc{
		{
			MethodName: "OrganizationInUse",
			Handler:    _OrganizationApi_OrganizationInUse_Handler,
		},
	},
	Streams:  []grpc.StreamDesc{},
	Metadata: "org.proto",
}

func (m *Organization) Marshal() (dAtA []byte, err error) {
	size := m.Size()
	dAtA = make([]byte, size)
	n, err := m.MarshalToSizedBuffer(dAtA[:size])
	if err != nil {
		return nil, err
	}
	return dAtA[:n], nil
}

func (m *Organization) MarshalTo(dAtA []byte) (int, error) {
	size := m.Size()
	return m.MarshalToSizedBuffer(dAtA[:size])
}

func (m *Organization) MarshalToSizedBuffer(dAtA []byte) (int, error) {
	i := len(dAtA)
	_ = i
	var l int
	_ = l
	if len(m.Name) > 0 {
		i -= len(m.Name)
		copy(dAtA[i:], m.Name)
		i = encodeVarintOrg(dAtA, i, uint64(len(m.Name)))
		i--
		dAtA[i] = 0xa
	}
	return len(dAtA) - i, nil
}

func (m *OrganizationData) Marshal() (dAtA []byte, err error) {
	size := m.Size()
	dAtA = make([]byte, size)
	n, err := m.MarshalToSizedBuffer(dAtA[:size])
	if err != nil {
		return nil, err
	}
	return dAtA[:n], nil
}

func (m *OrganizationData) MarshalTo(dAtA []byte) (int, error) {
	size := m.Size()
	return m.MarshalToSizedBuffer(dAtA[:size])
}

func (m *OrganizationData) MarshalToSizedBuffer(dAtA []byte) (int, error) {
	i := len(dAtA)
	_ = i
	var l int
	_ = l
	if len(m.Orgs) > 0 {
		for iNdEx := len(m.Orgs) - 1; iNdEx >= 0; iNdEx-- {
			{
				size, err := m.Orgs[iNdEx].MarshalToSizedBuffer(dAtA[:i])
				if err != nil {
					return 0, err
				}
				i -= size
				i = encodeVarintOrg(dAtA, i, uint64(size))
			}
			i--
			dAtA[i] = 0xa
		}
	}
	return len(dAtA) - i, nil
}

func encodeVarintOrg(dAtA []byte, offset int, v uint64) int {
	offset -= sovOrg(v)
	base := offset
	for v >= 1<<7 {
		dAtA[offset] = uint8(v&0x7f | 0x80)
		v >>= 7
		offset++
	}
	dAtA[offset] = uint8(v)
	return base
}
func (m *Organization) CopyInFields(src *Organization) int {
	changed := 0
	if m.Name != src.Name {
		m.Name = src.Name
		changed++
	}
	return changed
}

func (m *Organization) DeepCopyIn(src *Organization) {
	m.Name = src.Name
}

// Helper method to check that enums have valid values
func (m *Organization) ValidateEnums() error {
	return nil
}

func (s *Organization) ClearTagged(tags map[string]struct{}) {
}

func (m *OrganizationData) DeepCopyIn(src *OrganizationData) {
	if src.Orgs != nil {
		m.Orgs = make([]Organization, len(src.Orgs), len(src.Orgs))
		for ii, s := range src.Orgs {
			m.Orgs[ii].DeepCopyIn(&s)
		}
	} else {
		m.Orgs = nil
	}
}

// Helper method to check that enums have valid values
func (m *OrganizationData) ValidateEnums() error {
	for _, e := range m.Orgs {
		if err := e.ValidateEnums(); err != nil {
			return err
		}
	}
	return nil
}

func (s *OrganizationData) ClearTagged(tags map[string]struct{}) {
	if s.Orgs != nil {
		for ii := 0; ii < len(s.Orgs); ii++ {
			s.Orgs[ii].ClearTagged(tags)
		}
	}
}

func (m *Organization) IsValidArgsForOrganizationInUse() error {
	return nil
}

func (m *Organization) Size() (n int) {
	if m == nil {
		return 0
	}
	var l int
	_ = l
	l = len(m.Name)
	if l > 0 {
		n += 1 + l + sovOrg(uint64(l))
	}
	return n
}

func (m *OrganizationData) Size() (n int) {
	if m == nil {
		return 0
	}
	var l int
	_ = l
	if len(m.Orgs) > 0 {
		for _, e := range m.Orgs {
			l = e.Size()
			n += 1 + l + sovOrg(uint64(l))
		}
	}
	return n
}

func sovOrg(x uint64) (n int) {
	return (math_bits.Len64(x|1) + 6) / 7
}
func sozOrg(x uint64) (n int) {
	return sovOrg(uint64((x << 1) ^ uint64((int64(x) >> 63))))
}
func (m *Organization) Unmarshal(dAtA []byte) error {
	l := len(dAtA)
	iNdEx := 0
	for iNdEx < l {
		preIndex := iNdEx
		var wire uint64
		for shift := uint(0); ; shift += 7 {
			if shift >= 64 {
				return ErrIntOverflowOrg
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
			return fmt.Errorf("proto: Organization: wiretype end group for non-group")
		}
		if fieldNum <= 0 {
			return fmt.Errorf("proto: Organization: illegal tag %d (wire type %d)", fieldNum, wire)
		}
		switch fieldNum {
		case 1:
			if wireType != 2 {
				return fmt.Errorf("proto: wrong wireType = %d for field Name", wireType)
			}
			var stringLen uint64
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowOrg
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
				return ErrInvalidLengthOrg
			}
			postIndex := iNdEx + intStringLen
			if postIndex < 0 {
				return ErrInvalidLengthOrg
			}
			if postIndex > l {
				return io.ErrUnexpectedEOF
			}
			m.Name = string(dAtA[iNdEx:postIndex])
			iNdEx = postIndex
		default:
			iNdEx = preIndex
			skippy, err := skipOrg(dAtA[iNdEx:])
			if err != nil {
				return err
			}
			if skippy < 0 {
				return ErrInvalidLengthOrg
			}
			if (iNdEx + skippy) < 0 {
				return ErrInvalidLengthOrg
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
func (m *OrganizationData) Unmarshal(dAtA []byte) error {
	l := len(dAtA)
	iNdEx := 0
	for iNdEx < l {
		preIndex := iNdEx
		var wire uint64
		for shift := uint(0); ; shift += 7 {
			if shift >= 64 {
				return ErrIntOverflowOrg
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
			return fmt.Errorf("proto: OrganizationData: wiretype end group for non-group")
		}
		if fieldNum <= 0 {
			return fmt.Errorf("proto: OrganizationData: illegal tag %d (wire type %d)", fieldNum, wire)
		}
		switch fieldNum {
		case 1:
			if wireType != 2 {
				return fmt.Errorf("proto: wrong wireType = %d for field Orgs", wireType)
			}
			var msglen int
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowOrg
				}
				if iNdEx >= l {
					return io.ErrUnexpectedEOF
				}
				b := dAtA[iNdEx]
				iNdEx++
				msglen |= int(b&0x7F) << shift
				if b < 0x80 {
					break
				}
			}
			if msglen < 0 {
				return ErrInvalidLengthOrg
			}
			postIndex := iNdEx + msglen
			if postIndex < 0 {
				return ErrInvalidLengthOrg
			}
			if postIndex > l {
				return io.ErrUnexpectedEOF
			}
			m.Orgs = append(m.Orgs, Organization{})
			if err := m.Orgs[len(m.Orgs)-1].Unmarshal(dAtA[iNdEx:postIndex]); err != nil {
				return err
			}
			iNdEx = postIndex
		default:
			iNdEx = preIndex
			skippy, err := skipOrg(dAtA[iNdEx:])
			if err != nil {
				return err
			}
			if skippy < 0 {
				return ErrInvalidLengthOrg
			}
			if (iNdEx + skippy) < 0 {
				return ErrInvalidLengthOrg
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
func skipOrg(dAtA []byte) (n int, err error) {
	l := len(dAtA)
	iNdEx := 0
	depth := 0
	for iNdEx < l {
		var wire uint64
		for shift := uint(0); ; shift += 7 {
			if shift >= 64 {
				return 0, ErrIntOverflowOrg
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
					return 0, ErrIntOverflowOrg
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
					return 0, ErrIntOverflowOrg
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
				return 0, ErrInvalidLengthOrg
			}
			iNdEx += length
		case 3:
			depth++
		case 4:
			if depth == 0 {
				return 0, ErrUnexpectedEndOfGroupOrg
			}
			depth--
		case 5:
			iNdEx += 4
		default:
			return 0, fmt.Errorf("proto: illegal wireType %d", wireType)
		}
		if iNdEx < 0 {
			return 0, ErrInvalidLengthOrg
		}
		if depth == 0 {
			return iNdEx, nil
		}
	}
	return 0, io.ErrUnexpectedEOF
}

var (
	ErrInvalidLengthOrg        = fmt.Errorf("proto: negative length found during unmarshaling")
	ErrIntOverflowOrg          = fmt.Errorf("proto: integer overflow")
	ErrUnexpectedEndOfGroupOrg = fmt.Errorf("proto: unexpected end of group")
)