// Code generated by protoc-gen-gogo. DO NOT EDIT.
// source: exec.proto

package edgeproto

import proto "github.com/gogo/protobuf/proto"
import fmt "fmt"
import math "math"
import _ "github.com/gogo/googleapis/google/api"
import _ "github.com/mobiledgex/edge-cloud/protogen"
import _ "github.com/mobiledgex/edge-cloud/protoc-gen-cmd/protocmd"
import _ "github.com/gogo/protobuf/gogoproto"

import context "golang.org/x/net/context"
import grpc "google.golang.org/grpc"

import strings "strings"
import "github.com/google/go-cmp/cmp"
import "github.com/google/go-cmp/cmp/cmpopts"

import io "io"

// Reference imports to suppress errors if they are not otherwise used.
var _ = proto.Marshal
var _ = fmt.Errorf
var _ = math.Inf

type ExecRequest struct {
	// Target AppInst
	AppInstKey *AppInstKey `protobuf:"bytes,1,opt,name=app_inst_key,json=appInstKey" json:"app_inst_key,omitempty"`
	// Command or Shell
	Command string `protobuf:"bytes,2,opt,name=command,proto3" json:"command,omitempty"`
	// ContainerID is the name of the target container, if applicable
	ContainerId string `protobuf:"bytes,3,opt,name=container_id,json=containerId,proto3" json:"container_id,omitempty"`
	// WebRTC Offer
	Offer string `protobuf:"bytes,4,opt,name=offer,proto3" json:"offer,omitempty"`
	// WebRTC Answer
	Answer string `protobuf:"bytes,5,opt,name=answer,proto3" json:"answer,omitempty"`
	// Any error message
	Err string `protobuf:"bytes,6,opt,name=err,proto3" json:"err,omitempty"`
}

func (m *ExecRequest) Reset()                    { *m = ExecRequest{} }
func (m *ExecRequest) String() string            { return proto.CompactTextString(m) }
func (*ExecRequest) ProtoMessage()               {}
func (*ExecRequest) Descriptor() ([]byte, []int) { return fileDescriptorExec, []int{0} }

func init() {
	proto.RegisterType((*ExecRequest)(nil), "edgeproto.ExecRequest")
}

// Reference imports to suppress errors if they are not otherwise used.
var _ context.Context
var _ grpc.ClientConn

// This is a compile-time assertion to ensure that this generated file
// is compatible with the grpc package it is being compiled against.
const _ = grpc.SupportPackageIsVersion4

// Client API for ExecApi service

type ExecApiClient interface {
	// Run a Command or Shell on a container or VM
	RunCommand(ctx context.Context, in *ExecRequest, opts ...grpc.CallOption) (*ExecRequest, error)
	// This is used internally to forward requests to other Controllers.
	SendLocalRequest(ctx context.Context, in *ExecRequest, opts ...grpc.CallOption) (*ExecRequest, error)
}

type execApiClient struct {
	cc *grpc.ClientConn
}

func NewExecApiClient(cc *grpc.ClientConn) ExecApiClient {
	return &execApiClient{cc}
}

func (c *execApiClient) RunCommand(ctx context.Context, in *ExecRequest, opts ...grpc.CallOption) (*ExecRequest, error) {
	out := new(ExecRequest)
	err := grpc.Invoke(ctx, "/edgeproto.ExecApi/RunCommand", in, out, c.cc, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *execApiClient) SendLocalRequest(ctx context.Context, in *ExecRequest, opts ...grpc.CallOption) (*ExecRequest, error) {
	out := new(ExecRequest)
	err := grpc.Invoke(ctx, "/edgeproto.ExecApi/SendLocalRequest", in, out, c.cc, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

// Server API for ExecApi service

type ExecApiServer interface {
	// Run a Command or Shell on a container or VM
	RunCommand(context.Context, *ExecRequest) (*ExecRequest, error)
	// This is used internally to forward requests to other Controllers.
	SendLocalRequest(context.Context, *ExecRequest) (*ExecRequest, error)
}

func RegisterExecApiServer(s *grpc.Server, srv ExecApiServer) {
	s.RegisterService(&_ExecApi_serviceDesc, srv)
}

func _ExecApi_RunCommand_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(ExecRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(ExecApiServer).RunCommand(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/edgeproto.ExecApi/RunCommand",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(ExecApiServer).RunCommand(ctx, req.(*ExecRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _ExecApi_SendLocalRequest_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(ExecRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(ExecApiServer).SendLocalRequest(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/edgeproto.ExecApi/SendLocalRequest",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(ExecApiServer).SendLocalRequest(ctx, req.(*ExecRequest))
	}
	return interceptor(ctx, in, info, handler)
}

var _ExecApi_serviceDesc = grpc.ServiceDesc{
	ServiceName: "edgeproto.ExecApi",
	HandlerType: (*ExecApiServer)(nil),
	Methods: []grpc.MethodDesc{
		{
			MethodName: "RunCommand",
			Handler:    _ExecApi_RunCommand_Handler,
		},
		{
			MethodName: "SendLocalRequest",
			Handler:    _ExecApi_SendLocalRequest_Handler,
		},
	},
	Streams:  []grpc.StreamDesc{},
	Metadata: "exec.proto",
}

func (m *ExecRequest) Marshal() (dAtA []byte, err error) {
	size := m.Size()
	dAtA = make([]byte, size)
	n, err := m.MarshalTo(dAtA)
	if err != nil {
		return nil, err
	}
	return dAtA[:n], nil
}

func (m *ExecRequest) MarshalTo(dAtA []byte) (int, error) {
	var i int
	_ = i
	var l int
	_ = l
	if m.AppInstKey != nil {
		dAtA[i] = 0xa
		i++
		i = encodeVarintExec(dAtA, i, uint64(m.AppInstKey.Size()))
		n1, err := m.AppInstKey.MarshalTo(dAtA[i:])
		if err != nil {
			return 0, err
		}
		i += n1
	}
	if len(m.Command) > 0 {
		dAtA[i] = 0x12
		i++
		i = encodeVarintExec(dAtA, i, uint64(len(m.Command)))
		i += copy(dAtA[i:], m.Command)
	}
	if len(m.ContainerId) > 0 {
		dAtA[i] = 0x1a
		i++
		i = encodeVarintExec(dAtA, i, uint64(len(m.ContainerId)))
		i += copy(dAtA[i:], m.ContainerId)
	}
	if len(m.Offer) > 0 {
		dAtA[i] = 0x22
		i++
		i = encodeVarintExec(dAtA, i, uint64(len(m.Offer)))
		i += copy(dAtA[i:], m.Offer)
	}
	if len(m.Answer) > 0 {
		dAtA[i] = 0x2a
		i++
		i = encodeVarintExec(dAtA, i, uint64(len(m.Answer)))
		i += copy(dAtA[i:], m.Answer)
	}
	if len(m.Err) > 0 {
		dAtA[i] = 0x32
		i++
		i = encodeVarintExec(dAtA, i, uint64(len(m.Err)))
		i += copy(dAtA[i:], m.Err)
	}
	return i, nil
}

func encodeVarintExec(dAtA []byte, offset int, v uint64) int {
	for v >= 1<<7 {
		dAtA[offset] = uint8(v&0x7f | 0x80)
		v >>= 7
		offset++
	}
	dAtA[offset] = uint8(v)
	return offset + 1
}
func (m *ExecRequest) CopyInFields(src *ExecRequest) {
	if src.AppInstKey != nil {
		m.AppInstKey = &AppInstKey{}
		m.AppInstKey.AppKey.DeveloperKey.Name = src.AppInstKey.AppKey.DeveloperKey.Name
		m.AppInstKey.AppKey.Name = src.AppInstKey.AppKey.Name
		m.AppInstKey.AppKey.Version = src.AppInstKey.AppKey.Version
		m.AppInstKey.ClusterInstKey.ClusterKey.Name = src.AppInstKey.ClusterInstKey.ClusterKey.Name
		m.AppInstKey.ClusterInstKey.CloudletKey.OperatorKey.Name = src.AppInstKey.ClusterInstKey.CloudletKey.OperatorKey.Name
		m.AppInstKey.ClusterInstKey.CloudletKey.Name = src.AppInstKey.ClusterInstKey.CloudletKey.Name
		m.AppInstKey.ClusterInstKey.Developer = src.AppInstKey.ClusterInstKey.Developer
	}
	m.Command = src.Command
	m.ContainerId = src.ContainerId
	m.Offer = src.Offer
	m.Answer = src.Answer
	m.Err = src.Err
}

// Helper method to check that enums have valid values
func (m *ExecRequest) ValidateEnums() error {
	if err := m.AppInstKey.ValidateEnums(); err != nil {
		return err
	}
	return nil
}

func IgnoreExecRequestFields(taglist string) cmp.Option {
	names := []string{}
	tags := make(map[string]struct{})
	for _, tag := range strings.Split(taglist, ",") {
		tags[tag] = struct{}{}
	}
	if _, found := tags["nocmp"]; found {
		names = append(names, "Offer")
	}
	if _, found := tags["nocmp"]; found {
		names = append(names, "Answer")
	}
	return cmpopts.IgnoreFields(ExecRequest{}, names...)
}

func (m *ExecRequest) Size() (n int) {
	var l int
	_ = l
	if m.AppInstKey != nil {
		l = m.AppInstKey.Size()
		n += 1 + l + sovExec(uint64(l))
	}
	l = len(m.Command)
	if l > 0 {
		n += 1 + l + sovExec(uint64(l))
	}
	l = len(m.ContainerId)
	if l > 0 {
		n += 1 + l + sovExec(uint64(l))
	}
	l = len(m.Offer)
	if l > 0 {
		n += 1 + l + sovExec(uint64(l))
	}
	l = len(m.Answer)
	if l > 0 {
		n += 1 + l + sovExec(uint64(l))
	}
	l = len(m.Err)
	if l > 0 {
		n += 1 + l + sovExec(uint64(l))
	}
	return n
}

func sovExec(x uint64) (n int) {
	for {
		n++
		x >>= 7
		if x == 0 {
			break
		}
	}
	return n
}
func sozExec(x uint64) (n int) {
	return sovExec(uint64((x << 1) ^ uint64((int64(x) >> 63))))
}
func (m *ExecRequest) Unmarshal(dAtA []byte) error {
	l := len(dAtA)
	iNdEx := 0
	for iNdEx < l {
		preIndex := iNdEx
		var wire uint64
		for shift := uint(0); ; shift += 7 {
			if shift >= 64 {
				return ErrIntOverflowExec
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
			return fmt.Errorf("proto: ExecRequest: wiretype end group for non-group")
		}
		if fieldNum <= 0 {
			return fmt.Errorf("proto: ExecRequest: illegal tag %d (wire type %d)", fieldNum, wire)
		}
		switch fieldNum {
		case 1:
			if wireType != 2 {
				return fmt.Errorf("proto: wrong wireType = %d for field AppInstKey", wireType)
			}
			var msglen int
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowExec
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
				return ErrInvalidLengthExec
			}
			postIndex := iNdEx + msglen
			if postIndex > l {
				return io.ErrUnexpectedEOF
			}
			if m.AppInstKey == nil {
				m.AppInstKey = &AppInstKey{}
			}
			if err := m.AppInstKey.Unmarshal(dAtA[iNdEx:postIndex]); err != nil {
				return err
			}
			iNdEx = postIndex
		case 2:
			if wireType != 2 {
				return fmt.Errorf("proto: wrong wireType = %d for field Command", wireType)
			}
			var stringLen uint64
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowExec
				}
				if iNdEx >= l {
					return io.ErrUnexpectedEOF
				}
				b := dAtA[iNdEx]
				iNdEx++
				stringLen |= (uint64(b) & 0x7F) << shift
				if b < 0x80 {
					break
				}
			}
			intStringLen := int(stringLen)
			if intStringLen < 0 {
				return ErrInvalidLengthExec
			}
			postIndex := iNdEx + intStringLen
			if postIndex > l {
				return io.ErrUnexpectedEOF
			}
			m.Command = string(dAtA[iNdEx:postIndex])
			iNdEx = postIndex
		case 3:
			if wireType != 2 {
				return fmt.Errorf("proto: wrong wireType = %d for field ContainerId", wireType)
			}
			var stringLen uint64
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowExec
				}
				if iNdEx >= l {
					return io.ErrUnexpectedEOF
				}
				b := dAtA[iNdEx]
				iNdEx++
				stringLen |= (uint64(b) & 0x7F) << shift
				if b < 0x80 {
					break
				}
			}
			intStringLen := int(stringLen)
			if intStringLen < 0 {
				return ErrInvalidLengthExec
			}
			postIndex := iNdEx + intStringLen
			if postIndex > l {
				return io.ErrUnexpectedEOF
			}
			m.ContainerId = string(dAtA[iNdEx:postIndex])
			iNdEx = postIndex
		case 4:
			if wireType != 2 {
				return fmt.Errorf("proto: wrong wireType = %d for field Offer", wireType)
			}
			var stringLen uint64
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowExec
				}
				if iNdEx >= l {
					return io.ErrUnexpectedEOF
				}
				b := dAtA[iNdEx]
				iNdEx++
				stringLen |= (uint64(b) & 0x7F) << shift
				if b < 0x80 {
					break
				}
			}
			intStringLen := int(stringLen)
			if intStringLen < 0 {
				return ErrInvalidLengthExec
			}
			postIndex := iNdEx + intStringLen
			if postIndex > l {
				return io.ErrUnexpectedEOF
			}
			m.Offer = string(dAtA[iNdEx:postIndex])
			iNdEx = postIndex
		case 5:
			if wireType != 2 {
				return fmt.Errorf("proto: wrong wireType = %d for field Answer", wireType)
			}
			var stringLen uint64
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowExec
				}
				if iNdEx >= l {
					return io.ErrUnexpectedEOF
				}
				b := dAtA[iNdEx]
				iNdEx++
				stringLen |= (uint64(b) & 0x7F) << shift
				if b < 0x80 {
					break
				}
			}
			intStringLen := int(stringLen)
			if intStringLen < 0 {
				return ErrInvalidLengthExec
			}
			postIndex := iNdEx + intStringLen
			if postIndex > l {
				return io.ErrUnexpectedEOF
			}
			m.Answer = string(dAtA[iNdEx:postIndex])
			iNdEx = postIndex
		case 6:
			if wireType != 2 {
				return fmt.Errorf("proto: wrong wireType = %d for field Err", wireType)
			}
			var stringLen uint64
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowExec
				}
				if iNdEx >= l {
					return io.ErrUnexpectedEOF
				}
				b := dAtA[iNdEx]
				iNdEx++
				stringLen |= (uint64(b) & 0x7F) << shift
				if b < 0x80 {
					break
				}
			}
			intStringLen := int(stringLen)
			if intStringLen < 0 {
				return ErrInvalidLengthExec
			}
			postIndex := iNdEx + intStringLen
			if postIndex > l {
				return io.ErrUnexpectedEOF
			}
			m.Err = string(dAtA[iNdEx:postIndex])
			iNdEx = postIndex
		default:
			iNdEx = preIndex
			skippy, err := skipExec(dAtA[iNdEx:])
			if err != nil {
				return err
			}
			if skippy < 0 {
				return ErrInvalidLengthExec
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
func skipExec(dAtA []byte) (n int, err error) {
	l := len(dAtA)
	iNdEx := 0
	for iNdEx < l {
		var wire uint64
		for shift := uint(0); ; shift += 7 {
			if shift >= 64 {
				return 0, ErrIntOverflowExec
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
					return 0, ErrIntOverflowExec
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
					return 0, ErrIntOverflowExec
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
				return 0, ErrInvalidLengthExec
			}
			return iNdEx, nil
		case 3:
			for {
				var innerWire uint64
				var start int = iNdEx
				for shift := uint(0); ; shift += 7 {
					if shift >= 64 {
						return 0, ErrIntOverflowExec
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
				next, err := skipExec(dAtA[start:])
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
	ErrInvalidLengthExec = fmt.Errorf("proto: negative length found during unmarshaling")
	ErrIntOverflowExec   = fmt.Errorf("proto: integer overflow")
)

func init() { proto.RegisterFile("exec.proto", fileDescriptorExec) }

var fileDescriptorExec = []byte{
	// 445 bytes of a gzipped FileDescriptorProto
	0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0xff, 0x94, 0x52, 0x4d, 0x6f, 0xd3, 0x40,
	0x10, 0xed, 0xb6, 0x24, 0x55, 0x37, 0x05, 0x45, 0x2b, 0x40, 0xdb, 0x08, 0x45, 0xa1, 0x08, 0xa9,
	0x87, 0x24, 0x96, 0xca, 0x01, 0xc4, 0xcd, 0xa5, 0x11, 0xaa, 0xf8, 0x92, 0xcc, 0x0f, 0x88, 0x36,
	0xeb, 0xe9, 0x62, 0x61, 0xef, 0x2c, 0xeb, 0x35, 0xa4, 0xe7, 0xde, 0x38, 0xf2, 0x2b, 0x38, 0xe7,
	0x17, 0x70, 0xcc, 0x91, 0x0b, 0x12, 0x47, 0xc8, 0x91, 0xb3, 0x7f, 0x00, 0x5a, 0xc7, 0x09, 0x39,
	0x80, 0x44, 0x2f, 0xf6, 0x7b, 0xf3, 0xde, 0xac, 0x67, 0x9e, 0x97, 0x52, 0x98, 0x82, 0x1c, 0x1a,
	0x8b, 0x0e, 0xd9, 0x1e, 0xc4, 0x0a, 0x2a, 0xd8, 0xb9, 0xa3, 0x10, 0x55, 0x0a, 0x81, 0x30, 0x49,
	0x20, 0xb4, 0x46, 0x27, 0x5c, 0x82, 0x3a, 0x5f, 0x1a, 0x3b, 0x8f, 0x54, 0xe2, 0xde, 0x14, 0x93,
	0xa1, 0xc4, 0x2c, 0xc8, 0x70, 0x92, 0xa4, 0xbe, 0x71, 0x1a, 0xf8, 0xe7, 0x40, 0xa6, 0x58, 0xc4,
	0x41, 0xe5, 0x53, 0xa0, 0xd7, 0xa0, 0xee, 0x7c, 0xfa, 0x7f, 0x9d, 0x72, 0xa0, 0x40, 0x0f, 0x64,
	0xb6, 0xa2, 0x1b, 0xa0, 0x3e, 0xe8, 0xa6, 0x42, 0x85, 0x15, 0x0c, 0x3c, 0xaa, 0xab, 0x37, 0x84,
	0x31, 0xe3, 0x44, 0xe7, 0x6e, 0xc9, 0x0f, 0x2f, 0xb7, 0x69, 0x6b, 0x34, 0x05, 0x19, 0xc1, 0xbb,
	0x02, 0x72, 0xc7, 0x1e, 0xd2, 0xfd, 0x95, 0x63, 0xfc, 0x16, 0x2e, 0x38, 0xe9, 0x91, 0xa3, 0xd6,
	0xf1, 0xad, 0xe1, 0x7a, 0xf1, 0x61, 0x68, 0xcc, 0x99, 0xce, 0xdd, 0x33, 0xb8, 0x88, 0xa8, 0x58,
	0x63, 0xc6, 0xe9, 0xae, 0xc4, 0x2c, 0x13, 0x3a, 0xe6, 0xdb, 0x3d, 0x72, 0xb4, 0x17, 0xad, 0x28,
	0xbb, 0x4b, 0xf7, 0x25, 0x6a, 0x27, 0x12, 0x0d, 0x76, 0x9c, 0xc4, 0x7c, 0xa7, 0x92, 0x5b, 0xeb,
	0xda, 0x59, 0xcc, 0xee, 0xd1, 0x06, 0x9e, 0x9f, 0x83, 0xe5, 0xd7, 0xbc, 0x76, 0x72, 0xfd, 0x73,
	0xc9, 0xc9, 0xa7, 0xd9, 0x41, 0x43, 0xa3, 0xcc, 0x4c, 0xb4, 0xd4, 0xd8, 0x7d, 0xda, 0x14, 0x3a,
	0xff, 0x00, 0x96, 0x37, 0xfe, 0xe6, 0xaa, 0x45, 0xd6, 0xa6, 0x3b, 0x60, 0x2d, 0x6f, 0x56, 0x5f,
	0xf1, 0xf0, 0x71, 0xef, 0x4b, 0xc9, 0xc9, 0xbc, 0xe4, 0xe4, 0x7b, 0xc9, 0xc9, 0xc7, 0xd9, 0x41,
	0xfb, 0x95, 0x3f, 0xaf, 0x1f, 0x56, 0xfe, 0xfe, 0xc8, 0xda, 0xe3, 0x6f, 0x84, 0xee, 0xfa, 0x14,
	0x42, 0x93, 0xb0, 0x4b, 0x42, 0x69, 0x54, 0xe8, 0x27, 0xf5, 0xf4, 0xb7, 0x37, 0x56, 0xdf, 0x08,
	0xaa, 0xf3, 0x8f, 0xfa, 0xe1, 0xe8, 0x57, 0xc9, 0xc3, 0x08, 0x72, 0x2c, 0xac, 0x84, 0x3a, 0xab,
	0xbc, 0x1f, 0x4a, 0x7f, 0x3b, 0x5e, 0x08, 0x2d, 0x14, 0xf4, 0xff, 0x24, 0xe8, 0xc3, 0xf4, 0xaf,
	0x53, 0x78, 0x0f, 0x29, 0x1a, 0xb0, 0x9e, 0xbc, 0x14, 0x19, 0xb0, 0x53, 0xda, 0x7e, 0x0d, 0x3a,
	0x7e, 0x8e, 0x52, 0xa4, 0xab, 0x7f, 0x73, 0xd5, 0x51, 0xb6, 0x4e, 0xda, 0xf3, 0x9f, 0xdd, 0xad,
	0xf9, 0xa2, 0x4b, 0xbe, 0x2e, 0xba, 0xe4, 0xc7, 0xa2, 0x4b, 0x26, 0xcd, 0xca, 0xf6, 0xe0, 0x77,
	0x00, 0x00, 0x00, 0xff, 0xff, 0x9c, 0x84, 0xd1, 0xfb, 0xd6, 0x02, 0x00, 0x00,
}
