// Code generated by protoc-gen-gogo. DO NOT EDIT.
// source: debug.proto

/*
	Package log is a generated protocol buffer package.

	It is generated from these files:
		debug.proto

	It has these top-level messages:
		DebugLevels
		DebugResult
*/
package log

import proto "github.com/gogo/protobuf/proto"
import fmt "fmt"
import math "math"

import context "golang.org/x/net/context"
import grpc "google.golang.org/grpc"

import "errors"
import "strconv"

import io "io"

// Reference imports to suppress errors if they are not otherwise used.
var _ = proto.Marshal
var _ = fmt.Errorf
var _ = math.Inf

// This is a compile-time assertion to ensure that this generated file
// is compatible with the proto package it is being compiled against.
// A compilation error at this line likely means your copy of the
// proto package needs to be updated.
const _ = proto.GoGoProtoPackageIsVersion2 // please upgrade the proto package

type DebugLevel int32

const (
	DebugLevel_etcd   DebugLevel = 0
	DebugLevel_api    DebugLevel = 1
	DebugLevel_notify DebugLevel = 2
	DebugLevel_dmedb  DebugLevel = 3
	DebugLevel_dmereq DebugLevel = 4
	DebugLevel_locapi DebugLevel = 5
)

var DebugLevel_name = map[int32]string{
	0: "etcd",
	1: "api",
	2: "notify",
	3: "dmedb",
	4: "dmereq",
	5: "locapi",
}
var DebugLevel_value = map[string]int32{
	"etcd":   0,
	"api":    1,
	"notify": 2,
	"dmedb":  3,
	"dmereq": 4,
	"locapi": 5,
}

func (x DebugLevel) String() string {
	return proto.EnumName(DebugLevel_name, int32(x))
}
func (DebugLevel) EnumDescriptor() ([]byte, []int) { return fileDescriptorDebug, []int{0} }

type DebugLevels struct {
	// comma separated list of debug level names
	Levels []DebugLevel `protobuf:"varint,1,rep,packed,name=levels,enum=log.DebugLevel" json:"levels,omitempty"`
}

func (m *DebugLevels) Reset()                    { *m = DebugLevels{} }
func (m *DebugLevels) String() string            { return proto.CompactTextString(m) }
func (*DebugLevels) ProtoMessage()               {}
func (*DebugLevels) Descriptor() ([]byte, []int) { return fileDescriptorDebug, []int{0} }

type DebugResult struct {
	Status string `protobuf:"bytes,1,opt,name=status,proto3" json:"status,omitempty"`
	Code   uint32 `protobuf:"varint,2,opt,name=code,proto3" json:"code,omitempty"`
}

func (m *DebugResult) Reset()                    { *m = DebugResult{} }
func (m *DebugResult) String() string            { return proto.CompactTextString(m) }
func (*DebugResult) ProtoMessage()               {}
func (*DebugResult) Descriptor() ([]byte, []int) { return fileDescriptorDebug, []int{1} }

func init() {
	proto.RegisterType((*DebugLevels)(nil), "log.DebugLevels")
	proto.RegisterType((*DebugResult)(nil), "log.DebugResult")
	proto.RegisterEnum("log.DebugLevel", DebugLevel_name, DebugLevel_value)
}

// Reference imports to suppress errors if they are not otherwise used.
var _ context.Context
var _ grpc.ClientConn

// This is a compile-time assertion to ensure that this generated file
// is compatible with the grpc package it is being compiled against.
const _ = grpc.SupportPackageIsVersion4

// Client API for DebugApi service

type DebugApiClient interface {
	EnableDebugLevels(ctx context.Context, in *DebugLevels, opts ...grpc.CallOption) (*DebugResult, error)
	DisableDebugLevels(ctx context.Context, in *DebugLevels, opts ...grpc.CallOption) (*DebugResult, error)
	ShowDebugLevels(ctx context.Context, in *DebugLevels, opts ...grpc.CallOption) (*DebugLevels, error)
}

type debugApiClient struct {
	cc *grpc.ClientConn
}

func NewDebugApiClient(cc *grpc.ClientConn) DebugApiClient {
	return &debugApiClient{cc}
}

func (c *debugApiClient) EnableDebugLevels(ctx context.Context, in *DebugLevels, opts ...grpc.CallOption) (*DebugResult, error) {
	out := new(DebugResult)
	err := grpc.Invoke(ctx, "/log.DebugApi/EnableDebugLevels", in, out, c.cc, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *debugApiClient) DisableDebugLevels(ctx context.Context, in *DebugLevels, opts ...grpc.CallOption) (*DebugResult, error) {
	out := new(DebugResult)
	err := grpc.Invoke(ctx, "/log.DebugApi/DisableDebugLevels", in, out, c.cc, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *debugApiClient) ShowDebugLevels(ctx context.Context, in *DebugLevels, opts ...grpc.CallOption) (*DebugLevels, error) {
	out := new(DebugLevels)
	err := grpc.Invoke(ctx, "/log.DebugApi/ShowDebugLevels", in, out, c.cc, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

// Server API for DebugApi service

type DebugApiServer interface {
	EnableDebugLevels(context.Context, *DebugLevels) (*DebugResult, error)
	DisableDebugLevels(context.Context, *DebugLevels) (*DebugResult, error)
	ShowDebugLevels(context.Context, *DebugLevels) (*DebugLevels, error)
}

func RegisterDebugApiServer(s *grpc.Server, srv DebugApiServer) {
	s.RegisterService(&_DebugApi_serviceDesc, srv)
}

func _DebugApi_EnableDebugLevels_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(DebugLevels)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(DebugApiServer).EnableDebugLevels(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/log.DebugApi/EnableDebugLevels",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(DebugApiServer).EnableDebugLevels(ctx, req.(*DebugLevels))
	}
	return interceptor(ctx, in, info, handler)
}

func _DebugApi_DisableDebugLevels_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(DebugLevels)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(DebugApiServer).DisableDebugLevels(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/log.DebugApi/DisableDebugLevels",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(DebugApiServer).DisableDebugLevels(ctx, req.(*DebugLevels))
	}
	return interceptor(ctx, in, info, handler)
}

func _DebugApi_ShowDebugLevels_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(DebugLevels)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(DebugApiServer).ShowDebugLevels(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/log.DebugApi/ShowDebugLevels",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(DebugApiServer).ShowDebugLevels(ctx, req.(*DebugLevels))
	}
	return interceptor(ctx, in, info, handler)
}

var _DebugApi_serviceDesc = grpc.ServiceDesc{
	ServiceName: "log.DebugApi",
	HandlerType: (*DebugApiServer)(nil),
	Methods: []grpc.MethodDesc{
		{
			MethodName: "EnableDebugLevels",
			Handler:    _DebugApi_EnableDebugLevels_Handler,
		},
		{
			MethodName: "DisableDebugLevels",
			Handler:    _DebugApi_DisableDebugLevels_Handler,
		},
		{
			MethodName: "ShowDebugLevels",
			Handler:    _DebugApi_ShowDebugLevels_Handler,
		},
	},
	Streams:  []grpc.StreamDesc{},
	Metadata: "debug.proto",
}

func (m *DebugLevels) Marshal() (dAtA []byte, err error) {
	size := m.Size()
	dAtA = make([]byte, size)
	n, err := m.MarshalTo(dAtA)
	if err != nil {
		return nil, err
	}
	return dAtA[:n], nil
}

func (m *DebugLevels) MarshalTo(dAtA []byte) (int, error) {
	var i int
	_ = i
	var l int
	_ = l
	if len(m.Levels) > 0 {
		dAtA2 := make([]byte, len(m.Levels)*10)
		var j1 int
		for _, num := range m.Levels {
			for num >= 1<<7 {
				dAtA2[j1] = uint8(uint64(num)&0x7f | 0x80)
				num >>= 7
				j1++
			}
			dAtA2[j1] = uint8(num)
			j1++
		}
		dAtA[i] = 0xa
		i++
		i = encodeVarintDebug(dAtA, i, uint64(j1))
		i += copy(dAtA[i:], dAtA2[:j1])
	}
	return i, nil
}

func (m *DebugResult) Marshal() (dAtA []byte, err error) {
	size := m.Size()
	dAtA = make([]byte, size)
	n, err := m.MarshalTo(dAtA)
	if err != nil {
		return nil, err
	}
	return dAtA[:n], nil
}

func (m *DebugResult) MarshalTo(dAtA []byte) (int, error) {
	var i int
	_ = i
	var l int
	_ = l
	if len(m.Status) > 0 {
		dAtA[i] = 0xa
		i++
		i = encodeVarintDebug(dAtA, i, uint64(len(m.Status)))
		i += copy(dAtA[i:], m.Status)
	}
	if m.Code != 0 {
		dAtA[i] = 0x10
		i++
		i = encodeVarintDebug(dAtA, i, uint64(m.Code))
	}
	return i, nil
}

func encodeVarintDebug(dAtA []byte, offset int, v uint64) int {
	for v >= 1<<7 {
		dAtA[offset] = uint8(v&0x7f | 0x80)
		v >>= 7
		offset++
	}
	dAtA[offset] = uint8(v)
	return offset + 1
}
func (m *DebugLevels) CopyInFields(src *DebugLevels) {
	if m.Levels == nil || len(m.Levels) != len(src.Levels) {
		m.Levels = make([]DebugLevel, len(src.Levels))
	}
	copy(m.Levels, src.Levels)
}

func (m *DebugResult) CopyInFields(src *DebugResult) {
	m.Status = src.Status
	m.Code = src.Code
}

var DebugLevelStrings = []string{
	"etcd",
	"api",
	"notify",
	"dmedb",
	"dmereq",
	"locapi",
}

const (
	DebugLevelEtcd   uint64 = 1 << 0
	DebugLevelApi    uint64 = 1 << 1
	DebugLevelNotify uint64 = 1 << 2
	DebugLevelDmedb  uint64 = 1 << 3
	DebugLevelDmereq uint64 = 1 << 4
	DebugLevelLocapi uint64 = 1 << 5
)

func (e *DebugLevel) UnmarshalYAML(unmarshal func(interface{}) error) error {
	var str string
	err := unmarshal(&str)
	if err != nil {
		return err
	}
	val, ok := DebugLevel_value[str]
	if !ok {
		// may be enum value instead of string
		ival, err := strconv.Atoi(str)
		val = int32(ival)
		if err == nil {
			_, ok = DebugLevel_name[val]
		}
	}
	if !ok {
		return errors.New(fmt.Sprintf("No enum value for %s", str))
	}
	*e = DebugLevel(val)
	return nil
}

func (e DebugLevel) MarshalYAML() (interface{}, error) {
	return e.String(), nil
}

func (m *DebugLevels) Size() (n int) {
	var l int
	_ = l
	if len(m.Levels) > 0 {
		l = 0
		for _, e := range m.Levels {
			l += sovDebug(uint64(e))
		}
		n += 1 + sovDebug(uint64(l)) + l
	}
	return n
}

func (m *DebugResult) Size() (n int) {
	var l int
	_ = l
	l = len(m.Status)
	if l > 0 {
		n += 1 + l + sovDebug(uint64(l))
	}
	if m.Code != 0 {
		n += 1 + sovDebug(uint64(m.Code))
	}
	return n
}

func sovDebug(x uint64) (n int) {
	for {
		n++
		x >>= 7
		if x == 0 {
			break
		}
	}
	return n
}
func sozDebug(x uint64) (n int) {
	return sovDebug(uint64((x << 1) ^ uint64((int64(x) >> 63))))
}
func (m *DebugLevels) Unmarshal(dAtA []byte) error {
	l := len(dAtA)
	iNdEx := 0
	for iNdEx < l {
		preIndex := iNdEx
		var wire uint64
		for shift := uint(0); ; shift += 7 {
			if shift >= 64 {
				return ErrIntOverflowDebug
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
			return fmt.Errorf("proto: DebugLevels: wiretype end group for non-group")
		}
		if fieldNum <= 0 {
			return fmt.Errorf("proto: DebugLevels: illegal tag %d (wire type %d)", fieldNum, wire)
		}
		switch fieldNum {
		case 1:
			if wireType == 0 {
				var v DebugLevel
				for shift := uint(0); ; shift += 7 {
					if shift >= 64 {
						return ErrIntOverflowDebug
					}
					if iNdEx >= l {
						return io.ErrUnexpectedEOF
					}
					b := dAtA[iNdEx]
					iNdEx++
					v |= (DebugLevel(b) & 0x7F) << shift
					if b < 0x80 {
						break
					}
				}
				m.Levels = append(m.Levels, v)
			} else if wireType == 2 {
				var packedLen int
				for shift := uint(0); ; shift += 7 {
					if shift >= 64 {
						return ErrIntOverflowDebug
					}
					if iNdEx >= l {
						return io.ErrUnexpectedEOF
					}
					b := dAtA[iNdEx]
					iNdEx++
					packedLen |= (int(b) & 0x7F) << shift
					if b < 0x80 {
						break
					}
				}
				if packedLen < 0 {
					return ErrInvalidLengthDebug
				}
				postIndex := iNdEx + packedLen
				if postIndex > l {
					return io.ErrUnexpectedEOF
				}
				for iNdEx < postIndex {
					var v DebugLevel
					for shift := uint(0); ; shift += 7 {
						if shift >= 64 {
							return ErrIntOverflowDebug
						}
						if iNdEx >= l {
							return io.ErrUnexpectedEOF
						}
						b := dAtA[iNdEx]
						iNdEx++
						v |= (DebugLevel(b) & 0x7F) << shift
						if b < 0x80 {
							break
						}
					}
					m.Levels = append(m.Levels, v)
				}
			} else {
				return fmt.Errorf("proto: wrong wireType = %d for field Levels", wireType)
			}
		default:
			iNdEx = preIndex
			skippy, err := skipDebug(dAtA[iNdEx:])
			if err != nil {
				return err
			}
			if skippy < 0 {
				return ErrInvalidLengthDebug
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
func (m *DebugResult) Unmarshal(dAtA []byte) error {
	l := len(dAtA)
	iNdEx := 0
	for iNdEx < l {
		preIndex := iNdEx
		var wire uint64
		for shift := uint(0); ; shift += 7 {
			if shift >= 64 {
				return ErrIntOverflowDebug
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
			return fmt.Errorf("proto: DebugResult: wiretype end group for non-group")
		}
		if fieldNum <= 0 {
			return fmt.Errorf("proto: DebugResult: illegal tag %d (wire type %d)", fieldNum, wire)
		}
		switch fieldNum {
		case 1:
			if wireType != 2 {
				return fmt.Errorf("proto: wrong wireType = %d for field Status", wireType)
			}
			var stringLen uint64
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowDebug
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
				return ErrInvalidLengthDebug
			}
			postIndex := iNdEx + intStringLen
			if postIndex > l {
				return io.ErrUnexpectedEOF
			}
			m.Status = string(dAtA[iNdEx:postIndex])
			iNdEx = postIndex
		case 2:
			if wireType != 0 {
				return fmt.Errorf("proto: wrong wireType = %d for field Code", wireType)
			}
			m.Code = 0
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowDebug
				}
				if iNdEx >= l {
					return io.ErrUnexpectedEOF
				}
				b := dAtA[iNdEx]
				iNdEx++
				m.Code |= (uint32(b) & 0x7F) << shift
				if b < 0x80 {
					break
				}
			}
		default:
			iNdEx = preIndex
			skippy, err := skipDebug(dAtA[iNdEx:])
			if err != nil {
				return err
			}
			if skippy < 0 {
				return ErrInvalidLengthDebug
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
func skipDebug(dAtA []byte) (n int, err error) {
	l := len(dAtA)
	iNdEx := 0
	for iNdEx < l {
		var wire uint64
		for shift := uint(0); ; shift += 7 {
			if shift >= 64 {
				return 0, ErrIntOverflowDebug
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
					return 0, ErrIntOverflowDebug
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
					return 0, ErrIntOverflowDebug
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
				return 0, ErrInvalidLengthDebug
			}
			return iNdEx, nil
		case 3:
			for {
				var innerWire uint64
				var start int = iNdEx
				for shift := uint(0); ; shift += 7 {
					if shift >= 64 {
						return 0, ErrIntOverflowDebug
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
				next, err := skipDebug(dAtA[start:])
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
	ErrInvalidLengthDebug = fmt.Errorf("proto: negative length found during unmarshaling")
	ErrIntOverflowDebug   = fmt.Errorf("proto: integer overflow")
)

func init() { proto.RegisterFile("debug.proto", fileDescriptorDebug) }

var fileDescriptorDebug = []byte{
	// 270 bytes of a gzipped FileDescriptorProto
	0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0xff, 0xe2, 0xe2, 0x4e, 0x49, 0x4d, 0x2a,
	0x4d, 0xd7, 0x2b, 0x28, 0xca, 0x2f, 0xc9, 0x17, 0x62, 0xce, 0xc9, 0x4f, 0x57, 0x32, 0xe3, 0xe2,
	0x76, 0x01, 0x89, 0xf9, 0xa4, 0x96, 0xa5, 0xe6, 0x14, 0x0b, 0xa9, 0x73, 0xb1, 0xe5, 0x80, 0x59,
	0x12, 0x8c, 0x0a, 0xcc, 0x1a, 0x7c, 0x46, 0xfc, 0x7a, 0x39, 0xf9, 0xe9, 0x7a, 0x08, 0x15, 0x41,
	0x50, 0x69, 0x25, 0x4b, 0xa8, 0xbe, 0xa0, 0xd4, 0xe2, 0xd2, 0x9c, 0x12, 0x21, 0x31, 0x2e, 0xb6,
	0xe2, 0x92, 0xc4, 0x92, 0x52, 0x90, 0x3e, 0x46, 0x0d, 0xce, 0x20, 0x28, 0x4f, 0x48, 0x88, 0x8b,
	0x25, 0x39, 0x3f, 0x25, 0x55, 0x82, 0x49, 0x81, 0x51, 0x83, 0x37, 0x08, 0xcc, 0xd6, 0xf2, 0xe3,
	0xe2, 0x42, 0x18, 0x28, 0xc4, 0xc1, 0xc5, 0x92, 0x5a, 0x92, 0x9c, 0x22, 0xc0, 0x20, 0xc4, 0xce,
	0xc5, 0x9c, 0x58, 0x90, 0x29, 0xc0, 0x28, 0xc4, 0xc5, 0xc5, 0x96, 0x97, 0x5f, 0x92, 0x99, 0x56,
	0x29, 0xc0, 0x24, 0xc4, 0xc9, 0xc5, 0x9a, 0x92, 0x9b, 0x9a, 0x92, 0x24, 0xc0, 0x0c, 0x12, 0x4e,
	0xc9, 0x4d, 0x2d, 0x4a, 0x2d, 0x14, 0x60, 0x01, 0xb1, 0x73, 0xf2, 0x93, 0x41, 0xca, 0x59, 0x8d,
	0x76, 0x31, 0x72, 0x71, 0x80, 0x0d, 0x74, 0x2c, 0xc8, 0x14, 0xb2, 0xe4, 0x12, 0x74, 0xcd, 0x4b,
	0x4c, 0xca, 0x49, 0x45, 0xf6, 0x95, 0x00, 0x9a, 0x2f, 0x8a, 0xa5, 0x90, 0x44, 0x20, 0x3e, 0x50,
	0x62, 0x10, 0xb2, 0xe2, 0x12, 0x72, 0xc9, 0x2c, 0x26, 0x4f, 0xaf, 0x39, 0x17, 0x7f, 0x70, 0x46,
	0x7e, 0x39, 0xd1, 0x1a, 0x21, 0x22, 0x4a, 0x0c, 0x4e, 0x02, 0x27, 0x1e, 0xca, 0x31, 0x9c, 0x78,
	0x24, 0xc7, 0x78, 0xe1, 0x91, 0x1c, 0xe3, 0x83, 0x47, 0x72, 0x8c, 0x49, 0x6c, 0xe0, 0xd8, 0x31,
	0x06, 0x04, 0x00, 0x00, 0xff, 0xff, 0xde, 0x0c, 0x88, 0x86, 0xac, 0x01, 0x00, 0x00,
}
