// Code generated by protoc-gen-go. DO NOT EDIT.
// source: api/mexosagent.proto

package api

import proto "github.com/golang/protobuf/proto"
import fmt "fmt"
import math "math"
import _ "google.golang.org/genproto/googleapis/api/annotations"

import (
	context "golang.org/x/net/context"
	grpc "google.golang.org/grpc"
)

// Reference imports to suppress errors if they are not otherwise used.
var _ = proto.Marshal
var _ = fmt.Errorf
var _ = math.Inf

// This is a compile-time assertion to ensure that this generated file
// is compatible with the proto package it is being compiled against.
// A compilation error at this line likely means your copy of the
// proto package needs to be updated.
const _ = proto.ProtoPackageIsVersion2 // please upgrade the proto package

type Provision struct {
	Name                 string   `protobuf:"bytes,1,opt,name=name,proto3" json:"name,omitempty"`
	Image                string   `protobuf:"bytes,2,opt,name=image,proto3" json:"image,omitempty"`
	Flavor               string   `protobuf:"bytes,3,opt,name=flavor,proto3" json:"flavor,omitempty"`
	Network              string   `protobuf:"bytes,4,opt,name=network,proto3" json:"network,omitempty"`
	Fixedip              string   `protobuf:"bytes,5,opt,name=fixedip,proto3" json:"fixedip,omitempty"`
	Storage              string   `protobuf:"bytes,6,opt,name=storage,proto3" json:"storage,omitempty"`
	Zone                 string   `protobuf:"bytes,7,opt,name=zone,proto3" json:"zone,omitempty"`
	Tenant               string   `protobuf:"bytes,8,opt,name=tenant,proto3" json:"tenant,omitempty"`
	Metadata             string   `protobuf:"bytes,9,opt,name=metadata,proto3" json:"metadata,omitempty"`
	Region               string   `protobuf:"bytes,10,opt,name=region,proto3" json:"region,omitempty"`
	Kind                 string   `protobuf:"bytes,11,opt,name=kind,proto3" json:"kind,omitempty"`
	XXX_NoUnkeyedLiteral struct{} `json:"-"`
	XXX_unrecognized     []byte   `json:"-"`
	XXX_sizecache        int32    `json:"-"`
}

func (m *Provision) Reset()         { *m = Provision{} }
func (m *Provision) String() string { return proto.CompactTextString(m) }
func (*Provision) ProtoMessage()    {}
func (*Provision) Descriptor() ([]byte, []int) {
	return fileDescriptor_mexosagent_f761e18608af2469, []int{0}
}
func (m *Provision) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_Provision.Unmarshal(m, b)
}
func (m *Provision) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_Provision.Marshal(b, m, deterministic)
}
func (dst *Provision) XXX_Merge(src proto.Message) {
	xxx_messageInfo_Provision.Merge(dst, src)
}
func (m *Provision) XXX_Size() int {
	return xxx_messageInfo_Provision.Size(m)
}
func (m *Provision) XXX_DiscardUnknown() {
	xxx_messageInfo_Provision.DiscardUnknown(m)
}

var xxx_messageInfo_Provision proto.InternalMessageInfo

func (m *Provision) GetName() string {
	if m != nil {
		return m.Name
	}
	return ""
}

func (m *Provision) GetImage() string {
	if m != nil {
		return m.Image
	}
	return ""
}

func (m *Provision) GetFlavor() string {
	if m != nil {
		return m.Flavor
	}
	return ""
}

func (m *Provision) GetNetwork() string {
	if m != nil {
		return m.Network
	}
	return ""
}

func (m *Provision) GetFixedip() string {
	if m != nil {
		return m.Fixedip
	}
	return ""
}

func (m *Provision) GetStorage() string {
	if m != nil {
		return m.Storage
	}
	return ""
}

func (m *Provision) GetZone() string {
	if m != nil {
		return m.Zone
	}
	return ""
}

func (m *Provision) GetTenant() string {
	if m != nil {
		return m.Tenant
	}
	return ""
}

func (m *Provision) GetMetadata() string {
	if m != nil {
		return m.Metadata
	}
	return ""
}

func (m *Provision) GetRegion() string {
	if m != nil {
		return m.Region
	}
	return ""
}

func (m *Provision) GetKind() string {
	if m != nil {
		return m.Kind
	}
	return ""
}

type ProvisionRequest struct {
	Message              string       `protobuf:"bytes,1,opt,name=message,proto3" json:"message,omitempty"`
	Provisions           []*Provision `protobuf:"bytes,2,rep,name=provisions,proto3" json:"provisions,omitempty"`
	XXX_NoUnkeyedLiteral struct{}     `json:"-"`
	XXX_unrecognized     []byte       `json:"-"`
	XXX_sizecache        int32        `json:"-"`
}

func (m *ProvisionRequest) Reset()         { *m = ProvisionRequest{} }
func (m *ProvisionRequest) String() string { return proto.CompactTextString(m) }
func (*ProvisionRequest) ProtoMessage()    {}
func (*ProvisionRequest) Descriptor() ([]byte, []int) {
	return fileDescriptor_mexosagent_f761e18608af2469, []int{1}
}
func (m *ProvisionRequest) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_ProvisionRequest.Unmarshal(m, b)
}
func (m *ProvisionRequest) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_ProvisionRequest.Marshal(b, m, deterministic)
}
func (dst *ProvisionRequest) XXX_Merge(src proto.Message) {
	xxx_messageInfo_ProvisionRequest.Merge(dst, src)
}
func (m *ProvisionRequest) XXX_Size() int {
	return xxx_messageInfo_ProvisionRequest.Size(m)
}
func (m *ProvisionRequest) XXX_DiscardUnknown() {
	xxx_messageInfo_ProvisionRequest.DiscardUnknown(m)
}

var xxx_messageInfo_ProvisionRequest proto.InternalMessageInfo

func (m *ProvisionRequest) GetMessage() string {
	if m != nil {
		return m.Message
	}
	return ""
}

func (m *ProvisionRequest) GetProvisions() []*Provision {
	if m != nil {
		return m.Provisions
	}
	return nil
}

type ProvisionResponse struct {
	Message              string   `protobuf:"bytes,1,opt,name=message,proto3" json:"message,omitempty"`
	Status               string   `protobuf:"bytes,2,opt,name=status,proto3" json:"status,omitempty"`
	XXX_NoUnkeyedLiteral struct{} `json:"-"`
	XXX_unrecognized     []byte   `json:"-"`
	XXX_sizecache        int32    `json:"-"`
}

func (m *ProvisionResponse) Reset()         { *m = ProvisionResponse{} }
func (m *ProvisionResponse) String() string { return proto.CompactTextString(m) }
func (*ProvisionResponse) ProtoMessage()    {}
func (*ProvisionResponse) Descriptor() ([]byte, []int) {
	return fileDescriptor_mexosagent_f761e18608af2469, []int{2}
}
func (m *ProvisionResponse) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_ProvisionResponse.Unmarshal(m, b)
}
func (m *ProvisionResponse) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_ProvisionResponse.Marshal(b, m, deterministic)
}
func (dst *ProvisionResponse) XXX_Merge(src proto.Message) {
	xxx_messageInfo_ProvisionResponse.Merge(dst, src)
}
func (m *ProvisionResponse) XXX_Size() int {
	return xxx_messageInfo_ProvisionResponse.Size(m)
}
func (m *ProvisionResponse) XXX_DiscardUnknown() {
	xxx_messageInfo_ProvisionResponse.DiscardUnknown(m)
}

var xxx_messageInfo_ProvisionResponse proto.InternalMessageInfo

func (m *ProvisionResponse) GetMessage() string {
	if m != nil {
		return m.Message
	}
	return ""
}

func (m *ProvisionResponse) GetStatus() string {
	if m != nil {
		return m.Status
	}
	return ""
}

type StatusRequest struct {
	Message              string   `protobuf:"bytes,1,opt,name=message,proto3" json:"message,omitempty"`
	XXX_NoUnkeyedLiteral struct{} `json:"-"`
	XXX_unrecognized     []byte   `json:"-"`
	XXX_sizecache        int32    `json:"-"`
}

func (m *StatusRequest) Reset()         { *m = StatusRequest{} }
func (m *StatusRequest) String() string { return proto.CompactTextString(m) }
func (*StatusRequest) ProtoMessage()    {}
func (*StatusRequest) Descriptor() ([]byte, []int) {
	return fileDescriptor_mexosagent_f761e18608af2469, []int{3}
}
func (m *StatusRequest) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_StatusRequest.Unmarshal(m, b)
}
func (m *StatusRequest) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_StatusRequest.Marshal(b, m, deterministic)
}
func (dst *StatusRequest) XXX_Merge(src proto.Message) {
	xxx_messageInfo_StatusRequest.Merge(dst, src)
}
func (m *StatusRequest) XXX_Size() int {
	return xxx_messageInfo_StatusRequest.Size(m)
}
func (m *StatusRequest) XXX_DiscardUnknown() {
	xxx_messageInfo_StatusRequest.DiscardUnknown(m)
}

var xxx_messageInfo_StatusRequest proto.InternalMessageInfo

func (m *StatusRequest) GetMessage() string {
	if m != nil {
		return m.Message
	}
	return ""
}

type StatusResponse struct {
	Message              string       `protobuf:"bytes,1,opt,name=message,proto3" json:"message,omitempty"`
	Status               string       `protobuf:"bytes,2,opt,name=status,proto3" json:"status,omitempty"`
	Proxies              []*Proxy     `protobuf:"bytes,3,rep,name=proxies,proto3" json:"proxies,omitempty"`
	Provisions           []*Provision `protobuf:"bytes,4,rep,name=provisions,proto3" json:"provisions,omitempty"`
	XXX_NoUnkeyedLiteral struct{}     `json:"-"`
	XXX_unrecognized     []byte       `json:"-"`
	XXX_sizecache        int32        `json:"-"`
}

func (m *StatusResponse) Reset()         { *m = StatusResponse{} }
func (m *StatusResponse) String() string { return proto.CompactTextString(m) }
func (*StatusResponse) ProtoMessage()    {}
func (*StatusResponse) Descriptor() ([]byte, []int) {
	return fileDescriptor_mexosagent_f761e18608af2469, []int{4}
}
func (m *StatusResponse) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_StatusResponse.Unmarshal(m, b)
}
func (m *StatusResponse) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_StatusResponse.Marshal(b, m, deterministic)
}
func (dst *StatusResponse) XXX_Merge(src proto.Message) {
	xxx_messageInfo_StatusResponse.Merge(dst, src)
}
func (m *StatusResponse) XXX_Size() int {
	return xxx_messageInfo_StatusResponse.Size(m)
}
func (m *StatusResponse) XXX_DiscardUnknown() {
	xxx_messageInfo_StatusResponse.DiscardUnknown(m)
}

var xxx_messageInfo_StatusResponse proto.InternalMessageInfo

func (m *StatusResponse) GetMessage() string {
	if m != nil {
		return m.Message
	}
	return ""
}

func (m *StatusResponse) GetStatus() string {
	if m != nil {
		return m.Status
	}
	return ""
}

func (m *StatusResponse) GetProxies() []*Proxy {
	if m != nil {
		return m.Proxies
	}
	return nil
}

func (m *StatusResponse) GetProvisions() []*Provision {
	if m != nil {
		return m.Provisions
	}
	return nil
}

type Proxy struct {
	Name                 string   `protobuf:"bytes,1,opt,name=name,proto3" json:"name,omitempty"`
	Origin               string   `protobuf:"bytes,2,opt,name=origin,proto3" json:"origin,omitempty"`
	Path                 string   `protobuf:"bytes,3,opt,name=path,proto3" json:"path,omitempty"`
	XXX_NoUnkeyedLiteral struct{} `json:"-"`
	XXX_unrecognized     []byte   `json:"-"`
	XXX_sizecache        int32    `json:"-"`
}

func (m *Proxy) Reset()         { *m = Proxy{} }
func (m *Proxy) String() string { return proto.CompactTextString(m) }
func (*Proxy) ProtoMessage()    {}
func (*Proxy) Descriptor() ([]byte, []int) {
	return fileDescriptor_mexosagent_f761e18608af2469, []int{5}
}
func (m *Proxy) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_Proxy.Unmarshal(m, b)
}
func (m *Proxy) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_Proxy.Marshal(b, m, deterministic)
}
func (dst *Proxy) XXX_Merge(src proto.Message) {
	xxx_messageInfo_Proxy.Merge(dst, src)
}
func (m *Proxy) XXX_Size() int {
	return xxx_messageInfo_Proxy.Size(m)
}
func (m *Proxy) XXX_DiscardUnknown() {
	xxx_messageInfo_Proxy.DiscardUnknown(m)
}

var xxx_messageInfo_Proxy proto.InternalMessageInfo

func (m *Proxy) GetName() string {
	if m != nil {
		return m.Name
	}
	return ""
}

func (m *Proxy) GetOrigin() string {
	if m != nil {
		return m.Origin
	}
	return ""
}

func (m *Proxy) GetPath() string {
	if m != nil {
		return m.Path
	}
	return ""
}

type ProxyRequest struct {
	Message              string   `protobuf:"bytes,1,opt,name=message,proto3" json:"message,omitempty"`
	Proxies              []*Proxy `protobuf:"bytes,2,rep,name=proxies,proto3" json:"proxies,omitempty"`
	XXX_NoUnkeyedLiteral struct{} `json:"-"`
	XXX_unrecognized     []byte   `json:"-"`
	XXX_sizecache        int32    `json:"-"`
}

func (m *ProxyRequest) Reset()         { *m = ProxyRequest{} }
func (m *ProxyRequest) String() string { return proto.CompactTextString(m) }
func (*ProxyRequest) ProtoMessage()    {}
func (*ProxyRequest) Descriptor() ([]byte, []int) {
	return fileDescriptor_mexosagent_f761e18608af2469, []int{6}
}
func (m *ProxyRequest) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_ProxyRequest.Unmarshal(m, b)
}
func (m *ProxyRequest) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_ProxyRequest.Marshal(b, m, deterministic)
}
func (dst *ProxyRequest) XXX_Merge(src proto.Message) {
	xxx_messageInfo_ProxyRequest.Merge(dst, src)
}
func (m *ProxyRequest) XXX_Size() int {
	return xxx_messageInfo_ProxyRequest.Size(m)
}
func (m *ProxyRequest) XXX_DiscardUnknown() {
	xxx_messageInfo_ProxyRequest.DiscardUnknown(m)
}

var xxx_messageInfo_ProxyRequest proto.InternalMessageInfo

func (m *ProxyRequest) GetMessage() string {
	if m != nil {
		return m.Message
	}
	return ""
}

func (m *ProxyRequest) GetProxies() []*Proxy {
	if m != nil {
		return m.Proxies
	}
	return nil
}

type ProxyResponse struct {
	Message              string   `protobuf:"bytes,1,opt,name=message,proto3" json:"message,omitempty"`
	Status               string   `protobuf:"bytes,2,opt,name=status,proto3" json:"status,omitempty"`
	XXX_NoUnkeyedLiteral struct{} `json:"-"`
	XXX_unrecognized     []byte   `json:"-"`
	XXX_sizecache        int32    `json:"-"`
}

func (m *ProxyResponse) Reset()         { *m = ProxyResponse{} }
func (m *ProxyResponse) String() string { return proto.CompactTextString(m) }
func (*ProxyResponse) ProtoMessage()    {}
func (*ProxyResponse) Descriptor() ([]byte, []int) {
	return fileDescriptor_mexosagent_f761e18608af2469, []int{7}
}
func (m *ProxyResponse) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_ProxyResponse.Unmarshal(m, b)
}
func (m *ProxyResponse) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_ProxyResponse.Marshal(b, m, deterministic)
}
func (dst *ProxyResponse) XXX_Merge(src proto.Message) {
	xxx_messageInfo_ProxyResponse.Merge(dst, src)
}
func (m *ProxyResponse) XXX_Size() int {
	return xxx_messageInfo_ProxyResponse.Size(m)
}
func (m *ProxyResponse) XXX_DiscardUnknown() {
	xxx_messageInfo_ProxyResponse.DiscardUnknown(m)
}

var xxx_messageInfo_ProxyResponse proto.InternalMessageInfo

func (m *ProxyResponse) GetMessage() string {
	if m != nil {
		return m.Message
	}
	return ""
}

func (m *ProxyResponse) GetStatus() string {
	if m != nil {
		return m.Status
	}
	return ""
}

func init() {
	proto.RegisterType((*Provision)(nil), "api.Provision")
	proto.RegisterType((*ProvisionRequest)(nil), "api.ProvisionRequest")
	proto.RegisterType((*ProvisionResponse)(nil), "api.ProvisionResponse")
	proto.RegisterType((*StatusRequest)(nil), "api.StatusRequest")
	proto.RegisterType((*StatusResponse)(nil), "api.StatusResponse")
	proto.RegisterType((*Proxy)(nil), "api.Proxy")
	proto.RegisterType((*ProxyRequest)(nil), "api.ProxyRequest")
	proto.RegisterType((*ProxyResponse)(nil), "api.ProxyResponse")
}

// Reference imports to suppress errors if they are not otherwise used.
var _ context.Context
var _ grpc.ClientConn

// This is a compile-time assertion to ensure that this generated file
// is compatible with the grpc package it is being compiled against.
const _ = grpc.SupportPackageIsVersion4

// MexOSAgentClient is the client API for MexOSAgent service.
//
// For semantics around ctx use and closing/ending streaming RPCs, please refer to https://godoc.org/google.golang.org/grpc#ClientConn.NewStream.
type MexOSAgentClient interface {
	Provision(ctx context.Context, in *ProvisionRequest, opts ...grpc.CallOption) (*ProvisionResponse, error)
	Destroy(ctx context.Context, in *ProvisionRequest, opts ...grpc.CallOption) (*ProvisionResponse, error)
	Proxy(ctx context.Context, in *ProxyRequest, opts ...grpc.CallOption) (*ProxyResponse, error)
	Status(ctx context.Context, in *StatusRequest, opts ...grpc.CallOption) (*StatusResponse, error)
}

type mexOSAgentClient struct {
	cc *grpc.ClientConn
}

func NewMexOSAgentClient(cc *grpc.ClientConn) MexOSAgentClient {
	return &mexOSAgentClient{cc}
}

func (c *mexOSAgentClient) Provision(ctx context.Context, in *ProvisionRequest, opts ...grpc.CallOption) (*ProvisionResponse, error) {
	out := new(ProvisionResponse)
	err := c.cc.Invoke(ctx, "/api.MexOSAgent/Provision", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *mexOSAgentClient) Destroy(ctx context.Context, in *ProvisionRequest, opts ...grpc.CallOption) (*ProvisionResponse, error) {
	out := new(ProvisionResponse)
	err := c.cc.Invoke(ctx, "/api.MexOSAgent/Destroy", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *mexOSAgentClient) Proxy(ctx context.Context, in *ProxyRequest, opts ...grpc.CallOption) (*ProxyResponse, error) {
	out := new(ProxyResponse)
	err := c.cc.Invoke(ctx, "/api.MexOSAgent/Proxy", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *mexOSAgentClient) Status(ctx context.Context, in *StatusRequest, opts ...grpc.CallOption) (*StatusResponse, error) {
	out := new(StatusResponse)
	err := c.cc.Invoke(ctx, "/api.MexOSAgent/Status", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

// MexOSAgentServer is the server API for MexOSAgent service.
type MexOSAgentServer interface {
	Provision(context.Context, *ProvisionRequest) (*ProvisionResponse, error)
	Destroy(context.Context, *ProvisionRequest) (*ProvisionResponse, error)
	Proxy(context.Context, *ProxyRequest) (*ProxyResponse, error)
	Status(context.Context, *StatusRequest) (*StatusResponse, error)
}

func RegisterMexOSAgentServer(s *grpc.Server, srv MexOSAgentServer) {
	s.RegisterService(&_MexOSAgent_serviceDesc, srv)
}

func _MexOSAgent_Provision_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(ProvisionRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(MexOSAgentServer).Provision(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/api.MexOSAgent/Provision",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(MexOSAgentServer).Provision(ctx, req.(*ProvisionRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _MexOSAgent_Destroy_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(ProvisionRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(MexOSAgentServer).Destroy(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/api.MexOSAgent/Destroy",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(MexOSAgentServer).Destroy(ctx, req.(*ProvisionRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _MexOSAgent_Proxy_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(ProxyRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(MexOSAgentServer).Proxy(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/api.MexOSAgent/Proxy",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(MexOSAgentServer).Proxy(ctx, req.(*ProxyRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _MexOSAgent_Status_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(StatusRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(MexOSAgentServer).Status(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/api.MexOSAgent/Status",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(MexOSAgentServer).Status(ctx, req.(*StatusRequest))
	}
	return interceptor(ctx, in, info, handler)
}

var _MexOSAgent_serviceDesc = grpc.ServiceDesc{
	ServiceName: "api.MexOSAgent",
	HandlerType: (*MexOSAgentServer)(nil),
	Methods: []grpc.MethodDesc{
		{
			MethodName: "Provision",
			Handler:    _MexOSAgent_Provision_Handler,
		},
		{
			MethodName: "Destroy",
			Handler:    _MexOSAgent_Destroy_Handler,
		},
		{
			MethodName: "Proxy",
			Handler:    _MexOSAgent_Proxy_Handler,
		},
		{
			MethodName: "Status",
			Handler:    _MexOSAgent_Status_Handler,
		},
	},
	Streams:  []grpc.StreamDesc{},
	Metadata: "api/mexosagent.proto",
}

func init() { proto.RegisterFile("api/mexosagent.proto", fileDescriptor_mexosagent_f761e18608af2469) }

var fileDescriptor_mexosagent_f761e18608af2469 = []byte{
	// 523 bytes of a gzipped FileDescriptorProto
	0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0xff, 0x9c, 0x94, 0xc1, 0x6e, 0x13, 0x31,
	0x10, 0x86, 0xb5, 0x9b, 0x66, 0xd3, 0x4c, 0x48, 0x68, 0x4d, 0xba, 0xb2, 0x22, 0x0e, 0x95, 0xc5,
	0xa1, 0xf4, 0x90, 0x88, 0x72, 0xeb, 0xad, 0x52, 0x11, 0x5c, 0x80, 0x2a, 0xe5, 0xc8, 0xc5, 0x28,
	0xee, 0x62, 0xb5, 0x6b, 0x2f, 0xb6, 0x1b, 0xb6, 0x1c, 0x79, 0x01, 0x0e, 0x5c, 0x78, 0x20, 0xde,
	0x80, 0x57, 0xe0, 0x41, 0x90, 0x3d, 0xde, 0xb0, 0x8d, 0x80, 0x88, 0xde, 0xe6, 0x9f, 0x19, 0x7f,
	0x33, 0xfe, 0xe3, 0x0d, 0x8c, 0x79, 0x25, 0x67, 0xa5, 0xa8, 0xb5, 0xe5, 0x85, 0x50, 0x6e, 0x5a,
	0x19, 0xed, 0x34, 0xe9, 0xf0, 0x4a, 0x4e, 0x1e, 0x16, 0x5a, 0x17, 0x57, 0x62, 0xe6, 0x3b, 0xb8,
	0x52, 0xda, 0x71, 0x27, 0xb5, 0xb2, 0xd8, 0xc2, 0xbe, 0xa4, 0xd0, 0x3f, 0x33, 0x7a, 0x29, 0xad,
	0xd4, 0x8a, 0x10, 0xd8, 0x52, 0xbc, 0x14, 0x34, 0xd9, 0x4f, 0x0e, 0xfa, 0xf3, 0x10, 0x93, 0x31,
	0x74, 0x65, 0xc9, 0x0b, 0x41, 0xd3, 0x90, 0x44, 0x41, 0x72, 0xc8, 0x2e, 0xae, 0xf8, 0x52, 0x1b,
	0xda, 0x09, 0xe9, 0xa8, 0x08, 0x85, 0x9e, 0x12, 0xee, 0xa3, 0x36, 0x97, 0x74, 0x2b, 0x14, 0x1a,
	0xe9, 0x2b, 0x17, 0xb2, 0x16, 0x0b, 0x59, 0xd1, 0x2e, 0x56, 0xa2, 0xf4, 0x15, 0xeb, 0xb4, 0xf1,
	0x33, 0x32, 0xac, 0x44, 0xe9, 0xf7, 0xf9, 0xa4, 0x95, 0xa0, 0x3d, 0xdc, 0xc7, 0xc7, 0x7e, 0xb2,
	0x13, 0x8a, 0x2b, 0x47, 0xb7, 0x71, 0x32, 0x2a, 0x32, 0x81, 0xed, 0x52, 0x38, 0xbe, 0xe0, 0x8e,
	0xd3, 0x7e, 0xa8, 0xac, 0xb4, 0x3f, 0x63, 0x44, 0x21, 0xb5, 0xa2, 0x80, 0x67, 0x50, 0x79, 0xfe,
	0xa5, 0x54, 0x0b, 0x3a, 0x40, 0xbe, 0x8f, 0xd9, 0x5b, 0xd8, 0x59, 0x19, 0x32, 0x17, 0x1f, 0xae,
	0x85, 0x75, 0x7e, 0xc3, 0x52, 0x58, 0xef, 0x6d, 0xb4, 0xa6, 0x91, 0x64, 0x0a, 0x50, 0x35, 0xdd,
	0x96, 0xa6, 0xfb, 0x9d, 0x83, 0xc1, 0xd1, 0x68, 0xca, 0x2b, 0x39, 0xfd, 0x0d, 0x69, 0x75, 0xb0,
	0x67, 0xb0, 0xdb, 0xa2, 0xdb, 0x4a, 0x2b, 0x2b, 0xfe, 0x81, 0xcf, 0x21, 0xb3, 0x8e, 0xbb, 0x6b,
	0x1b, 0xdd, 0x8f, 0x8a, 0x3d, 0x86, 0xe1, 0x79, 0x88, 0x36, 0x6e, 0xc8, 0xbe, 0x25, 0x30, 0x6a,
	0x7a, 0xef, 0x3a, 0x8f, 0x3c, 0x82, 0x5e, 0x65, 0x74, 0x2d, 0x85, 0xa5, 0x9d, 0x70, 0x47, 0x68,
	0xee, 0x58, 0xdf, 0xcc, 0x9b, 0xd2, 0x9a, 0x19, 0x5b, 0x1b, 0xcd, 0x78, 0x0e, 0xdd, 0x40, 0xf8,
	0xe3, 0xbb, 0xcb, 0x21, 0xd3, 0x46, 0x16, 0x52, 0x35, 0xab, 0xa0, 0xf2, 0xbd, 0x15, 0x77, 0xef,
	0xe3, 0xbb, 0x0b, 0x31, 0x7b, 0x05, 0xf7, 0x70, 0x95, 0x8d, 0xbf, 0x57, 0xeb, 0x22, 0xe9, 0x5f,
	0x2f, 0xc2, 0x4e, 0x60, 0x18, 0x79, 0x77, 0x75, 0xec, 0xe8, 0x7b, 0x0a, 0xf0, 0x52, 0xd4, 0xaf,
	0xcf, 0x4f, 0xfc, 0x07, 0x49, 0xde, 0xb4, 0x3f, 0xb3, 0xbd, 0x35, 0x4f, 0x70, 0xeb, 0x49, 0xbe,
	0x9e, 0xc6, 0xe1, 0x8c, 0x7e, 0xfe, 0xf1, 0xf3, 0x6b, 0x4a, 0xd8, 0x70, 0xb6, 0x7c, 0x32, 0x5b,
	0xd9, 0x77, 0x9c, 0x1c, 0x92, 0x33, 0xe8, 0x9d, 0x0a, 0xeb, 0x8c, 0xbe, 0xf9, 0x5f, 0x66, 0x1e,
	0x98, 0x3b, 0x6c, 0xe0, 0x99, 0x0b, 0x64, 0x78, 0xe2, 0x69, 0xf3, 0x93, 0xec, 0xb6, 0x7c, 0x89,
	0x2c, 0xd2, 0x4e, 0x45, 0xce, 0x38, 0x70, 0x46, 0xac, 0x1f, 0x77, 0xab, 0x03, 0xe5, 0x05, 0x64,
	0xf8, 0xe4, 0x08, 0x9e, 0xb9, 0xf5, 0x56, 0x27, 0x0f, 0x6e, 0xe5, 0x22, 0x68, 0x2f, 0x80, 0xee,
	0x33, 0xf0, 0x20, 0xf4, 0xf0, 0x38, 0x39, 0x7c, 0x97, 0x85, 0xbf, 0xa9, 0xa7, 0xbf, 0x02, 0x00,
	0x00, 0xff, 0xff, 0xae, 0x70, 0x04, 0x02, 0xe1, 0x04, 0x00, 0x00,
}
