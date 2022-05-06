// Code generated by protoc-gen-gogo. DO NOT EDIT.
// source: operatorcode.proto

package edgeproto

import (
	context "context"
	"encoding/json"
	fmt "fmt"
	"github.com/coreos/etcd/clientv3/concurrency"
	"github.com/edgexr/edge-cloud/log"
	"github.com/edgexr/edge-cloud/objstore"
	_ "github.com/edgexr/edge-cloud/protogen"
	"github.com/edgexr/edge-cloud/util"
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

// OperatorCode maps a carrier code to an Operator organization name
type OperatorCode struct {
	// MCC plus MNC code, or custom carrier code designation.
	Code string `protobuf:"bytes,1,opt,name=code,proto3" json:"code,omitempty"`
	// Operator Organization name
	Organization string `protobuf:"bytes,2,opt,name=organization,proto3" json:"organization,omitempty"`
}

func (m *OperatorCode) Reset()         { *m = OperatorCode{} }
func (m *OperatorCode) String() string { return proto.CompactTextString(m) }
func (*OperatorCode) ProtoMessage()    {}
func (*OperatorCode) Descriptor() ([]byte, []int) {
	return fileDescriptor_3383c254f43c18d0, []int{0}
}
func (m *OperatorCode) XXX_Unmarshal(b []byte) error {
	return m.Unmarshal(b)
}
func (m *OperatorCode) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	if deterministic {
		return xxx_messageInfo_OperatorCode.Marshal(b, m, deterministic)
	} else {
		b = b[:cap(b)]
		n, err := m.MarshalToSizedBuffer(b)
		if err != nil {
			return nil, err
		}
		return b[:n], nil
	}
}
func (m *OperatorCode) XXX_Merge(src proto.Message) {
	xxx_messageInfo_OperatorCode.Merge(m, src)
}
func (m *OperatorCode) XXX_Size() int {
	return m.Size()
}
func (m *OperatorCode) XXX_DiscardUnknown() {
	xxx_messageInfo_OperatorCode.DiscardUnknown(m)
}

var xxx_messageInfo_OperatorCode proto.InternalMessageInfo

func init() {
	proto.RegisterType((*OperatorCode)(nil), "edgeproto.OperatorCode")
}

func init() { proto.RegisterFile("operatorcode.proto", fileDescriptor_3383c254f43c18d0) }

var fileDescriptor_3383c254f43c18d0 = []byte{
	// 425 bytes of a gzipped FileDescriptorProto
	0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0xff, 0xa4, 0x91, 0xbf, 0x8b, 0xd4, 0x40,
	0x14, 0xc7, 0xf3, 0x4e, 0x11, 0x6e, 0x08, 0x78, 0x0e, 0x07, 0x37, 0x2e, 0x47, 0x90, 0x54, 0xfe,
	0x38, 0x33, 0xa2, 0x56, 0x07, 0x22, 0xe7, 0x5a, 0x29, 0x7a, 0xb0, 0x82, 0xa5, 0x30, 0x97, 0x3c,
	0x66, 0x03, 0x31, 0x2f, 0x4c, 0x26, 0xae, 0x5a, 0x89, 0x8d, 0xed, 0xa2, 0x8d, 0xa5, 0xb5, 0x95,
	0xf8, 0x57, 0x5c, 0x79, 0x60, 0x63, 0x61, 0xa1, 0xbb, 0x16, 0x72, 0x95, 0x78, 0xb9, 0xab, 0x25,
	0x73, 0xcb, 0x92, 0x75, 0x59, 0x50, 0xac, 0xf2, 0x7d, 0xef, 0xfb, 0x5e, 0xbe, 0x9f, 0xbc, 0x30,
	0x4e, 0x05, 0x1a, 0x65, 0xc9, 0xc4, 0x94, 0x60, 0x54, 0x18, 0xb2, 0xc4, 0x97, 0x31, 0xd1, 0xe8,
	0x64, 0x67, 0x5d, 0x13, 0xe9, 0x0c, 0xa5, 0x2a, 0x52, 0xa9, 0xf2, 0x9c, 0xac, 0xb2, 0x29, 0xe5,
	0xe5, 0xf1, 0x60, 0xe7, 0xba, 0x4e, 0x6d, 0xbf, 0xda, 0x89, 0x62, 0x7a, 0x2c, 0x9b, 0x9d, 0xa7,
	0xc6, 0x3d, 0x2e, 0xc7, 0x19, 0x55, 0x89, 0x74, 0x33, 0x1a, 0xf3, 0xa9, 0x98, 0x6c, 0xf9, 0x06,
	0xcb, 0x2a, 0xb3, 0x93, 0x6a, 0x55, 0x93, 0x26, 0x27, 0x65, 0xa3, 0x8e, 0xbb, 0xe1, 0x2b, 0x60,
	0xfe, 0xf6, 0x84, 0xac, 0x4b, 0x09, 0x72, 0xce, 0x4e, 0x36, 0x84, 0x02, 0xce, 0xc1, 0xf9, 0xe5,
	0x9e, 0xd3, 0x3c, 0x64, 0x3e, 0x19, 0xad, 0xf2, 0xf4, 0xb9, 0xa3, 0x12, 0x4b, 0xce, 0x9b, 0xe9,
	0x6d, 0xde, 0xfc, 0x71, 0x20, 0xe0, 0xe7, 0x81, 0x80, 0x17, 0xb5, 0x80, 0x61, 0x2d, 0xe0, 0x6d,
	0x2d, 0xe0, 0xc3, 0xa1, 0xf0, 0x7e, 0x1d, 0x8a, 0xd3, 0xed, 0x84, 0xbb, 0xf8, 0xec, 0xe3, 0x91,
	0x58, 0x79, 0xa2, 0xb2, 0x1b, 0xdb, 0xad, 0x17, 0x5c, 0xfd, 0x72, 0x82, 0xcd, 0xcc, 0x6d, 0x15,
	0x29, 0x7f, 0x07, 0x8c, 0x77, 0x0d, 0x2a, 0x8b, 0x33, 0x8c, 0x6b, 0xd1, 0xf4, 0x70, 0x51, 0xdb,
	0xe8, 0x9c, 0x69, 0x19, 0x3d, 0xf7, 0xf1, 0xe1, 0xa3, 0xfd, 0x5a, 0x5c, 0xea, 0x61, 0x49, 0x95,
	0x89, 0xb1, 0xdb, 0xdc, 0x2b, 0x43, 0x5b, 0x6e, 0x6c, 0xc5, 0x4d, 0xe8, 0x3d, 0x95, 0x2b, 0x8d,
	0x1b, 0x6d, 0x8e, 0xf7, 0x47, 0xc2, 0x6f, 0xd7, 0x2f, 0x3f, 0x7d, 0x7f, 0xb3, 0x74, 0x36, 0x5c,
	0x95, 0xb1, 0xe3, 0x90, 0xed, 0xdf, 0xb8, 0x09, 0x17, 0xf9, 0x10, 0x18, 0xbf, 0x8d, 0x19, 0xfe,
	0x07, 0xe2, 0xfd, 0x7f, 0x44, 0x9c, 0x22, 0x25, 0x2e, 0x77, 0x0e, 0xe9, 0x35, 0xb0, 0x95, 0x07,
	0x7d, 0x1a, 0xfc, 0x1d, 0xd0, 0x22, 0x23, 0xbc, 0xb3, 0x5f, 0x8b, 0x0b, 0x8b, 0xb0, 0x1e, 0xa6,
	0x38, 0x98, 0x87, 0x5a, 0x0b, 0xb9, 0x2c, 0xfb, 0x34, 0xf8, 0x13, 0xe9, 0x0a, 0xdc, 0x5a, 0xdf,
	0xfd, 0x16, 0x78, 0xbb, 0xa3, 0x00, 0xf6, 0x46, 0x01, 0x7c, 0x1d, 0x05, 0x30, 0x1c, 0x07, 0xde,
	0xde, 0x38, 0xf0, 0x3e, 0x8f, 0x03, 0x6f, 0xe7, 0x94, 0xcb, 0xbf, 0xf6, 0x3b, 0x00, 0x00, 0xff,
	0xff, 0x1e, 0x75, 0xe4, 0xea, 0x26, 0x03, 0x00, 0x00,
}

// Reference imports to suppress errors if they are not otherwise used.
var _ context.Context
var _ grpc.ClientConn

// This is a compile-time assertion to ensure that this generated file
// is compatible with the grpc package it is being compiled against.
const _ = grpc.SupportPackageIsVersion4

// OperatorCodeApiClient is the client API for OperatorCodeApi service.
//
// For semantics around ctx use and closing/ending streaming RPCs, please refer to https://godoc.org/google.golang.org/grpc#ClientConn.NewStream.
type OperatorCodeApiClient interface {
	// Create Operator Code. Create a code for an Operator.
	CreateOperatorCode(ctx context.Context, in *OperatorCode, opts ...grpc.CallOption) (*Result, error)
	// Delete Operator Code. Delete a code for an Operator.
	DeleteOperatorCode(ctx context.Context, in *OperatorCode, opts ...grpc.CallOption) (*Result, error)
	// Show Operator Code. Show Codes for an Operator.
	ShowOperatorCode(ctx context.Context, in *OperatorCode, opts ...grpc.CallOption) (OperatorCodeApi_ShowOperatorCodeClient, error)
}

type operatorCodeApiClient struct {
	cc *grpc.ClientConn
}

func NewOperatorCodeApiClient(cc *grpc.ClientConn) OperatorCodeApiClient {
	return &operatorCodeApiClient{cc}
}

func (c *operatorCodeApiClient) CreateOperatorCode(ctx context.Context, in *OperatorCode, opts ...grpc.CallOption) (*Result, error) {
	out := new(Result)
	err := c.cc.Invoke(ctx, "/edgeproto.OperatorCodeApi/CreateOperatorCode", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *operatorCodeApiClient) DeleteOperatorCode(ctx context.Context, in *OperatorCode, opts ...grpc.CallOption) (*Result, error) {
	out := new(Result)
	err := c.cc.Invoke(ctx, "/edgeproto.OperatorCodeApi/DeleteOperatorCode", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *operatorCodeApiClient) ShowOperatorCode(ctx context.Context, in *OperatorCode, opts ...grpc.CallOption) (OperatorCodeApi_ShowOperatorCodeClient, error) {
	stream, err := c.cc.NewStream(ctx, &_OperatorCodeApi_serviceDesc.Streams[0], "/edgeproto.OperatorCodeApi/ShowOperatorCode", opts...)
	if err != nil {
		return nil, err
	}
	x := &operatorCodeApiShowOperatorCodeClient{stream}
	if err := x.ClientStream.SendMsg(in); err != nil {
		return nil, err
	}
	if err := x.ClientStream.CloseSend(); err != nil {
		return nil, err
	}
	return x, nil
}

type OperatorCodeApi_ShowOperatorCodeClient interface {
	Recv() (*OperatorCode, error)
	grpc.ClientStream
}

type operatorCodeApiShowOperatorCodeClient struct {
	grpc.ClientStream
}

func (x *operatorCodeApiShowOperatorCodeClient) Recv() (*OperatorCode, error) {
	m := new(OperatorCode)
	if err := x.ClientStream.RecvMsg(m); err != nil {
		return nil, err
	}
	return m, nil
}

// OperatorCodeApiServer is the server API for OperatorCodeApi service.
type OperatorCodeApiServer interface {
	// Create Operator Code. Create a code for an Operator.
	CreateOperatorCode(context.Context, *OperatorCode) (*Result, error)
	// Delete Operator Code. Delete a code for an Operator.
	DeleteOperatorCode(context.Context, *OperatorCode) (*Result, error)
	// Show Operator Code. Show Codes for an Operator.
	ShowOperatorCode(*OperatorCode, OperatorCodeApi_ShowOperatorCodeServer) error
}

// UnimplementedOperatorCodeApiServer can be embedded to have forward compatible implementations.
type UnimplementedOperatorCodeApiServer struct {
}

func (*UnimplementedOperatorCodeApiServer) CreateOperatorCode(ctx context.Context, req *OperatorCode) (*Result, error) {
	return nil, status.Errorf(codes.Unimplemented, "method CreateOperatorCode not implemented")
}
func (*UnimplementedOperatorCodeApiServer) DeleteOperatorCode(ctx context.Context, req *OperatorCode) (*Result, error) {
	return nil, status.Errorf(codes.Unimplemented, "method DeleteOperatorCode not implemented")
}
func (*UnimplementedOperatorCodeApiServer) ShowOperatorCode(req *OperatorCode, srv OperatorCodeApi_ShowOperatorCodeServer) error {
	return status.Errorf(codes.Unimplemented, "method ShowOperatorCode not implemented")
}

func RegisterOperatorCodeApiServer(s *grpc.Server, srv OperatorCodeApiServer) {
	s.RegisterService(&_OperatorCodeApi_serviceDesc, srv)
}

func _OperatorCodeApi_CreateOperatorCode_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(OperatorCode)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(OperatorCodeApiServer).CreateOperatorCode(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/edgeproto.OperatorCodeApi/CreateOperatorCode",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(OperatorCodeApiServer).CreateOperatorCode(ctx, req.(*OperatorCode))
	}
	return interceptor(ctx, in, info, handler)
}

func _OperatorCodeApi_DeleteOperatorCode_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(OperatorCode)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(OperatorCodeApiServer).DeleteOperatorCode(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/edgeproto.OperatorCodeApi/DeleteOperatorCode",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(OperatorCodeApiServer).DeleteOperatorCode(ctx, req.(*OperatorCode))
	}
	return interceptor(ctx, in, info, handler)
}

func _OperatorCodeApi_ShowOperatorCode_Handler(srv interface{}, stream grpc.ServerStream) error {
	m := new(OperatorCode)
	if err := stream.RecvMsg(m); err != nil {
		return err
	}
	return srv.(OperatorCodeApiServer).ShowOperatorCode(m, &operatorCodeApiShowOperatorCodeServer{stream})
}

type OperatorCodeApi_ShowOperatorCodeServer interface {
	Send(*OperatorCode) error
	grpc.ServerStream
}

type operatorCodeApiShowOperatorCodeServer struct {
	grpc.ServerStream
}

func (x *operatorCodeApiShowOperatorCodeServer) Send(m *OperatorCode) error {
	return x.ServerStream.SendMsg(m)
}

var _OperatorCodeApi_serviceDesc = grpc.ServiceDesc{
	ServiceName: "edgeproto.OperatorCodeApi",
	HandlerType: (*OperatorCodeApiServer)(nil),
	Methods: []grpc.MethodDesc{
		{
			MethodName: "CreateOperatorCode",
			Handler:    _OperatorCodeApi_CreateOperatorCode_Handler,
		},
		{
			MethodName: "DeleteOperatorCode",
			Handler:    _OperatorCodeApi_DeleteOperatorCode_Handler,
		},
	},
	Streams: []grpc.StreamDesc{
		{
			StreamName:    "ShowOperatorCode",
			Handler:       _OperatorCodeApi_ShowOperatorCode_Handler,
			ServerStreams: true,
		},
	},
	Metadata: "operatorcode.proto",
}

func (m *OperatorCode) Marshal() (dAtA []byte, err error) {
	size := m.Size()
	dAtA = make([]byte, size)
	n, err := m.MarshalToSizedBuffer(dAtA[:size])
	if err != nil {
		return nil, err
	}
	return dAtA[:n], nil
}

func (m *OperatorCode) MarshalTo(dAtA []byte) (int, error) {
	size := m.Size()
	return m.MarshalToSizedBuffer(dAtA[:size])
}

func (m *OperatorCode) MarshalToSizedBuffer(dAtA []byte) (int, error) {
	i := len(dAtA)
	_ = i
	var l int
	_ = l
	if len(m.Organization) > 0 {
		i -= len(m.Organization)
		copy(dAtA[i:], m.Organization)
		i = encodeVarintOperatorcode(dAtA, i, uint64(len(m.Organization)))
		i--
		dAtA[i] = 0x12
	}
	if len(m.Code) > 0 {
		i -= len(m.Code)
		copy(dAtA[i:], m.Code)
		i = encodeVarintOperatorcode(dAtA, i, uint64(len(m.Code)))
		i--
		dAtA[i] = 0xa
	}
	return len(dAtA) - i, nil
}

func encodeVarintOperatorcode(dAtA []byte, offset int, v uint64) int {
	offset -= sovOperatorcode(v)
	base := offset
	for v >= 1<<7 {
		dAtA[offset] = uint8(v&0x7f | 0x80)
		v >>= 7
		offset++
	}
	dAtA[offset] = uint8(v)
	return base
}
func (m *OperatorCode) Matches(o *OperatorCode, fopts ...MatchOpt) bool {
	opts := MatchOptions{}
	applyMatchOptions(&opts, fopts...)
	if o == nil {
		if opts.Filter {
			return true
		}
		return false
	}
	if !opts.Filter || o.Code != "" {
		if o.Code != m.Code {
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

func (m *OperatorCode) CopyInFields(src *OperatorCode) int {
	changed := 0
	if m.Code != src.Code {
		m.Code = src.Code
		changed++
	}
	if m.Organization != src.Organization {
		m.Organization = src.Organization
		changed++
	}
	return changed
}

func (m *OperatorCode) DeepCopyIn(src *OperatorCode) {
	m.Code = src.Code
	m.Organization = src.Organization
}

func (s *OperatorCode) HasFields() bool {
	return false
}

type OperatorCodeStore interface {
	Create(ctx context.Context, m *OperatorCode, wait func(int64)) (*Result, error)
	Update(ctx context.Context, m *OperatorCode, wait func(int64)) (*Result, error)
	Delete(ctx context.Context, m *OperatorCode, wait func(int64)) (*Result, error)
	Put(ctx context.Context, m *OperatorCode, wait func(int64), ops ...objstore.KVOp) (*Result, error)
	LoadOne(key string) (*OperatorCode, int64, error)
	Get(ctx context.Context, key *OperatorCodeKey, buf *OperatorCode) bool
	STMGet(stm concurrency.STM, key *OperatorCodeKey, buf *OperatorCode) bool
	STMPut(stm concurrency.STM, obj *OperatorCode, ops ...objstore.KVOp)
	STMDel(stm concurrency.STM, key *OperatorCodeKey)
}

type OperatorCodeStoreImpl struct {
	kvstore objstore.KVStore
}

func NewOperatorCodeStore(kvstore objstore.KVStore) *OperatorCodeStoreImpl {
	return &OperatorCodeStoreImpl{kvstore: kvstore}
}

func (s *OperatorCodeStoreImpl) Create(ctx context.Context, m *OperatorCode, wait func(int64)) (*Result, error) {
	err := m.Validate(nil)
	if err != nil {
		return nil, err
	}
	key := objstore.DbKeyString("OperatorCode", m.GetKey())
	val, err := json.Marshal(m)
	if err != nil {
		return nil, err
	}
	rev, err := s.kvstore.Create(ctx, key, string(val))
	if err != nil {
		return nil, err
	}
	if wait != nil {
		wait(rev)
	}
	return &Result{}, err
}

func (s *OperatorCodeStoreImpl) Update(ctx context.Context, m *OperatorCode, wait func(int64)) (*Result, error) {
	err := m.Validate(nil)
	if err != nil {
		return nil, err
	}
	key := objstore.DbKeyString("OperatorCode", m.GetKey())
	var vers int64 = 0
	val, err := json.Marshal(m)
	if err != nil {
		return nil, err
	}
	rev, err := s.kvstore.Update(ctx, key, string(val), vers)
	if err != nil {
		return nil, err
	}
	if wait != nil {
		wait(rev)
	}
	return &Result{}, err
}

func (s *OperatorCodeStoreImpl) Put(ctx context.Context, m *OperatorCode, wait func(int64), ops ...objstore.KVOp) (*Result, error) {
	err := m.Validate(nil)
	if err != nil {
		return nil, err
	}
	key := objstore.DbKeyString("OperatorCode", m.GetKey())
	var val []byte
	val, err = json.Marshal(m)
	if err != nil {
		return nil, err
	}
	rev, err := s.kvstore.Put(ctx, key, string(val), ops...)
	if err != nil {
		return nil, err
	}
	if wait != nil {
		wait(rev)
	}
	return &Result{}, err
}

func (s *OperatorCodeStoreImpl) Delete(ctx context.Context, m *OperatorCode, wait func(int64)) (*Result, error) {
	err := m.GetKey().ValidateKey()
	if err != nil {
		return nil, err
	}
	key := objstore.DbKeyString("OperatorCode", m.GetKey())
	rev, err := s.kvstore.Delete(ctx, key)
	if err != nil {
		return nil, err
	}
	if wait != nil {
		wait(rev)
	}
	return &Result{}, err
}

func (s *OperatorCodeStoreImpl) LoadOne(key string) (*OperatorCode, int64, error) {
	val, rev, _, err := s.kvstore.Get(key)
	if err != nil {
		return nil, 0, err
	}
	var obj OperatorCode
	err = json.Unmarshal(val, &obj)
	if err != nil {
		log.DebugLog(log.DebugLevelApi, "Failed to parse OperatorCode data", "val", string(val), "err", err)
		return nil, 0, err
	}
	return &obj, rev, nil
}

func (s *OperatorCodeStoreImpl) Get(ctx context.Context, key *OperatorCodeKey, buf *OperatorCode) bool {
	keystr := objstore.DbKeyString("OperatorCode", key)
	val, _, _, err := s.kvstore.Get(keystr)
	if err != nil {
		return false
	}
	return s.parseGetData(val, buf)
}

func (s *OperatorCodeStoreImpl) STMGet(stm concurrency.STM, key *OperatorCodeKey, buf *OperatorCode) bool {
	keystr := objstore.DbKeyString("OperatorCode", key)
	valstr := stm.Get(keystr)
	return s.parseGetData([]byte(valstr), buf)
}

func (s *OperatorCodeStoreImpl) parseGetData(val []byte, buf *OperatorCode) bool {
	if len(val) == 0 {
		return false
	}
	if buf != nil {
		// clear buf, because empty values in val won't
		// overwrite non-empty values in buf.
		*buf = OperatorCode{}
		err := json.Unmarshal(val, buf)
		if err != nil {
			return false
		}
	}
	return true
}

func (s *OperatorCodeStoreImpl) STMPut(stm concurrency.STM, obj *OperatorCode, ops ...objstore.KVOp) {
	keystr := objstore.DbKeyString("OperatorCode", obj.GetKey())

	val, err := json.Marshal(obj)
	if err != nil {
		log.InfoLog("OperatorCode json marshal failed", "obj", obj, "err", err)
	}
	v3opts := GetSTMOpts(ops...)
	stm.Put(keystr, string(val), v3opts...)
}

func (s *OperatorCodeStoreImpl) STMDel(stm concurrency.STM, key *OperatorCodeKey) {
	keystr := objstore.DbKeyString("OperatorCode", key)
	stm.Del(keystr)
}

type OperatorCodeKeyWatcher struct {
	cb func(ctx context.Context)
}

type OperatorCodeCacheData struct {
	Obj    *OperatorCode
	ModRev int64
}

// OperatorCodeCache caches OperatorCode objects in memory in a hash table
// and keeps them in sync with the database.
type OperatorCodeCache struct {
	Objs          map[OperatorCodeKey]*OperatorCodeCacheData
	Mux           util.Mutex
	List          map[OperatorCodeKey]struct{}
	FlushAll      bool
	NotifyCbs     []func(ctx context.Context, obj *OperatorCodeKey, old *OperatorCode, modRev int64)
	UpdatedCbs    []func(ctx context.Context, old *OperatorCode, new *OperatorCode)
	DeletedCbs    []func(ctx context.Context, old *OperatorCode)
	KeyWatchers   map[OperatorCodeKey][]*OperatorCodeKeyWatcher
	UpdatedKeyCbs []func(ctx context.Context, key *OperatorCodeKey)
	DeletedKeyCbs []func(ctx context.Context, key *OperatorCodeKey)
}

func NewOperatorCodeCache() *OperatorCodeCache {
	cache := OperatorCodeCache{}
	InitOperatorCodeCache(&cache)
	return &cache
}

func InitOperatorCodeCache(cache *OperatorCodeCache) {
	cache.Objs = make(map[OperatorCodeKey]*OperatorCodeCacheData)
	cache.KeyWatchers = make(map[OperatorCodeKey][]*OperatorCodeKeyWatcher)
	cache.NotifyCbs = nil
	cache.UpdatedCbs = nil
	cache.DeletedCbs = nil
	cache.UpdatedKeyCbs = nil
	cache.DeletedKeyCbs = nil
}

func (c *OperatorCodeCache) GetTypeString() string {
	return "OperatorCode"
}

func (c *OperatorCodeCache) Get(key *OperatorCodeKey, valbuf *OperatorCode) bool {
	var modRev int64
	return c.GetWithRev(key, valbuf, &modRev)
}

func (c *OperatorCodeCache) GetWithRev(key *OperatorCodeKey, valbuf *OperatorCode, modRev *int64) bool {
	c.Mux.Lock()
	defer c.Mux.Unlock()
	inst, found := c.Objs[*key]
	if found {
		valbuf.DeepCopyIn(inst.Obj)
		*modRev = inst.ModRev
	}
	return found
}

func (c *OperatorCodeCache) HasKey(key *OperatorCodeKey) bool {
	c.Mux.Lock()
	defer c.Mux.Unlock()
	_, found := c.Objs[*key]
	return found
}

func (c *OperatorCodeCache) GetAllKeys(ctx context.Context, cb func(key *OperatorCodeKey, modRev int64)) {
	c.Mux.Lock()
	defer c.Mux.Unlock()
	for key, data := range c.Objs {
		cb(&key, data.ModRev)
	}
}

func (c *OperatorCodeCache) Update(ctx context.Context, in *OperatorCode, modRev int64) {
	c.UpdateModFunc(ctx, in.GetKey(), modRev, func(old *OperatorCode) (*OperatorCode, bool) {
		return in, true
	})
}

func (c *OperatorCodeCache) UpdateModFunc(ctx context.Context, key *OperatorCodeKey, modRev int64, modFunc func(old *OperatorCode) (new *OperatorCode, changed bool)) {
	c.Mux.Lock()
	var old *OperatorCode
	if oldData, found := c.Objs[*key]; found {
		old = oldData.Obj
	}
	new, changed := modFunc(old)
	if !changed {
		c.Mux.Unlock()
		return
	}
	for _, cb := range c.UpdatedCbs {
		newCopy := &OperatorCode{}
		newCopy.DeepCopyIn(new)
		defer cb(ctx, old, newCopy)
	}
	for _, cb := range c.NotifyCbs {
		if cb != nil {
			defer cb(ctx, new.GetKey(), old, modRev)
		}
	}
	for _, cb := range c.UpdatedKeyCbs {
		defer cb(ctx, key)
	}
	store := &OperatorCode{}
	store.DeepCopyIn(new)
	c.Objs[new.GetKeyVal()] = &OperatorCodeCacheData{
		Obj:    store,
		ModRev: modRev,
	}
	log.SpanLog(ctx, log.DebugLevelApi, "cache update", "new", store)
	c.Mux.Unlock()
	c.TriggerKeyWatchers(ctx, new.GetKey())
}

func (c *OperatorCodeCache) Delete(ctx context.Context, in *OperatorCode, modRev int64) {
	c.DeleteCondFunc(ctx, in, modRev, func(old *OperatorCode) bool {
		return true
	})
}

func (c *OperatorCodeCache) DeleteCondFunc(ctx context.Context, in *OperatorCode, modRev int64, condFunc func(old *OperatorCode) bool) {
	c.Mux.Lock()
	var old *OperatorCode
	oldData, found := c.Objs[in.GetKeyVal()]
	if found {
		old = oldData.Obj
		if !condFunc(old) {
			c.Mux.Unlock()
			return
		}
	}
	delete(c.Objs, in.GetKeyVal())
	log.SpanLog(ctx, log.DebugLevelApi, "cache delete")
	c.Mux.Unlock()
	for _, cb := range c.NotifyCbs {
		if cb != nil {
			cb(ctx, in.GetKey(), old, modRev)
		}
	}
	if old != nil {
		for _, cb := range c.DeletedCbs {
			cb(ctx, old)
		}
	}
	for _, cb := range c.DeletedKeyCbs {
		cb(ctx, in.GetKey())
	}
	c.TriggerKeyWatchers(ctx, in.GetKey())
}

func (c *OperatorCodeCache) Prune(ctx context.Context, validKeys map[OperatorCodeKey]struct{}) {
	notify := make(map[OperatorCodeKey]*OperatorCodeCacheData)
	c.Mux.Lock()
	for key, _ := range c.Objs {
		if _, ok := validKeys[key]; !ok {
			if len(c.NotifyCbs) > 0 || len(c.DeletedKeyCbs) > 0 || len(c.DeletedCbs) > 0 {
				notify[key] = c.Objs[key]
			}
			delete(c.Objs, key)
		}
	}
	c.Mux.Unlock()
	for key, old := range notify {
		for _, cb := range c.NotifyCbs {
			if cb != nil {
				cb(ctx, &key, old.Obj, old.ModRev)
			}
		}
		for _, cb := range c.DeletedKeyCbs {
			cb(ctx, &key)
		}
		if old.Obj != nil {
			for _, cb := range c.DeletedCbs {
				cb(ctx, old.Obj)
			}
		}
		c.TriggerKeyWatchers(ctx, &key)
	}
}

func (c *OperatorCodeCache) GetCount() int {
	c.Mux.Lock()
	defer c.Mux.Unlock()
	return len(c.Objs)
}

func (c *OperatorCodeCache) Flush(ctx context.Context, notifyId int64) {
}

func (c *OperatorCodeCache) Show(filter *OperatorCode, cb func(ret *OperatorCode) error) error {
	c.Mux.Lock()
	defer c.Mux.Unlock()
	for _, data := range c.Objs {
		if !data.Obj.Matches(filter, MatchFilter()) {
			continue
		}
		err := cb(data.Obj)
		if err != nil {
			return err
		}
	}
	return nil
}

func OperatorCodeGenericNotifyCb(fn func(key *OperatorCodeKey, old *OperatorCode)) func(objstore.ObjKey, objstore.Obj) {
	return func(objkey objstore.ObjKey, obj objstore.Obj) {
		fn(objkey.(*OperatorCodeKey), obj.(*OperatorCode))
	}
}

func (c *OperatorCodeCache) SetNotifyCb(fn func(ctx context.Context, obj *OperatorCodeKey, old *OperatorCode, modRev int64)) {
	c.NotifyCbs = []func(ctx context.Context, obj *OperatorCodeKey, old *OperatorCode, modRev int64){fn}
}

func (c *OperatorCodeCache) SetUpdatedCb(fn func(ctx context.Context, old *OperatorCode, new *OperatorCode)) {
	c.UpdatedCbs = []func(ctx context.Context, old *OperatorCode, new *OperatorCode){fn}
}

func (c *OperatorCodeCache) SetDeletedCb(fn func(ctx context.Context, old *OperatorCode)) {
	c.DeletedCbs = []func(ctx context.Context, old *OperatorCode){fn}
}

func (c *OperatorCodeCache) SetUpdatedKeyCb(fn func(ctx context.Context, key *OperatorCodeKey)) {
	c.UpdatedKeyCbs = []func(ctx context.Context, key *OperatorCodeKey){fn}
}

func (c *OperatorCodeCache) SetDeletedKeyCb(fn func(ctx context.Context, key *OperatorCodeKey)) {
	c.DeletedKeyCbs = []func(ctx context.Context, key *OperatorCodeKey){fn}
}

func (c *OperatorCodeCache) AddUpdatedCb(fn func(ctx context.Context, old *OperatorCode, new *OperatorCode)) {
	c.UpdatedCbs = append(c.UpdatedCbs, fn)
}

func (c *OperatorCodeCache) AddDeletedCb(fn func(ctx context.Context, old *OperatorCode)) {
	c.DeletedCbs = append(c.DeletedCbs, fn)
}

func (c *OperatorCodeCache) AddNotifyCb(fn func(ctx context.Context, obj *OperatorCodeKey, old *OperatorCode, modRev int64)) {
	c.NotifyCbs = append(c.NotifyCbs, fn)
}

func (c *OperatorCodeCache) AddUpdatedKeyCb(fn func(ctx context.Context, key *OperatorCodeKey)) {
	c.UpdatedKeyCbs = append(c.UpdatedKeyCbs, fn)
}

func (c *OperatorCodeCache) AddDeletedKeyCb(fn func(ctx context.Context, key *OperatorCodeKey)) {
	c.DeletedKeyCbs = append(c.DeletedKeyCbs, fn)
}

func (c *OperatorCodeCache) SetFlushAll() {
	c.FlushAll = true
}

func (c *OperatorCodeCache) WatchKey(key *OperatorCodeKey, cb func(ctx context.Context)) context.CancelFunc {
	c.Mux.Lock()
	defer c.Mux.Unlock()
	list, ok := c.KeyWatchers[*key]
	if !ok {
		list = make([]*OperatorCodeKeyWatcher, 0)
	}
	watcher := OperatorCodeKeyWatcher{cb: cb}
	c.KeyWatchers[*key] = append(list, &watcher)
	log.DebugLog(log.DebugLevelApi, "Watching OperatorCode", "key", key)
	return func() {
		c.Mux.Lock()
		defer c.Mux.Unlock()
		list, ok := c.KeyWatchers[*key]
		if !ok {
			return
		}
		for ii, _ := range list {
			if list[ii] != &watcher {
				continue
			}
			if len(list) == 1 {
				delete(c.KeyWatchers, *key)
				return
			}
			list[ii] = list[len(list)-1]
			list[len(list)-1] = nil
			c.KeyWatchers[*key] = list[:len(list)-1]
			return
		}
	}
}

func (c *OperatorCodeCache) TriggerKeyWatchers(ctx context.Context, key *OperatorCodeKey) {
	watchers := make([]*OperatorCodeKeyWatcher, 0)
	c.Mux.Lock()
	if list, ok := c.KeyWatchers[*key]; ok {
		watchers = append(watchers, list...)
	}
	c.Mux.Unlock()
	for ii, _ := range watchers {
		watchers[ii].cb(ctx)
	}
}

// Note that we explicitly ignore the global revision number, because of the way
// the notify framework sends updates (by hashing keys and doing lookups, instead
// of sequentially through a history buffer), updates may be done out-of-order
// or multiple updates compressed into one update, so the state of the cache at
// any point in time may not by in sync with a particular database revision number.

func (c *OperatorCodeCache) SyncUpdate(ctx context.Context, key, val []byte, rev, modRev int64) {
	obj := OperatorCode{}
	err := json.Unmarshal(val, &obj)
	if err != nil {
		log.WarnLog("Failed to parse OperatorCode data", "val", string(val), "err", err)
		return
	}
	c.Update(ctx, &obj, modRev)
	c.Mux.Lock()
	if c.List != nil {
		c.List[obj.GetKeyVal()] = struct{}{}
	}
	c.Mux.Unlock()
}

func (c *OperatorCodeCache) SyncDelete(ctx context.Context, key []byte, rev, modRev int64) {
	obj := OperatorCode{}
	keystr := objstore.DbKeyPrefixRemove(string(key))
	OperatorCodeKeyStringParse(keystr, &obj)
	c.Delete(ctx, &obj, modRev)
}

func (c *OperatorCodeCache) SyncListStart(ctx context.Context) {
	c.List = make(map[OperatorCodeKey]struct{})
}

func (c *OperatorCodeCache) SyncListEnd(ctx context.Context) {
	deleted := make(map[OperatorCodeKey]*OperatorCodeCacheData)
	c.Mux.Lock()
	for key, val := range c.Objs {
		if _, found := c.List[key]; !found {
			deleted[key] = val
			delete(c.Objs, key)
		}
	}
	c.List = nil
	c.Mux.Unlock()
	for key, val := range deleted {
		for _, cb := range c.NotifyCbs {
			if cb != nil {
				cb(ctx, &key, val.Obj, val.ModRev)
			}
		}
		for _, cb := range c.DeletedKeyCbs {
			cb(ctx, &key)
		}
		if val.Obj != nil {
			for _, cb := range c.DeletedCbs {
				cb(ctx, val.Obj)
			}
		}
		c.TriggerKeyWatchers(ctx, &key)
	}
}

func (c *OperatorCodeCache) UsesOrg(org string) bool {
	c.Mux.Lock()
	defer c.Mux.Unlock()
	for _, val := range c.Objs {
		if val.Obj.Organization == org {
			return true
		}
	}
	return false
}

// Helper method to check that enums have valid values
func (m *OperatorCode) ValidateEnums() error {
	return nil
}

func (s *OperatorCode) ClearTagged(tags map[string]struct{}) {
}

func (m *OperatorCode) IsValidArgsForCreateOperatorCode() error {
	return nil
}

func (m *OperatorCode) IsValidArgsForDeleteOperatorCode() error {
	return nil
}

func (m *OperatorCode) Size() (n int) {
	if m == nil {
		return 0
	}
	var l int
	_ = l
	l = len(m.Code)
	if l > 0 {
		n += 1 + l + sovOperatorcode(uint64(l))
	}
	l = len(m.Organization)
	if l > 0 {
		n += 1 + l + sovOperatorcode(uint64(l))
	}
	return n
}

func sovOperatorcode(x uint64) (n int) {
	return (math_bits.Len64(x|1) + 6) / 7
}
func sozOperatorcode(x uint64) (n int) {
	return sovOperatorcode(uint64((x << 1) ^ uint64((int64(x) >> 63))))
}
func (m *OperatorCode) Unmarshal(dAtA []byte) error {
	l := len(dAtA)
	iNdEx := 0
	for iNdEx < l {
		preIndex := iNdEx
		var wire uint64
		for shift := uint(0); ; shift += 7 {
			if shift >= 64 {
				return ErrIntOverflowOperatorcode
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
			return fmt.Errorf("proto: OperatorCode: wiretype end group for non-group")
		}
		if fieldNum <= 0 {
			return fmt.Errorf("proto: OperatorCode: illegal tag %d (wire type %d)", fieldNum, wire)
		}
		switch fieldNum {
		case 1:
			if wireType != 2 {
				return fmt.Errorf("proto: wrong wireType = %d for field Code", wireType)
			}
			var stringLen uint64
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowOperatorcode
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
				return ErrInvalidLengthOperatorcode
			}
			postIndex := iNdEx + intStringLen
			if postIndex < 0 {
				return ErrInvalidLengthOperatorcode
			}
			if postIndex > l {
				return io.ErrUnexpectedEOF
			}
			m.Code = string(dAtA[iNdEx:postIndex])
			iNdEx = postIndex
		case 2:
			if wireType != 2 {
				return fmt.Errorf("proto: wrong wireType = %d for field Organization", wireType)
			}
			var stringLen uint64
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowOperatorcode
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
				return ErrInvalidLengthOperatorcode
			}
			postIndex := iNdEx + intStringLen
			if postIndex < 0 {
				return ErrInvalidLengthOperatorcode
			}
			if postIndex > l {
				return io.ErrUnexpectedEOF
			}
			m.Organization = string(dAtA[iNdEx:postIndex])
			iNdEx = postIndex
		default:
			iNdEx = preIndex
			skippy, err := skipOperatorcode(dAtA[iNdEx:])
			if err != nil {
				return err
			}
			if skippy < 0 {
				return ErrInvalidLengthOperatorcode
			}
			if (iNdEx + skippy) < 0 {
				return ErrInvalidLengthOperatorcode
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
func skipOperatorcode(dAtA []byte) (n int, err error) {
	l := len(dAtA)
	iNdEx := 0
	depth := 0
	for iNdEx < l {
		var wire uint64
		for shift := uint(0); ; shift += 7 {
			if shift >= 64 {
				return 0, ErrIntOverflowOperatorcode
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
					return 0, ErrIntOverflowOperatorcode
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
					return 0, ErrIntOverflowOperatorcode
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
				return 0, ErrInvalidLengthOperatorcode
			}
			iNdEx += length
		case 3:
			depth++
		case 4:
			if depth == 0 {
				return 0, ErrUnexpectedEndOfGroupOperatorcode
			}
			depth--
		case 5:
			iNdEx += 4
		default:
			return 0, fmt.Errorf("proto: illegal wireType %d", wireType)
		}
		if iNdEx < 0 {
			return 0, ErrInvalidLengthOperatorcode
		}
		if depth == 0 {
			return iNdEx, nil
		}
	}
	return 0, io.ErrUnexpectedEOF
}

var (
	ErrInvalidLengthOperatorcode        = fmt.Errorf("proto: negative length found during unmarshaling")
	ErrIntOverflowOperatorcode          = fmt.Errorf("proto: integer overflow")
	ErrUnexpectedEndOfGroupOperatorcode = fmt.Errorf("proto: unexpected end of group")
)
