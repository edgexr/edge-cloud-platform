// Code generated by protoc-gen-gogo. DO NOT EDIT.
// source: operator.proto

package edgeproto

import proto "github.com/gogo/protobuf/proto"
import fmt "fmt"
import math "math"
import _ "github.com/gogo/googleapis/google/api"
import _ "github.com/mobiledgex/edge-cloud/protogen"
import _ "github.com/gogo/protobuf/gogoproto"

import strings "strings"
import reflect "reflect"

import context "golang.org/x/net/context"
import grpc "google.golang.org/grpc"

import "encoding/json"
import "github.com/mobiledgex/edge-cloud/objstore"
import "github.com/mobiledgex/edge-cloud/util"
import "github.com/mobiledgex/edge-cloud/log"

import io "io"

// Reference imports to suppress errors if they are not otherwise used.
var _ = proto.Marshal
var _ = fmt.Errorf
var _ = math.Inf

type OperatorCode struct {
	// Operator code consists of two pars, a mobile network code (MNC)
	// and a mobile country code (MCC). These are strings instead of
	// integers to preserve leading zeros which have meaning.
	// A single operator (like UFGT) may have multiple operator codes
	// across countries and in the same country for different wireless bands.
	MNC string `protobuf:"bytes,1,opt,name=MNC,proto3" json:"MNC,omitempty"`
	MCC string `protobuf:"bytes,2,opt,name=MCC,proto3" json:"MCC,omitempty"`
}

func (m *OperatorCode) Reset()                    { *m = OperatorCode{} }
func (m *OperatorCode) String() string            { return proto.CompactTextString(m) }
func (*OperatorCode) ProtoMessage()               {}
func (*OperatorCode) Descriptor() ([]byte, []int) { return fileDescriptorOperator, []int{0} }

type OperatorKey struct {
	// Company or Organization name of the operator
	Name string `protobuf:"bytes,1,opt,name=name,proto3" json:"name,omitempty"`
}

func (m *OperatorKey) Reset()                    { *m = OperatorKey{} }
func (m *OperatorKey) String() string            { return proto.CompactTextString(m) }
func (*OperatorKey) ProtoMessage()               {}
func (*OperatorKey) Descriptor() ([]byte, []int) { return fileDescriptorOperator, []int{1} }

type Operator struct {
	Fields []string `protobuf:"bytes,1,rep,name=fields" json:"fields,omitempty"`
	// Unique identifier key
	Key OperatorKey `protobuf:"bytes,2,opt,name=key" json:"key"`
}

func (m *Operator) Reset()                    { *m = Operator{} }
func (m *Operator) String() string            { return proto.CompactTextString(m) }
func (*Operator) ProtoMessage()               {}
func (*Operator) Descriptor() ([]byte, []int) { return fileDescriptorOperator, []int{2} }

func init() {
	proto.RegisterType((*OperatorCode)(nil), "edgeproto.OperatorCode")
	proto.RegisterType((*OperatorKey)(nil), "edgeproto.OperatorKey")
	proto.RegisterType((*Operator)(nil), "edgeproto.Operator")
}
func (this *OperatorKey) GoString() string {
	if this == nil {
		return "nil"
	}
	s := make([]string, 0, 5)
	s = append(s, "&edgeproto.OperatorKey{")
	s = append(s, "Name: "+fmt.Sprintf("%#v", this.Name)+",\n")
	s = append(s, "}")
	return strings.Join(s, "")
}
func valueToGoStringOperator(v interface{}, typ string) string {
	rv := reflect.ValueOf(v)
	if rv.IsNil() {
		return "nil"
	}
	pv := reflect.Indirect(rv).Interface()
	return fmt.Sprintf("func(v %v) *%v { return &v } ( %#v )", typ, typ, pv)
}

// Reference imports to suppress errors if they are not otherwise used.
var _ context.Context
var _ grpc.ClientConn

// This is a compile-time assertion to ensure that this generated file
// is compatible with the grpc package it is being compiled against.
const _ = grpc.SupportPackageIsVersion4

// Client API for OperatorApi service

type OperatorApiClient interface {
	CreateOperator(ctx context.Context, in *Operator, opts ...grpc.CallOption) (*Result, error)
	DeleteOperator(ctx context.Context, in *Operator, opts ...grpc.CallOption) (*Result, error)
	UpdateOperator(ctx context.Context, in *Operator, opts ...grpc.CallOption) (*Result, error)
	ShowOperator(ctx context.Context, in *Operator, opts ...grpc.CallOption) (OperatorApi_ShowOperatorClient, error)
}

type operatorApiClient struct {
	cc *grpc.ClientConn
}

func NewOperatorApiClient(cc *grpc.ClientConn) OperatorApiClient {
	return &operatorApiClient{cc}
}

func (c *operatorApiClient) CreateOperator(ctx context.Context, in *Operator, opts ...grpc.CallOption) (*Result, error) {
	out := new(Result)
	err := grpc.Invoke(ctx, "/edgeproto.OperatorApi/CreateOperator", in, out, c.cc, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *operatorApiClient) DeleteOperator(ctx context.Context, in *Operator, opts ...grpc.CallOption) (*Result, error) {
	out := new(Result)
	err := grpc.Invoke(ctx, "/edgeproto.OperatorApi/DeleteOperator", in, out, c.cc, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *operatorApiClient) UpdateOperator(ctx context.Context, in *Operator, opts ...grpc.CallOption) (*Result, error) {
	out := new(Result)
	err := grpc.Invoke(ctx, "/edgeproto.OperatorApi/UpdateOperator", in, out, c.cc, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *operatorApiClient) ShowOperator(ctx context.Context, in *Operator, opts ...grpc.CallOption) (OperatorApi_ShowOperatorClient, error) {
	stream, err := grpc.NewClientStream(ctx, &_OperatorApi_serviceDesc.Streams[0], c.cc, "/edgeproto.OperatorApi/ShowOperator", opts...)
	if err != nil {
		return nil, err
	}
	x := &operatorApiShowOperatorClient{stream}
	if err := x.ClientStream.SendMsg(in); err != nil {
		return nil, err
	}
	if err := x.ClientStream.CloseSend(); err != nil {
		return nil, err
	}
	return x, nil
}

type OperatorApi_ShowOperatorClient interface {
	Recv() (*Operator, error)
	grpc.ClientStream
}

type operatorApiShowOperatorClient struct {
	grpc.ClientStream
}

func (x *operatorApiShowOperatorClient) Recv() (*Operator, error) {
	m := new(Operator)
	if err := x.ClientStream.RecvMsg(m); err != nil {
		return nil, err
	}
	return m, nil
}

// Server API for OperatorApi service

type OperatorApiServer interface {
	CreateOperator(context.Context, *Operator) (*Result, error)
	DeleteOperator(context.Context, *Operator) (*Result, error)
	UpdateOperator(context.Context, *Operator) (*Result, error)
	ShowOperator(*Operator, OperatorApi_ShowOperatorServer) error
}

func RegisterOperatorApiServer(s *grpc.Server, srv OperatorApiServer) {
	s.RegisterService(&_OperatorApi_serviceDesc, srv)
}

func _OperatorApi_CreateOperator_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(Operator)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(OperatorApiServer).CreateOperator(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/edgeproto.OperatorApi/CreateOperator",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(OperatorApiServer).CreateOperator(ctx, req.(*Operator))
	}
	return interceptor(ctx, in, info, handler)
}

func _OperatorApi_DeleteOperator_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(Operator)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(OperatorApiServer).DeleteOperator(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/edgeproto.OperatorApi/DeleteOperator",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(OperatorApiServer).DeleteOperator(ctx, req.(*Operator))
	}
	return interceptor(ctx, in, info, handler)
}

func _OperatorApi_UpdateOperator_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(Operator)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(OperatorApiServer).UpdateOperator(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/edgeproto.OperatorApi/UpdateOperator",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(OperatorApiServer).UpdateOperator(ctx, req.(*Operator))
	}
	return interceptor(ctx, in, info, handler)
}

func _OperatorApi_ShowOperator_Handler(srv interface{}, stream grpc.ServerStream) error {
	m := new(Operator)
	if err := stream.RecvMsg(m); err != nil {
		return err
	}
	return srv.(OperatorApiServer).ShowOperator(m, &operatorApiShowOperatorServer{stream})
}

type OperatorApi_ShowOperatorServer interface {
	Send(*Operator) error
	grpc.ServerStream
}

type operatorApiShowOperatorServer struct {
	grpc.ServerStream
}

func (x *operatorApiShowOperatorServer) Send(m *Operator) error {
	return x.ServerStream.SendMsg(m)
}

var _OperatorApi_serviceDesc = grpc.ServiceDesc{
	ServiceName: "edgeproto.OperatorApi",
	HandlerType: (*OperatorApiServer)(nil),
	Methods: []grpc.MethodDesc{
		{
			MethodName: "CreateOperator",
			Handler:    _OperatorApi_CreateOperator_Handler,
		},
		{
			MethodName: "DeleteOperator",
			Handler:    _OperatorApi_DeleteOperator_Handler,
		},
		{
			MethodName: "UpdateOperator",
			Handler:    _OperatorApi_UpdateOperator_Handler,
		},
	},
	Streams: []grpc.StreamDesc{
		{
			StreamName:    "ShowOperator",
			Handler:       _OperatorApi_ShowOperator_Handler,
			ServerStreams: true,
		},
	},
	Metadata: "operator.proto",
}

func (m *OperatorCode) Marshal() (dAtA []byte, err error) {
	size := m.Size()
	dAtA = make([]byte, size)
	n, err := m.MarshalTo(dAtA)
	if err != nil {
		return nil, err
	}
	return dAtA[:n], nil
}

func (m *OperatorCode) MarshalTo(dAtA []byte) (int, error) {
	var i int
	_ = i
	var l int
	_ = l
	if len(m.MNC) > 0 {
		dAtA[i] = 0xa
		i++
		i = encodeVarintOperator(dAtA, i, uint64(len(m.MNC)))
		i += copy(dAtA[i:], m.MNC)
	}
	if len(m.MCC) > 0 {
		dAtA[i] = 0x12
		i++
		i = encodeVarintOperator(dAtA, i, uint64(len(m.MCC)))
		i += copy(dAtA[i:], m.MCC)
	}
	return i, nil
}

func (m *OperatorKey) Marshal() (dAtA []byte, err error) {
	size := m.Size()
	dAtA = make([]byte, size)
	n, err := m.MarshalTo(dAtA)
	if err != nil {
		return nil, err
	}
	return dAtA[:n], nil
}

func (m *OperatorKey) MarshalTo(dAtA []byte) (int, error) {
	var i int
	_ = i
	var l int
	_ = l
	if len(m.Name) > 0 {
		dAtA[i] = 0xa
		i++
		i = encodeVarintOperator(dAtA, i, uint64(len(m.Name)))
		i += copy(dAtA[i:], m.Name)
	}
	return i, nil
}

func (m *Operator) Marshal() (dAtA []byte, err error) {
	size := m.Size()
	dAtA = make([]byte, size)
	n, err := m.MarshalTo(dAtA)
	if err != nil {
		return nil, err
	}
	return dAtA[:n], nil
}

func (m *Operator) MarshalTo(dAtA []byte) (int, error) {
	var i int
	_ = i
	var l int
	_ = l
	if len(m.Fields) > 0 {
		for _, s := range m.Fields {
			dAtA[i] = 0xa
			i++
			l = len(s)
			for l >= 1<<7 {
				dAtA[i] = uint8(uint64(l)&0x7f | 0x80)
				l >>= 7
				i++
			}
			dAtA[i] = uint8(l)
			i++
			i += copy(dAtA[i:], s)
		}
	}
	dAtA[i] = 0x12
	i++
	i = encodeVarintOperator(dAtA, i, uint64(m.Key.Size()))
	n1, err := m.Key.MarshalTo(dAtA[i:])
	if err != nil {
		return 0, err
	}
	i += n1
	return i, nil
}

func encodeVarintOperator(dAtA []byte, offset int, v uint64) int {
	for v >= 1<<7 {
		dAtA[offset] = uint8(v&0x7f | 0x80)
		v >>= 7
		offset++
	}
	dAtA[offset] = uint8(v)
	return offset + 1
}
func (m *OperatorCode) Matches(filter *OperatorCode) bool {
	if filter == nil {
		return true
	}
	if filter.MNC != "" && filter.MNC != m.MNC {
		return false
	}
	if filter.MCC != "" && filter.MCC != m.MCC {
		return false
	}
	return true
}

func (m *OperatorCode) CopyInFields(src *OperatorCode) {
	m.MNC = src.MNC
	m.MCC = src.MCC
}

func (m *OperatorKey) Matches(filter *OperatorKey) bool {
	if filter == nil {
		return true
	}
	if filter.Name != "" && filter.Name != m.Name {
		return false
	}
	return true
}

func (m *OperatorKey) CopyInFields(src *OperatorKey) {
	m.Name = src.Name
}

func (m *OperatorKey) GetKeyString() string {
	key, err := json.Marshal(m)
	if err != nil {
		log.FatalLog("Failed to marshal OperatorKey key string", "obj", m)
	}
	return string(key)
}

func OperatorKeyStringParse(str string, key *OperatorKey) {
	err := json.Unmarshal([]byte(str), key)
	if err != nil {
		log.FatalLog("Failed to unmarshal OperatorKey key string", "str", str)
	}
}

func (m *Operator) Matches(filter *Operator) bool {
	if filter == nil {
		return true
	}
	if !m.Key.Matches(&filter.Key) {
		return false
	}
	return true
}

const OperatorFieldKey = "2"
const OperatorFieldKeyName = "2.1"

var OperatorAllFields = []string{
	OperatorFieldKeyName,
}

var OperatorAllFieldsMap = map[string]struct{}{
	OperatorFieldKeyName: struct{}{},
}

func (m *Operator) CopyInFields(src *Operator) {
	fmap := MakeFieldMap(src.Fields)
	if _, set := fmap["2"]; set {
		if _, set := fmap["2.1"]; set {
			m.Key.Name = src.Key.Name
		}
	}
}

func (s *Operator) HasFields() bool {
	return true
}

type OperatorStore struct {
	objstore objstore.ObjStore
}

func NewOperatorStore(objstore objstore.ObjStore) OperatorStore {
	return OperatorStore{objstore: objstore}
}

func (s *OperatorStore) Create(m *Operator, wait func(int64)) (*Result, error) {
	err := m.Validate(OperatorAllFieldsMap)
	if err != nil {
		return nil, err
	}
	key := objstore.DbKeyString(m.GetKey())
	val, err := json.Marshal(m)
	if err != nil {
		return nil, err
	}
	rev, err := s.objstore.Create(key, string(val))
	if err != nil {
		return nil, err
	}
	if wait != nil {
		wait(rev)
	}
	return &Result{}, err
}

func (s *OperatorStore) Update(m *Operator, wait func(int64)) (*Result, error) {
	fmap := MakeFieldMap(m.Fields)
	err := m.Validate(fmap)
	if err != nil {
		return nil, err
	}
	key := objstore.DbKeyString(m.GetKey())
	var vers int64 = 0
	curBytes, vers, err := s.objstore.Get(key)
	if err != nil {
		return nil, err
	}
	var cur Operator
	err = json.Unmarshal(curBytes, &cur)
	if err != nil {
		return nil, err
	}
	cur.CopyInFields(m)
	// never save fields
	cur.Fields = nil
	val, err := json.Marshal(cur)
	if err != nil {
		return nil, err
	}
	rev, err := s.objstore.Update(key, string(val), vers)
	if err != nil {
		return nil, err
	}
	if wait != nil {
		wait(rev)
	}
	return &Result{}, err
}

func (s *OperatorStore) Delete(m *Operator, wait func(int64)) (*Result, error) {
	err := m.GetKey().Validate()
	if err != nil {
		return nil, err
	}
	key := objstore.DbKeyString(m.GetKey())
	rev, err := s.objstore.Delete(key)
	if err != nil {
		return nil, err
	}
	if wait != nil {
		wait(rev)
	}
	return &Result{}, err
}

type OperatorCb func(m *Operator) error

func (s *OperatorStore) LoadAll(cb OperatorCb) error {
	loadkey := objstore.DbKeyPrefixString(&OperatorKey{})
	err := s.objstore.List(loadkey, func(key, val []byte, rev int64) error {
		var obj Operator
		err := json.Unmarshal(val, &obj)
		if err != nil {
			log.WarnLog("Failed to parse Operator data", "val", string(val))
			return nil
		}
		err = cb(&obj)
		if err != nil {
			return err
		}
		return nil
	})
	return err
}

func (s *OperatorStore) LoadOne(key string) (*Operator, int64, error) {
	val, rev, err := s.objstore.Get(key)
	if err != nil {
		return nil, 0, err
	}
	var obj Operator
	err = json.Unmarshal(val, &obj)
	if err != nil {
		log.DebugLog(log.DebugLevelApi, "Failed to parse Operator data", "val", string(val))
		return nil, 0, err
	}
	return &obj, rev, nil
}

// OperatorCache caches Operator objects in memory in a hash table
// and keeps them in sync with the database.
type OperatorCache struct {
	Objs      map[OperatorKey]*Operator
	Mux       util.Mutex
	List      map[OperatorKey]struct{}
	NotifyCb  func(obj *OperatorKey)
	UpdatedCb func(old *Operator, new *Operator)
}

func NewOperatorCache() *OperatorCache {
	cache := OperatorCache{}
	InitOperatorCache(&cache)
	return &cache
}

func InitOperatorCache(cache *OperatorCache) {
	cache.Objs = make(map[OperatorKey]*Operator)
}

func (c *OperatorCache) Get(key *OperatorKey, valbuf *Operator) bool {
	c.Mux.Lock()
	defer c.Mux.Unlock()
	inst, found := c.Objs[*key]
	if found {
		*valbuf = *inst
	}
	return found
}

func (c *OperatorCache) HasKey(key *OperatorKey) bool {
	c.Mux.Lock()
	defer c.Mux.Unlock()
	_, found := c.Objs[*key]
	return found
}

func (c *OperatorCache) GetAllKeys(keys map[OperatorKey]struct{}) {
	c.Mux.Lock()
	defer c.Mux.Unlock()
	for key, _ := range c.Objs {
		keys[key] = struct{}{}
	}
}

func (c *OperatorCache) Update(in *Operator, rev int64) {
	c.Mux.Lock()
	if c.UpdatedCb != nil {
		old := c.Objs[in.Key]
		new := &Operator{}
		*new = *in
		defer c.UpdatedCb(old, new)
	}
	c.Objs[in.Key] = in
	log.DebugLog(log.DebugLevelApi, "SyncUpdate", "obj", in, "rev", rev)
	c.Mux.Unlock()
	if c.NotifyCb != nil {
		c.NotifyCb(&in.Key)
	}
}

func (c *OperatorCache) Delete(in *Operator, rev int64) {
	c.Mux.Lock()
	delete(c.Objs, in.Key)
	log.DebugLog(log.DebugLevelApi, "SyncUpdate", "key", in.Key, "rev", rev)
	c.Mux.Unlock()
	if c.NotifyCb != nil {
		c.NotifyCb(&in.Key)
	}
}

func (c *OperatorCache) Prune(validKeys map[OperatorKey]struct{}) {
	c.Mux.Lock()
	defer c.Mux.Unlock()
	for key, _ := range c.Objs {
		if _, ok := validKeys[key]; !ok {
			delete(c.Objs, key)
			if c.NotifyCb != nil {
				c.NotifyCb(&key)
			}
		}
	}
}

func (c *OperatorCache) Show(filter *Operator, cb func(ret *Operator) error) error {
	log.DebugLog(log.DebugLevelApi, "Show Operator", "count", len(c.Objs))
	c.Mux.Lock()
	defer c.Mux.Unlock()
	for _, obj := range c.Objs {
		if !obj.Matches(filter) {
			continue
		}
		log.DebugLog(log.DebugLevelApi, "Show Operator", "obj", obj)
		err := cb(obj)
		if err != nil {
			return err
		}
	}
	return nil
}

func (c *OperatorCache) SetNotifyCb(fn func(obj *OperatorKey)) {
	c.NotifyCb = fn
}

func (c *OperatorCache) SetUpdatedCb(fn func(old *Operator, new *Operator)) {
	c.UpdatedCb = fn
}
func (c *OperatorCache) SyncUpdate(key, val []byte, rev int64) {
	obj := Operator{}
	err := json.Unmarshal(val, &obj)
	if err != nil {
		log.WarnLog("Failed to parse Operator data", "val", string(val))
		return
	}
	c.Update(&obj, rev)
	c.Mux.Lock()
	if c.List != nil {
		c.List[obj.Key] = struct{}{}
	}
	c.Mux.Unlock()
}

func (c *OperatorCache) SyncDelete(key []byte, rev int64) {
	obj := Operator{}
	keystr := objstore.DbKeyPrefixRemove(string(key))
	OperatorKeyStringParse(keystr, &obj.Key)
	c.Delete(&obj, rev)
}

func (c *OperatorCache) SyncListStart() {
	c.List = make(map[OperatorKey]struct{})
}

func (c *OperatorCache) SyncListEnd() {
	deleted := make(map[OperatorKey]struct{})
	c.Mux.Lock()
	for key, _ := range c.Objs {
		if _, found := c.List[key]; !found {
			delete(c.Objs, key)
			deleted[key] = struct{}{}
		}
	}
	c.List = nil
	c.Mux.Unlock()
	if c.NotifyCb != nil {
		for key, _ := range deleted {
			c.NotifyCb(&key)
		}
	}
}

func (m *Operator) GetKey() *OperatorKey {
	return &m.Key
}

func (m *OperatorCode) Size() (n int) {
	var l int
	_ = l
	l = len(m.MNC)
	if l > 0 {
		n += 1 + l + sovOperator(uint64(l))
	}
	l = len(m.MCC)
	if l > 0 {
		n += 1 + l + sovOperator(uint64(l))
	}
	return n
}

func (m *OperatorKey) Size() (n int) {
	var l int
	_ = l
	l = len(m.Name)
	if l > 0 {
		n += 1 + l + sovOperator(uint64(l))
	}
	return n
}

func (m *Operator) Size() (n int) {
	var l int
	_ = l
	if len(m.Fields) > 0 {
		for _, s := range m.Fields {
			l = len(s)
			n += 1 + l + sovOperator(uint64(l))
		}
	}
	l = m.Key.Size()
	n += 1 + l + sovOperator(uint64(l))
	return n
}

func sovOperator(x uint64) (n int) {
	for {
		n++
		x >>= 7
		if x == 0 {
			break
		}
	}
	return n
}
func sozOperator(x uint64) (n int) {
	return sovOperator(uint64((x << 1) ^ uint64((int64(x) >> 63))))
}
func (m *OperatorCode) Unmarshal(dAtA []byte) error {
	l := len(dAtA)
	iNdEx := 0
	for iNdEx < l {
		preIndex := iNdEx
		var wire uint64
		for shift := uint(0); ; shift += 7 {
			if shift >= 64 {
				return ErrIntOverflowOperator
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
			return fmt.Errorf("proto: OperatorCode: wiretype end group for non-group")
		}
		if fieldNum <= 0 {
			return fmt.Errorf("proto: OperatorCode: illegal tag %d (wire type %d)", fieldNum, wire)
		}
		switch fieldNum {
		case 1:
			if wireType != 2 {
				return fmt.Errorf("proto: wrong wireType = %d for field MNC", wireType)
			}
			var stringLen uint64
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowOperator
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
				return ErrInvalidLengthOperator
			}
			postIndex := iNdEx + intStringLen
			if postIndex > l {
				return io.ErrUnexpectedEOF
			}
			m.MNC = string(dAtA[iNdEx:postIndex])
			iNdEx = postIndex
		case 2:
			if wireType != 2 {
				return fmt.Errorf("proto: wrong wireType = %d for field MCC", wireType)
			}
			var stringLen uint64
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowOperator
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
				return ErrInvalidLengthOperator
			}
			postIndex := iNdEx + intStringLen
			if postIndex > l {
				return io.ErrUnexpectedEOF
			}
			m.MCC = string(dAtA[iNdEx:postIndex])
			iNdEx = postIndex
		default:
			iNdEx = preIndex
			skippy, err := skipOperator(dAtA[iNdEx:])
			if err != nil {
				return err
			}
			if skippy < 0 {
				return ErrInvalidLengthOperator
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
func (m *OperatorKey) Unmarshal(dAtA []byte) error {
	l := len(dAtA)
	iNdEx := 0
	for iNdEx < l {
		preIndex := iNdEx
		var wire uint64
		for shift := uint(0); ; shift += 7 {
			if shift >= 64 {
				return ErrIntOverflowOperator
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
			return fmt.Errorf("proto: OperatorKey: wiretype end group for non-group")
		}
		if fieldNum <= 0 {
			return fmt.Errorf("proto: OperatorKey: illegal tag %d (wire type %d)", fieldNum, wire)
		}
		switch fieldNum {
		case 1:
			if wireType != 2 {
				return fmt.Errorf("proto: wrong wireType = %d for field Name", wireType)
			}
			var stringLen uint64
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowOperator
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
				return ErrInvalidLengthOperator
			}
			postIndex := iNdEx + intStringLen
			if postIndex > l {
				return io.ErrUnexpectedEOF
			}
			m.Name = string(dAtA[iNdEx:postIndex])
			iNdEx = postIndex
		default:
			iNdEx = preIndex
			skippy, err := skipOperator(dAtA[iNdEx:])
			if err != nil {
				return err
			}
			if skippy < 0 {
				return ErrInvalidLengthOperator
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
func (m *Operator) Unmarshal(dAtA []byte) error {
	l := len(dAtA)
	iNdEx := 0
	for iNdEx < l {
		preIndex := iNdEx
		var wire uint64
		for shift := uint(0); ; shift += 7 {
			if shift >= 64 {
				return ErrIntOverflowOperator
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
			return fmt.Errorf("proto: Operator: wiretype end group for non-group")
		}
		if fieldNum <= 0 {
			return fmt.Errorf("proto: Operator: illegal tag %d (wire type %d)", fieldNum, wire)
		}
		switch fieldNum {
		case 1:
			if wireType != 2 {
				return fmt.Errorf("proto: wrong wireType = %d for field Fields", wireType)
			}
			var stringLen uint64
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowOperator
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
				return ErrInvalidLengthOperator
			}
			postIndex := iNdEx + intStringLen
			if postIndex > l {
				return io.ErrUnexpectedEOF
			}
			m.Fields = append(m.Fields, string(dAtA[iNdEx:postIndex]))
			iNdEx = postIndex
		case 2:
			if wireType != 2 {
				return fmt.Errorf("proto: wrong wireType = %d for field Key", wireType)
			}
			var msglen int
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowOperator
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
				return ErrInvalidLengthOperator
			}
			postIndex := iNdEx + msglen
			if postIndex > l {
				return io.ErrUnexpectedEOF
			}
			if err := m.Key.Unmarshal(dAtA[iNdEx:postIndex]); err != nil {
				return err
			}
			iNdEx = postIndex
		default:
			iNdEx = preIndex
			skippy, err := skipOperator(dAtA[iNdEx:])
			if err != nil {
				return err
			}
			if skippy < 0 {
				return ErrInvalidLengthOperator
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
func skipOperator(dAtA []byte) (n int, err error) {
	l := len(dAtA)
	iNdEx := 0
	for iNdEx < l {
		var wire uint64
		for shift := uint(0); ; shift += 7 {
			if shift >= 64 {
				return 0, ErrIntOverflowOperator
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
					return 0, ErrIntOverflowOperator
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
					return 0, ErrIntOverflowOperator
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
				return 0, ErrInvalidLengthOperator
			}
			return iNdEx, nil
		case 3:
			for {
				var innerWire uint64
				var start int = iNdEx
				for shift := uint(0); ; shift += 7 {
					if shift >= 64 {
						return 0, ErrIntOverflowOperator
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
				next, err := skipOperator(dAtA[start:])
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
	ErrInvalidLengthOperator = fmt.Errorf("proto: negative length found during unmarshaling")
	ErrIntOverflowOperator   = fmt.Errorf("proto: integer overflow")
)

func init() { proto.RegisterFile("operator.proto", fileDescriptorOperator) }

var fileDescriptorOperator = []byte{
	// 406 bytes of a gzipped FileDescriptorProto
	0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0xff, 0xa4, 0x91, 0xcf, 0x6a, 0xe2, 0x50,
	0x14, 0xc6, 0xbd, 0x2a, 0x32, 0x5e, 0x83, 0x38, 0x91, 0x91, 0x8c, 0x33, 0x44, 0xc9, 0x4a, 0x06,
	0xcc, 0x1d, 0xec, 0x46, 0xdc, 0xd5, 0x74, 0x57, 0xda, 0x42, 0x8a, 0xfb, 0x26, 0xe6, 0x1a, 0x43,
	0x63, 0x4e, 0xc8, 0x1f, 0xac, 0xbb, 0xd2, 0x57, 0xe8, 0x0b, 0xf4, 0x11, 0xfa, 0x18, 0x2e, 0x0b,
	0xdd, 0x97, 0x56, 0xba, 0x68, 0x77, 0x05, 0xbb, 0xe8, 0xb2, 0xe4, 0x26, 0xda, 0x20, 0xd2, 0x8d,
	0x9b, 0xf0, 0x9d, 0xc3, 0xf7, 0xfd, 0xbe, 0xc3, 0x0d, 0x2e, 0x83, 0x4b, 0x3d, 0x2d, 0x00, 0x4f,
	0x76, 0x3d, 0x08, 0x80, 0x2f, 0x52, 0xc3, 0xa4, 0x4c, 0xd6, 0xff, 0x9a, 0x00, 0xa6, 0x4d, 0x89,
	0xe6, 0x5a, 0x44, 0x73, 0x1c, 0x08, 0xb4, 0xc0, 0x02, 0xc7, 0x8f, 0x8d, 0xf5, 0xae, 0x69, 0x05,
	0xe3, 0x50, 0x97, 0x87, 0x30, 0x21, 0x13, 0xd0, 0x2d, 0x3b, 0x0a, 0x5e, 0x90, 0xe8, 0xdb, 0x1e,
	0xda, 0x10, 0x1a, 0x84, 0xf9, 0x4c, 0xea, 0xac, 0x45, 0x92, 0xe4, 0x3c, 0xea, 0x87, 0x76, 0x90,
	0x4c, 0xed, 0x14, 0xc7, 0x04, 0x13, 0x62, 0xb7, 0x1e, 0x8e, 0xd8, 0xc4, 0x06, 0xa6, 0x62, 0xbb,
	0xd4, 0xc5, 0xdc, 0x49, 0x72, 0xb1, 0x02, 0x06, 0xe5, 0x2b, 0x38, 0x77, 0x74, 0xac, 0x08, 0xa8,
	0x89, 0x5a, 0x45, 0x35, 0x92, 0x6c, 0xa3, 0x28, 0x42, 0x36, 0xd9, 0x28, 0x4a, 0x2f, 0xff, 0xb2,
	0x14, 0x90, 0x44, 0x70, 0x69, 0x95, 0x3c, 0xa4, 0x33, 0x9e, 0xc7, 0x79, 0x47, 0x9b, 0xd0, 0x24,
	0xc9, 0x74, 0x8f, 0x8b, 0x8c, 0x1f, 0x4b, 0x01, 0xdd, 0xde, 0x34, 0x90, 0x74, 0x86, 0x7f, 0xac,
	0x02, 0x7c, 0x0d, 0x17, 0x46, 0x16, 0xb5, 0x0d, 0x5f, 0x40, 0xcd, 0x5c, 0xab, 0xa8, 0x26, 0x13,
	0x2f, 0xe3, 0xdc, 0x39, 0x9d, 0xb1, 0xb2, 0x52, 0xa7, 0x26, 0xaf, 0x1f, 0x4f, 0x4e, 0x55, 0xf5,
	0xf3, 0xf3, 0x87, 0x46, 0x46, 0x8d, 0x8c, 0x71, 0xc3, 0xdb, 0x52, 0x40, 0x97, 0xef, 0x02, 0xea,
	0xbc, 0x66, 0xbf, 0x6e, 0xda, 0x77, 0x2d, 0x7e, 0x80, 0xcb, 0x8a, 0x47, 0xb5, 0x80, 0xae, 0x7b,
	0xab, 0x5b, 0x90, 0xf5, 0x9f, 0xa9, 0xa5, 0xca, 0xde, 0x52, 0xfa, 0x73, 0x75, 0xff, 0x7c, 0x9d,
	0xfd, 0x25, 0x55, 0xc8, 0x90, 0x01, 0xc8, 0xea, 0xb7, 0xf6, 0xd0, 0xbf, 0x08, 0x7b, 0x40, 0x6d,
	0xba, 0x13, 0xd6, 0x60, 0x80, 0x4d, 0xec, 0xc0, 0x35, 0x76, 0xbb, 0x36, 0x64, 0x80, 0x0d, 0x2c,
	0x77, 0x3a, 0x86, 0xe9, 0xf7, 0xd0, 0x6d, 0x4b, 0xe9, 0x37, 0xc3, 0x56, 0xa5, 0x32, 0xf1, 0xc7,
	0x30, 0x4d, 0x43, 0xff, 0xa3, 0x7e, 0x65, 0xfe, 0x24, 0x66, 0xe6, 0x0b, 0x11, 0xdd, 0x2d, 0x44,
	0xf4, 0xb8, 0x10, 0x91, 0x5e, 0x60, 0xf1, 0xbd, 0xcf, 0x00, 0x00, 0x00, 0xff, 0xff, 0x46, 0x40,
	0x8a, 0x44, 0x03, 0x03, 0x00, 0x00,
}
