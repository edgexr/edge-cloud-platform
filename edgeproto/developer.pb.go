// Code generated by protoc-gen-gogo. DO NOT EDIT.
// source: developer.proto

package edgeproto

import proto "github.com/gogo/protobuf/proto"
import fmt "fmt"
import math "math"
import _ "github.com/gogo/googleapis/google/api"
import _ "github.com/mobiledgex/edge-cloud/protogen"
import _ "github.com/mobiledgex/edge-cloud/protoc-gen-cmd/protocmd"
import _ "github.com/gogo/protobuf/gogoproto"

import strings "strings"
import reflect "reflect"

import context "golang.org/x/net/context"
import grpc "google.golang.org/grpc"

import "encoding/json"
import "github.com/mobiledgex/edge-cloud/objstore"
import "github.com/coreos/etcd/clientv3/concurrency"
import "github.com/mobiledgex/edge-cloud/util"
import "github.com/mobiledgex/edge-cloud/log"

import io "io"

// Reference imports to suppress errors if they are not otherwise used.
var _ = proto.Marshal
var _ = fmt.Errorf
var _ = math.Inf

// DeveloperKey uniquely identifies a Developer
type DeveloperKey struct {
	// Organization or Company Name that a Developer is part of
	Name string `protobuf:"bytes,2,opt,name=name,proto3" json:"name,omitempty"`
}

func (m *DeveloperKey) Reset()                    { *m = DeveloperKey{} }
func (m *DeveloperKey) String() string            { return proto.CompactTextString(m) }
func (*DeveloperKey) ProtoMessage()               {}
func (*DeveloperKey) Descriptor() ([]byte, []int) { return fileDescriptorDeveloper, []int{0} }

// Developer is defined as the consumer of edge computing resources to manage and deploy Apps
type Developer struct {
	// Fields are used for the Update API to specify which fields to apply
	Fields []string `protobuf:"bytes,1,rep,name=fields" json:"fields,omitempty"`
	// Unique identifier key
	Key DeveloperKey `protobuf:"bytes,2,opt,name=key" json:"key"`
}

func (m *Developer) Reset()                    { *m = Developer{} }
func (m *Developer) String() string            { return proto.CompactTextString(m) }
func (*Developer) ProtoMessage()               {}
func (*Developer) Descriptor() ([]byte, []int) { return fileDescriptorDeveloper, []int{1} }

func init() {
	proto.RegisterType((*DeveloperKey)(nil), "edgeproto.DeveloperKey")
	proto.RegisterType((*Developer)(nil), "edgeproto.Developer")
}
func (this *DeveloperKey) GoString() string {
	if this == nil {
		return "nil"
	}
	s := make([]string, 0, 5)
	s = append(s, "&edgeproto.DeveloperKey{")
	s = append(s, "Name: "+fmt.Sprintf("%#v", this.Name)+",\n")
	s = append(s, "}")
	return strings.Join(s, "")
}
func valueToGoStringDeveloper(v interface{}, typ string) string {
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

// Client API for DeveloperApi service

type DeveloperApiClient interface {
	// Create a Developer
	CreateDeveloper(ctx context.Context, in *Developer, opts ...grpc.CallOption) (*Result, error)
	// Delete a Developer
	DeleteDeveloper(ctx context.Context, in *Developer, opts ...grpc.CallOption) (*Result, error)
	// Update a Developer
	UpdateDeveloper(ctx context.Context, in *Developer, opts ...grpc.CallOption) (*Result, error)
	// Show Developers
	ShowDeveloper(ctx context.Context, in *Developer, opts ...grpc.CallOption) (DeveloperApi_ShowDeveloperClient, error)
}

type developerApiClient struct {
	cc *grpc.ClientConn
}

func NewDeveloperApiClient(cc *grpc.ClientConn) DeveloperApiClient {
	return &developerApiClient{cc}
}

func (c *developerApiClient) CreateDeveloper(ctx context.Context, in *Developer, opts ...grpc.CallOption) (*Result, error) {
	out := new(Result)
	err := grpc.Invoke(ctx, "/edgeproto.DeveloperApi/CreateDeveloper", in, out, c.cc, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *developerApiClient) DeleteDeveloper(ctx context.Context, in *Developer, opts ...grpc.CallOption) (*Result, error) {
	out := new(Result)
	err := grpc.Invoke(ctx, "/edgeproto.DeveloperApi/DeleteDeveloper", in, out, c.cc, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *developerApiClient) UpdateDeveloper(ctx context.Context, in *Developer, opts ...grpc.CallOption) (*Result, error) {
	out := new(Result)
	err := grpc.Invoke(ctx, "/edgeproto.DeveloperApi/UpdateDeveloper", in, out, c.cc, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *developerApiClient) ShowDeveloper(ctx context.Context, in *Developer, opts ...grpc.CallOption) (DeveloperApi_ShowDeveloperClient, error) {
	stream, err := grpc.NewClientStream(ctx, &_DeveloperApi_serviceDesc.Streams[0], c.cc, "/edgeproto.DeveloperApi/ShowDeveloper", opts...)
	if err != nil {
		return nil, err
	}
	x := &developerApiShowDeveloperClient{stream}
	if err := x.ClientStream.SendMsg(in); err != nil {
		return nil, err
	}
	if err := x.ClientStream.CloseSend(); err != nil {
		return nil, err
	}
	return x, nil
}

type DeveloperApi_ShowDeveloperClient interface {
	Recv() (*Developer, error)
	grpc.ClientStream
}

type developerApiShowDeveloperClient struct {
	grpc.ClientStream
}

func (x *developerApiShowDeveloperClient) Recv() (*Developer, error) {
	m := new(Developer)
	if err := x.ClientStream.RecvMsg(m); err != nil {
		return nil, err
	}
	return m, nil
}

// Server API for DeveloperApi service

type DeveloperApiServer interface {
	// Create a Developer
	CreateDeveloper(context.Context, *Developer) (*Result, error)
	// Delete a Developer
	DeleteDeveloper(context.Context, *Developer) (*Result, error)
	// Update a Developer
	UpdateDeveloper(context.Context, *Developer) (*Result, error)
	// Show Developers
	ShowDeveloper(*Developer, DeveloperApi_ShowDeveloperServer) error
}

func RegisterDeveloperApiServer(s *grpc.Server, srv DeveloperApiServer) {
	s.RegisterService(&_DeveloperApi_serviceDesc, srv)
}

func _DeveloperApi_CreateDeveloper_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(Developer)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(DeveloperApiServer).CreateDeveloper(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/edgeproto.DeveloperApi/CreateDeveloper",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(DeveloperApiServer).CreateDeveloper(ctx, req.(*Developer))
	}
	return interceptor(ctx, in, info, handler)
}

func _DeveloperApi_DeleteDeveloper_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(Developer)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(DeveloperApiServer).DeleteDeveloper(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/edgeproto.DeveloperApi/DeleteDeveloper",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(DeveloperApiServer).DeleteDeveloper(ctx, req.(*Developer))
	}
	return interceptor(ctx, in, info, handler)
}

func _DeveloperApi_UpdateDeveloper_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(Developer)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(DeveloperApiServer).UpdateDeveloper(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/edgeproto.DeveloperApi/UpdateDeveloper",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(DeveloperApiServer).UpdateDeveloper(ctx, req.(*Developer))
	}
	return interceptor(ctx, in, info, handler)
}

func _DeveloperApi_ShowDeveloper_Handler(srv interface{}, stream grpc.ServerStream) error {
	m := new(Developer)
	if err := stream.RecvMsg(m); err != nil {
		return err
	}
	return srv.(DeveloperApiServer).ShowDeveloper(m, &developerApiShowDeveloperServer{stream})
}

type DeveloperApi_ShowDeveloperServer interface {
	Send(*Developer) error
	grpc.ServerStream
}

type developerApiShowDeveloperServer struct {
	grpc.ServerStream
}

func (x *developerApiShowDeveloperServer) Send(m *Developer) error {
	return x.ServerStream.SendMsg(m)
}

var _DeveloperApi_serviceDesc = grpc.ServiceDesc{
	ServiceName: "edgeproto.DeveloperApi",
	HandlerType: (*DeveloperApiServer)(nil),
	Methods: []grpc.MethodDesc{
		{
			MethodName: "CreateDeveloper",
			Handler:    _DeveloperApi_CreateDeveloper_Handler,
		},
		{
			MethodName: "DeleteDeveloper",
			Handler:    _DeveloperApi_DeleteDeveloper_Handler,
		},
		{
			MethodName: "UpdateDeveloper",
			Handler:    _DeveloperApi_UpdateDeveloper_Handler,
		},
	},
	Streams: []grpc.StreamDesc{
		{
			StreamName:    "ShowDeveloper",
			Handler:       _DeveloperApi_ShowDeveloper_Handler,
			ServerStreams: true,
		},
	},
	Metadata: "developer.proto",
}

func (m *DeveloperKey) Marshal() (dAtA []byte, err error) {
	size := m.Size()
	dAtA = make([]byte, size)
	n, err := m.MarshalTo(dAtA)
	if err != nil {
		return nil, err
	}
	return dAtA[:n], nil
}

func (m *DeveloperKey) MarshalTo(dAtA []byte) (int, error) {
	var i int
	_ = i
	var l int
	_ = l
	if len(m.Name) > 0 {
		dAtA[i] = 0x12
		i++
		i = encodeVarintDeveloper(dAtA, i, uint64(len(m.Name)))
		i += copy(dAtA[i:], m.Name)
	}
	return i, nil
}

func (m *Developer) Marshal() (dAtA []byte, err error) {
	size := m.Size()
	dAtA = make([]byte, size)
	n, err := m.MarshalTo(dAtA)
	if err != nil {
		return nil, err
	}
	return dAtA[:n], nil
}

func (m *Developer) MarshalTo(dAtA []byte) (int, error) {
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
	i = encodeVarintDeveloper(dAtA, i, uint64(m.Key.Size()))
	n1, err := m.Key.MarshalTo(dAtA[i:])
	if err != nil {
		return 0, err
	}
	i += n1
	return i, nil
}

func encodeVarintDeveloper(dAtA []byte, offset int, v uint64) int {
	for v >= 1<<7 {
		dAtA[offset] = uint8(v&0x7f | 0x80)
		v >>= 7
		offset++
	}
	dAtA[offset] = uint8(v)
	return offset + 1
}
func (m *DeveloperKey) Matches(o *DeveloperKey, fopts ...MatchOpt) bool {
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

func (m *DeveloperKey) CopyInFields(src *DeveloperKey) {
	m.Name = src.Name
}

func (m *DeveloperKey) GetKeyString() string {
	key, err := json.Marshal(m)
	if err != nil {
		log.FatalLog("Failed to marshal DeveloperKey key string", "obj", m)
	}
	return string(key)
}

func DeveloperKeyStringParse(str string, key *DeveloperKey) {
	err := json.Unmarshal([]byte(str), key)
	if err != nil {
		log.FatalLog("Failed to unmarshal DeveloperKey key string", "str", str)
	}
}

// Helper method to check that enums have valid values
func (m *DeveloperKey) ValidateEnums() error {
	return nil
}

func (m *Developer) Matches(o *Developer, fopts ...MatchOpt) bool {
	opts := MatchOptions{}
	applyMatchOptions(&opts, fopts...)
	if o == nil {
		if opts.Filter {
			return true
		}
		return false
	}
	if !m.Key.Matches(&o.Key, fopts...) {
		return false
	}
	return true
}

const DeveloperFieldKey = "2"
const DeveloperFieldKeyName = "2.2"

var DeveloperAllFields = []string{
	DeveloperFieldKeyName,
}

var DeveloperAllFieldsMap = map[string]struct{}{
	DeveloperFieldKeyName: struct{}{},
}

func (m *Developer) DiffFields(o *Developer, fields map[string]struct{}) {
	if m.Key.Name != o.Key.Name {
		fields[DeveloperFieldKeyName] = struct{}{}
		fields[DeveloperFieldKey] = struct{}{}
	}
}

func (m *Developer) CopyInFields(src *Developer) {
	fmap := MakeFieldMap(src.Fields)
	if _, set := fmap["2"]; set {
		if _, set := fmap["2.2"]; set {
			m.Key.Name = src.Key.Name
		}
	}
}

func (s *Developer) HasFields() bool {
	return true
}

type DeveloperStore struct {
	kvstore objstore.KVStore
}

func NewDeveloperStore(kvstore objstore.KVStore) DeveloperStore {
	return DeveloperStore{kvstore: kvstore}
}

func (s *DeveloperStore) Create(m *Developer, wait func(int64)) (*Result, error) {
	err := m.Validate(DeveloperAllFieldsMap)
	if err != nil {
		return nil, err
	}
	key := objstore.DbKeyString("Developer", m.GetKey())
	val, err := json.Marshal(m)
	if err != nil {
		return nil, err
	}
	rev, err := s.kvstore.Create(key, string(val))
	if err != nil {
		return nil, err
	}
	if wait != nil {
		wait(rev)
	}
	return &Result{}, err
}

func (s *DeveloperStore) Update(m *Developer, wait func(int64)) (*Result, error) {
	fmap := MakeFieldMap(m.Fields)
	err := m.Validate(fmap)
	if err != nil {
		return nil, err
	}
	key := objstore.DbKeyString("Developer", m.GetKey())
	var vers int64 = 0
	curBytes, vers, _, err := s.kvstore.Get(key)
	if err != nil {
		return nil, err
	}
	var cur Developer
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
	rev, err := s.kvstore.Update(key, string(val), vers)
	if err != nil {
		return nil, err
	}
	if wait != nil {
		wait(rev)
	}
	return &Result{}, err
}

func (s *DeveloperStore) Put(m *Developer, wait func(int64), ops ...objstore.KVOp) (*Result, error) {
	fmap := MakeFieldMap(m.Fields)
	err := m.Validate(fmap)
	if err != nil {
		return nil, err
	}
	key := objstore.DbKeyString("Developer", m.GetKey())
	var val []byte
	curBytes, _, _, err := s.kvstore.Get(key)
	if err == nil {
		var cur Developer
		err = json.Unmarshal(curBytes, &cur)
		if err != nil {
			return nil, err
		}
		cur.CopyInFields(m)
		// never save fields
		cur.Fields = nil
		val, err = json.Marshal(cur)
	} else {
		m.Fields = nil
		val, err = json.Marshal(m)
	}
	if err != nil {
		return nil, err
	}
	rev, err := s.kvstore.Put(key, string(val), ops...)
	if err != nil {
		return nil, err
	}
	if wait != nil {
		wait(rev)
	}
	return &Result{}, err
}

func (s *DeveloperStore) Delete(m *Developer, wait func(int64)) (*Result, error) {
	err := m.GetKey().Validate()
	if err != nil {
		return nil, err
	}
	key := objstore.DbKeyString("Developer", m.GetKey())
	rev, err := s.kvstore.Delete(key)
	if err != nil {
		return nil, err
	}
	if wait != nil {
		wait(rev)
	}
	return &Result{}, err
}

func (s *DeveloperStore) LoadOne(key string) (*Developer, int64, error) {
	val, rev, _, err := s.kvstore.Get(key)
	if err != nil {
		return nil, 0, err
	}
	var obj Developer
	err = json.Unmarshal(val, &obj)
	if err != nil {
		log.DebugLog(log.DebugLevelApi, "Failed to parse Developer data", "val", string(val))
		return nil, 0, err
	}
	return &obj, rev, nil
}

func (s *DeveloperStore) STMGet(stm concurrency.STM, key *DeveloperKey, buf *Developer) bool {
	keystr := objstore.DbKeyString("Developer", key)
	valstr := stm.Get(keystr)
	if valstr == "" {
		return false
	}
	if buf != nil {
		err := json.Unmarshal([]byte(valstr), buf)
		if err != nil {
			return false
		}
	}
	return true
}

func (s *DeveloperStore) STMPut(stm concurrency.STM, obj *Developer, ops ...objstore.KVOp) {
	keystr := objstore.DbKeyString("Developer", obj.GetKey())
	val, err := json.Marshal(obj)
	if err != nil {
		log.InfoLog("Developer json marsahal failed", "obj", obj, "err", err)
	}
	v3opts := GetSTMOpts(ops...)
	stm.Put(keystr, string(val), v3opts...)
}

func (s *DeveloperStore) STMDel(stm concurrency.STM, key *DeveloperKey) {
	keystr := objstore.DbKeyString("Developer", key)
	stm.Del(keystr)
}

type DeveloperKeyWatcher struct {
	cb func()
}

// DeveloperCache caches Developer objects in memory in a hash table
// and keeps them in sync with the database.
type DeveloperCache struct {
	Objs        map[DeveloperKey]*Developer
	Mux         util.Mutex
	List        map[DeveloperKey]struct{}
	NotifyCb    func(obj *DeveloperKey, old *Developer)
	UpdatedCb   func(old *Developer, new *Developer)
	KeyWatchers map[DeveloperKey][]*DeveloperKeyWatcher
}

func NewDeveloperCache() *DeveloperCache {
	cache := DeveloperCache{}
	InitDeveloperCache(&cache)
	return &cache
}

func InitDeveloperCache(cache *DeveloperCache) {
	cache.Objs = make(map[DeveloperKey]*Developer)
	cache.KeyWatchers = make(map[DeveloperKey][]*DeveloperKeyWatcher)
}

func (c *DeveloperCache) GetTypeString() string {
	return "Developer"
}

func (c *DeveloperCache) Get(key *DeveloperKey, valbuf *Developer) bool {
	c.Mux.Lock()
	defer c.Mux.Unlock()
	inst, found := c.Objs[*key]
	if found {
		*valbuf = *inst
	}
	return found
}

func (c *DeveloperCache) HasKey(key *DeveloperKey) bool {
	c.Mux.Lock()
	defer c.Mux.Unlock()
	_, found := c.Objs[*key]
	return found
}

func (c *DeveloperCache) GetAllKeys(keys map[DeveloperKey]struct{}) {
	c.Mux.Lock()
	defer c.Mux.Unlock()
	for key, _ := range c.Objs {
		keys[key] = struct{}{}
	}
}

func (c *DeveloperCache) Update(in *Developer, rev int64) {
	c.UpdateModFunc(&in.Key, rev, func(old *Developer) (*Developer, bool) {
		return in, true
	})
}

func (c *DeveloperCache) UpdateModFunc(key *DeveloperKey, rev int64, modFunc func(old *Developer) (new *Developer, changed bool)) {
	c.Mux.Lock()
	old := c.Objs[*key]
	new, changed := modFunc(old)
	if !changed {
		c.Mux.Unlock()
		return
	}
	if c.UpdatedCb != nil || c.NotifyCb != nil {
		if c.UpdatedCb != nil {
			newCopy := &Developer{}
			*newCopy = *new
			defer c.UpdatedCb(old, newCopy)
		}
		if c.NotifyCb != nil {
			defer c.NotifyCb(&new.Key, old)
		}
	}
	c.Objs[new.Key] = new
	log.DebugLog(log.DebugLevelApi, "SyncUpdate Developer", "obj", new, "rev", rev)
	c.Mux.Unlock()
	c.TriggerKeyWatchers(&new.Key)
}

func (c *DeveloperCache) Delete(in *Developer, rev int64) {
	c.Mux.Lock()
	old := c.Objs[in.Key]
	delete(c.Objs, in.Key)
	log.DebugLog(log.DebugLevelApi, "SyncDelete Developer", "key", in.Key, "rev", rev)
	c.Mux.Unlock()
	if c.NotifyCb != nil {
		c.NotifyCb(&in.Key, old)
	}
	c.TriggerKeyWatchers(&in.Key)
}

func (c *DeveloperCache) Prune(validKeys map[DeveloperKey]struct{}) {
	notify := make(map[DeveloperKey]*Developer)
	c.Mux.Lock()
	for key, _ := range c.Objs {
		if _, ok := validKeys[key]; !ok {
			if c.NotifyCb != nil {
				notify[key] = c.Objs[key]
			}
			delete(c.Objs, key)
		}
	}
	c.Mux.Unlock()
	for key, old := range notify {
		if c.NotifyCb != nil {
			c.NotifyCb(&key, old)
		}
		c.TriggerKeyWatchers(&key)
	}
}

func (c *DeveloperCache) GetCount() int {
	c.Mux.Lock()
	defer c.Mux.Unlock()
	return len(c.Objs)
}

func (c *DeveloperCache) Flush(notifyId int64) {
}

func (c *DeveloperCache) Show(filter *Developer, cb func(ret *Developer) error) error {
	log.DebugLog(log.DebugLevelApi, "Show Developer", "count", len(c.Objs))
	c.Mux.Lock()
	defer c.Mux.Unlock()
	for _, obj := range c.Objs {
		if !obj.Matches(filter, MatchFilter()) {
			continue
		}
		log.DebugLog(log.DebugLevelApi, "Show Developer", "obj", obj)
		err := cb(obj)
		if err != nil {
			return err
		}
	}
	return nil
}

func DeveloperGenericNotifyCb(fn func(key *DeveloperKey, old *Developer)) func(objstore.ObjKey, objstore.Obj) {
	return func(objkey objstore.ObjKey, obj objstore.Obj) {
		fn(objkey.(*DeveloperKey), obj.(*Developer))
	}
}

func (c *DeveloperCache) SetNotifyCb(fn func(obj *DeveloperKey, old *Developer)) {
	c.NotifyCb = fn
}

func (c *DeveloperCache) SetUpdatedCb(fn func(old *Developer, new *Developer)) {
	c.UpdatedCb = fn
}

func (c *DeveloperCache) WatchKey(key *DeveloperKey, cb func()) context.CancelFunc {
	c.Mux.Lock()
	defer c.Mux.Unlock()
	list, ok := c.KeyWatchers[*key]
	if !ok {
		list = make([]*DeveloperKeyWatcher, 0)
	}
	watcher := DeveloperKeyWatcher{cb: cb}
	c.KeyWatchers[*key] = append(list, &watcher)
	log.DebugLog(log.DebugLevelApi, "Watching Developer", "key", key)
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

func (c *DeveloperCache) TriggerKeyWatchers(key *DeveloperKey) {
	watchers := make([]*DeveloperKeyWatcher, 0)
	c.Mux.Lock()
	if list, ok := c.KeyWatchers[*key]; ok {
		watchers = append(watchers, list...)
	}
	c.Mux.Unlock()
	for ii, _ := range watchers {
		watchers[ii].cb()
	}
}
func (c *DeveloperCache) SyncUpdate(key, val []byte, rev int64) {
	obj := Developer{}
	err := json.Unmarshal(val, &obj)
	if err != nil {
		log.WarnLog("Failed to parse Developer data", "val", string(val))
		return
	}
	c.Update(&obj, rev)
	c.Mux.Lock()
	if c.List != nil {
		c.List[obj.Key] = struct{}{}
	}
	c.Mux.Unlock()
}

func (c *DeveloperCache) SyncDelete(key []byte, rev int64) {
	obj := Developer{}
	keystr := objstore.DbKeyPrefixRemove(string(key))
	DeveloperKeyStringParse(keystr, &obj.Key)
	c.Delete(&obj, rev)
}

func (c *DeveloperCache) SyncListStart() {
	c.List = make(map[DeveloperKey]struct{})
}

func (c *DeveloperCache) SyncListEnd() {
	deleted := make(map[DeveloperKey]*Developer)
	c.Mux.Lock()
	for key, val := range c.Objs {
		if _, found := c.List[key]; !found {
			deleted[key] = val
			delete(c.Objs, key)
		}
	}
	c.List = nil
	c.Mux.Unlock()
	if c.NotifyCb != nil {
		for key, val := range deleted {
			c.NotifyCb(&key, val)
			c.TriggerKeyWatchers(&key)
		}
	}
}

func (m *Developer) GetKey() objstore.ObjKey {
	return &m.Key
}

func CmpSortDeveloper(a Developer, b Developer) bool {
	return a.Key.GetKeyString() < b.Key.GetKeyString()
}

// Helper method to check that enums have valid values
// NOTE: ValidateEnums checks all Fields even if some are not set
func (m *Developer) ValidateEnums() error {
	if err := m.Key.ValidateEnums(); err != nil {
		return err
	}
	return nil
}

func (m *DeveloperKey) Size() (n int) {
	var l int
	_ = l
	l = len(m.Name)
	if l > 0 {
		n += 1 + l + sovDeveloper(uint64(l))
	}
	return n
}

func (m *Developer) Size() (n int) {
	var l int
	_ = l
	if len(m.Fields) > 0 {
		for _, s := range m.Fields {
			l = len(s)
			n += 1 + l + sovDeveloper(uint64(l))
		}
	}
	l = m.Key.Size()
	n += 1 + l + sovDeveloper(uint64(l))
	return n
}

func sovDeveloper(x uint64) (n int) {
	for {
		n++
		x >>= 7
		if x == 0 {
			break
		}
	}
	return n
}
func sozDeveloper(x uint64) (n int) {
	return sovDeveloper(uint64((x << 1) ^ uint64((int64(x) >> 63))))
}
func (m *DeveloperKey) Unmarshal(dAtA []byte) error {
	l := len(dAtA)
	iNdEx := 0
	for iNdEx < l {
		preIndex := iNdEx
		var wire uint64
		for shift := uint(0); ; shift += 7 {
			if shift >= 64 {
				return ErrIntOverflowDeveloper
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
			return fmt.Errorf("proto: DeveloperKey: wiretype end group for non-group")
		}
		if fieldNum <= 0 {
			return fmt.Errorf("proto: DeveloperKey: illegal tag %d (wire type %d)", fieldNum, wire)
		}
		switch fieldNum {
		case 2:
			if wireType != 2 {
				return fmt.Errorf("proto: wrong wireType = %d for field Name", wireType)
			}
			var stringLen uint64
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowDeveloper
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
				return ErrInvalidLengthDeveloper
			}
			postIndex := iNdEx + intStringLen
			if postIndex > l {
				return io.ErrUnexpectedEOF
			}
			m.Name = string(dAtA[iNdEx:postIndex])
			iNdEx = postIndex
		default:
			iNdEx = preIndex
			skippy, err := skipDeveloper(dAtA[iNdEx:])
			if err != nil {
				return err
			}
			if skippy < 0 {
				return ErrInvalidLengthDeveloper
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
func (m *Developer) Unmarshal(dAtA []byte) error {
	l := len(dAtA)
	iNdEx := 0
	for iNdEx < l {
		preIndex := iNdEx
		var wire uint64
		for shift := uint(0); ; shift += 7 {
			if shift >= 64 {
				return ErrIntOverflowDeveloper
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
			return fmt.Errorf("proto: Developer: wiretype end group for non-group")
		}
		if fieldNum <= 0 {
			return fmt.Errorf("proto: Developer: illegal tag %d (wire type %d)", fieldNum, wire)
		}
		switch fieldNum {
		case 1:
			if wireType != 2 {
				return fmt.Errorf("proto: wrong wireType = %d for field Fields", wireType)
			}
			var stringLen uint64
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowDeveloper
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
				return ErrInvalidLengthDeveloper
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
					return ErrIntOverflowDeveloper
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
				return ErrInvalidLengthDeveloper
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
			skippy, err := skipDeveloper(dAtA[iNdEx:])
			if err != nil {
				return err
			}
			if skippy < 0 {
				return ErrInvalidLengthDeveloper
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
func skipDeveloper(dAtA []byte) (n int, err error) {
	l := len(dAtA)
	iNdEx := 0
	for iNdEx < l {
		var wire uint64
		for shift := uint(0); ; shift += 7 {
			if shift >= 64 {
				return 0, ErrIntOverflowDeveloper
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
					return 0, ErrIntOverflowDeveloper
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
					return 0, ErrIntOverflowDeveloper
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
				return 0, ErrInvalidLengthDeveloper
			}
			return iNdEx, nil
		case 3:
			for {
				var innerWire uint64
				var start int = iNdEx
				for shift := uint(0); ; shift += 7 {
					if shift >= 64 {
						return 0, ErrIntOverflowDeveloper
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
				next, err := skipDeveloper(dAtA[start:])
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
	ErrInvalidLengthDeveloper = fmt.Errorf("proto: negative length found during unmarshaling")
	ErrIntOverflowDeveloper   = fmt.Errorf("proto: integer overflow")
)

func init() { proto.RegisterFile("developer.proto", fileDescriptorDeveloper) }

var fileDescriptorDeveloper = []byte{
	// 407 bytes of a gzipped FileDescriptorProto
	0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0xff, 0xe2, 0xe2, 0x4f, 0x49, 0x2d, 0x4b,
	0xcd, 0xc9, 0x2f, 0x48, 0x2d, 0xd2, 0x2b, 0x28, 0xca, 0x2f, 0xc9, 0x17, 0xe2, 0x4c, 0x4d, 0x49,
	0x4f, 0x05, 0x33, 0xa5, 0x64, 0xd2, 0xf3, 0xf3, 0xd3, 0x73, 0x52, 0xf5, 0x13, 0x0b, 0x32, 0xf5,
	0x13, 0xf3, 0xf2, 0xf2, 0x4b, 0x12, 0x4b, 0x32, 0xf3, 0xf3, 0x8a, 0x21, 0x0a, 0xa5, 0x2c, 0xd2,
	0x33, 0x4b, 0x32, 0x4a, 0x93, 0xf4, 0x92, 0xf3, 0x73, 0xf5, 0x73, 0xf3, 0x93, 0x32, 0x73, 0x40,
	0x1a, 0x2b, 0xf4, 0x41, 0xa4, 0x6e, 0x72, 0x4e, 0x7e, 0x69, 0x8a, 0x3e, 0x58, 0x5d, 0x7a, 0x6a,
	0x1e, 0x9c, 0x01, 0xd5, 0xe9, 0x4e, 0x9c, 0xce, 0x64, 0xdd, 0xf4, 0xd4, 0x3c, 0xdd, 0xe4, 0x5c,
	0x18, 0x17, 0x89, 0x01, 0x35, 0x88, 0xa7, 0x28, 0xb5, 0xb8, 0x34, 0xa7, 0x04, 0xca, 0x13, 0x49,
	0xcf, 0x4f, 0xcf, 0x07, 0x33, 0xf5, 0x41, 0x2c, 0x88, 0xa8, 0x92, 0x01, 0x17, 0x8f, 0x0b, 0xcc,
	0x8b, 0xde, 0xa9, 0x95, 0x42, 0x42, 0x5c, 0x2c, 0x79, 0x89, 0xb9, 0xa9, 0x12, 0x4c, 0x0a, 0x8c,
	0x1a, 0x9c, 0x41, 0x60, 0xb6, 0x15, 0xcf, 0x8b, 0xcf, 0x12, 0x8c, 0x3f, 0x3e, 0x4b, 0x30, 0x6e,
	0x58, 0x20, 0xcf, 0xa8, 0x54, 0xce, 0xc5, 0x09, 0xd7, 0x21, 0x24, 0xc6, 0xc5, 0x96, 0x96, 0x99,
	0x9a, 0x93, 0x52, 0x2c, 0xc1, 0xa8, 0xc0, 0xac, 0xc1, 0x19, 0x04, 0xe5, 0x09, 0xe9, 0x73, 0x31,
	0x67, 0xa7, 0x56, 0x82, 0x4d, 0xe1, 0x36, 0x12, 0xd7, 0x83, 0x07, 0x9a, 0x1e, 0xb2, 0x65, 0x4e,
	0x2c, 0x27, 0xee, 0xc9, 0x33, 0x04, 0x81, 0x54, 0x5a, 0x29, 0x82, 0xec, 0xf8, 0xf0, 0x59, 0x82,
	0xb1, 0xe1, 0x8b, 0x04, 0xe3, 0x8c, 0x2f, 0x12, 0x8c, 0x93, 0x36, 0x49, 0xf2, 0x82, 0x6c, 0xb7,
	0xf5, 0x4e, 0xad, 0xd4, 0xf3, 0x4b, 0xcc, 0x4d, 0x35, 0xfa, 0xce, 0x84, 0xe4, 0x56, 0xc7, 0x82,
	0x4c, 0xa1, 0x08, 0x2e, 0x7e, 0xe7, 0xa2, 0xd4, 0xc4, 0x92, 0x54, 0x84, 0x7b, 0x44, 0xb0, 0x59,
	0x25, 0x25, 0x88, 0x24, 0x1a, 0x04, 0x0e, 0x13, 0x25, 0x99, 0xa6, 0xcb, 0x4f, 0x26, 0x33, 0x89,
	0x29, 0x09, 0xea, 0x27, 0x83, 0x8d, 0xd0, 0x87, 0x47, 0xb4, 0x15, 0xa3, 0x16, 0xc8, 0x64, 0x97,
	0xd4, 0x9c, 0x54, 0x0a, 0x4d, 0x4e, 0x01, 0x1b, 0x81, 0x61, 0x72, 0x68, 0x41, 0x0a, 0xa5, 0x6e,
	0x2e, 0x05, 0x1b, 0x81, 0x6a, 0x72, 0x24, 0x17, 0x6f, 0x70, 0x46, 0x7e, 0x39, 0x21, 0x73, 0xb1,
	0x8a, 0x2a, 0x49, 0x81, 0x8d, 0x16, 0x51, 0xe2, 0xd7, 0x2f, 0xce, 0xc8, 0x2f, 0x47, 0x31, 0xd8,
	0x80, 0xd1, 0x49, 0xe0, 0xc4, 0x43, 0x39, 0x86, 0x13, 0x8f, 0xe4, 0x18, 0x2f, 0x3c, 0x92, 0x63,
	0x7c, 0xf0, 0x48, 0x8e, 0x31, 0x89, 0x0d, 0x6c, 0x80, 0x31, 0x20, 0x00, 0x00, 0xff, 0xff, 0x2b,
	0x1f, 0x09, 0xdd, 0x20, 0x03, 0x00, 0x00,
}
