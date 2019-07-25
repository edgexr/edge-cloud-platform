// Code generated by protoc-gen-gogo. DO NOT EDIT.
// source: controller.proto

package edgeproto

import proto "github.com/gogo/protobuf/proto"
import fmt "fmt"
import math "math"
import _ "github.com/gogo/googleapis/google/api"
import _ "github.com/gogo/protobuf/gogoproto"
import _ "github.com/mobiledgex/edge-cloud/protogen"
import _ "github.com/mobiledgex/edge-cloud/protoc-gen-cmd/protocmd"

import strings "strings"
import reflect "reflect"

import context "golang.org/x/net/context"
import grpc "google.golang.org/grpc"

import "encoding/json"
import "github.com/mobiledgex/edge-cloud/objstore"
import "github.com/coreos/etcd/clientv3/concurrency"
import "github.com/mobiledgex/edge-cloud/util"
import "github.com/mobiledgex/edge-cloud/log"
import "github.com/google/go-cmp/cmp"
import "github.com/google/go-cmp/cmp/cmpopts"

import io "io"

// Reference imports to suppress errors if they are not otherwise used.
var _ = proto.Marshal
var _ = fmt.Errorf
var _ = math.Inf

// ControllerKey uniquely defines a Controller
type ControllerKey struct {
	// external API address
	Addr string `protobuf:"bytes,1,opt,name=addr,proto3" json:"addr,omitempty"`
}

func (m *ControllerKey) Reset()                    { *m = ControllerKey{} }
func (m *ControllerKey) String() string            { return proto.CompactTextString(m) }
func (*ControllerKey) ProtoMessage()               {}
func (*ControllerKey) Descriptor() ([]byte, []int) { return fileDescriptorController, []int{0} }

// A Controller is a service that manages the edge-cloud data and controls other edge-cloud micro-services.
type Controller struct {
	// Fields are used for the Update API to specify which fields to apply
	Fields []string `protobuf:"bytes,1,rep,name=fields" json:"fields,omitempty"`
	// Unique identifier key
	Key ControllerKey `protobuf:"bytes,2,opt,name=key" json:"key"`
	// Build Master Version
	BuildMaster string `protobuf:"bytes,4,opt,name=build_master,json=buildMaster,proto3" json:"build_master,omitempty"`
	// Build Head Version
	BuildHead string `protobuf:"bytes,5,opt,name=build_head,json=buildHead,proto3" json:"build_head,omitempty"`
	// Build Author
	BuildAuthor string `protobuf:"bytes,6,opt,name=build_author,json=buildAuthor,proto3" json:"build_author,omitempty"`
	// Hostname
	Hostname string `protobuf:"bytes,7,opt,name=hostname,proto3" json:"hostname,omitempty"`
}

func (m *Controller) Reset()                    { *m = Controller{} }
func (m *Controller) String() string            { return proto.CompactTextString(m) }
func (*Controller) ProtoMessage()               {}
func (*Controller) Descriptor() ([]byte, []int) { return fileDescriptorController, []int{1} }

func init() {
	proto.RegisterType((*ControllerKey)(nil), "edgeproto.ControllerKey")
	proto.RegisterType((*Controller)(nil), "edgeproto.Controller")
}
func (this *ControllerKey) GoString() string {
	if this == nil {
		return "nil"
	}
	s := make([]string, 0, 5)
	s = append(s, "&edgeproto.ControllerKey{")
	s = append(s, "Addr: "+fmt.Sprintf("%#v", this.Addr)+",\n")
	s = append(s, "}")
	return strings.Join(s, "")
}
func valueToGoStringController(v interface{}, typ string) string {
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

// Client API for ControllerApi service

type ControllerApiClient interface {
	// Show Controllers
	ShowController(ctx context.Context, in *Controller, opts ...grpc.CallOption) (ControllerApi_ShowControllerClient, error)
}

type controllerApiClient struct {
	cc *grpc.ClientConn
}

func NewControllerApiClient(cc *grpc.ClientConn) ControllerApiClient {
	return &controllerApiClient{cc}
}

func (c *controllerApiClient) ShowController(ctx context.Context, in *Controller, opts ...grpc.CallOption) (ControllerApi_ShowControllerClient, error) {
	stream, err := grpc.NewClientStream(ctx, &_ControllerApi_serviceDesc.Streams[0], c.cc, "/edgeproto.ControllerApi/ShowController", opts...)
	if err != nil {
		return nil, err
	}
	x := &controllerApiShowControllerClient{stream}
	if err := x.ClientStream.SendMsg(in); err != nil {
		return nil, err
	}
	if err := x.ClientStream.CloseSend(); err != nil {
		return nil, err
	}
	return x, nil
}

type ControllerApi_ShowControllerClient interface {
	Recv() (*Controller, error)
	grpc.ClientStream
}

type controllerApiShowControllerClient struct {
	grpc.ClientStream
}

func (x *controllerApiShowControllerClient) Recv() (*Controller, error) {
	m := new(Controller)
	if err := x.ClientStream.RecvMsg(m); err != nil {
		return nil, err
	}
	return m, nil
}

// Server API for ControllerApi service

type ControllerApiServer interface {
	// Show Controllers
	ShowController(*Controller, ControllerApi_ShowControllerServer) error
}

func RegisterControllerApiServer(s *grpc.Server, srv ControllerApiServer) {
	s.RegisterService(&_ControllerApi_serviceDesc, srv)
}

func _ControllerApi_ShowController_Handler(srv interface{}, stream grpc.ServerStream) error {
	m := new(Controller)
	if err := stream.RecvMsg(m); err != nil {
		return err
	}
	return srv.(ControllerApiServer).ShowController(m, &controllerApiShowControllerServer{stream})
}

type ControllerApi_ShowControllerServer interface {
	Send(*Controller) error
	grpc.ServerStream
}

type controllerApiShowControllerServer struct {
	grpc.ServerStream
}

func (x *controllerApiShowControllerServer) Send(m *Controller) error {
	return x.ServerStream.SendMsg(m)
}

var _ControllerApi_serviceDesc = grpc.ServiceDesc{
	ServiceName: "edgeproto.ControllerApi",
	HandlerType: (*ControllerApiServer)(nil),
	Methods:     []grpc.MethodDesc{},
	Streams: []grpc.StreamDesc{
		{
			StreamName:    "ShowController",
			Handler:       _ControllerApi_ShowController_Handler,
			ServerStreams: true,
		},
	},
	Metadata: "controller.proto",
}

func (m *ControllerKey) Marshal() (dAtA []byte, err error) {
	size := m.Size()
	dAtA = make([]byte, size)
	n, err := m.MarshalTo(dAtA)
	if err != nil {
		return nil, err
	}
	return dAtA[:n], nil
}

func (m *ControllerKey) MarshalTo(dAtA []byte) (int, error) {
	var i int
	_ = i
	var l int
	_ = l
	if len(m.Addr) > 0 {
		dAtA[i] = 0xa
		i++
		i = encodeVarintController(dAtA, i, uint64(len(m.Addr)))
		i += copy(dAtA[i:], m.Addr)
	}
	return i, nil
}

func (m *Controller) Marshal() (dAtA []byte, err error) {
	size := m.Size()
	dAtA = make([]byte, size)
	n, err := m.MarshalTo(dAtA)
	if err != nil {
		return nil, err
	}
	return dAtA[:n], nil
}

func (m *Controller) MarshalTo(dAtA []byte) (int, error) {
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
	i = encodeVarintController(dAtA, i, uint64(m.Key.Size()))
	n1, err := m.Key.MarshalTo(dAtA[i:])
	if err != nil {
		return 0, err
	}
	i += n1
	if len(m.BuildMaster) > 0 {
		dAtA[i] = 0x22
		i++
		i = encodeVarintController(dAtA, i, uint64(len(m.BuildMaster)))
		i += copy(dAtA[i:], m.BuildMaster)
	}
	if len(m.BuildHead) > 0 {
		dAtA[i] = 0x2a
		i++
		i = encodeVarintController(dAtA, i, uint64(len(m.BuildHead)))
		i += copy(dAtA[i:], m.BuildHead)
	}
	if len(m.BuildAuthor) > 0 {
		dAtA[i] = 0x32
		i++
		i = encodeVarintController(dAtA, i, uint64(len(m.BuildAuthor)))
		i += copy(dAtA[i:], m.BuildAuthor)
	}
	if len(m.Hostname) > 0 {
		dAtA[i] = 0x3a
		i++
		i = encodeVarintController(dAtA, i, uint64(len(m.Hostname)))
		i += copy(dAtA[i:], m.Hostname)
	}
	return i, nil
}

func encodeVarintController(dAtA []byte, offset int, v uint64) int {
	for v >= 1<<7 {
		dAtA[offset] = uint8(v&0x7f | 0x80)
		v >>= 7
		offset++
	}
	dAtA[offset] = uint8(v)
	return offset + 1
}
func (m *ControllerKey) Matches(o *ControllerKey, fopts ...MatchOpt) bool {
	opts := MatchOptions{}
	applyMatchOptions(&opts, fopts...)
	if o == nil {
		if opts.Filter {
			return true
		}
		return false
	}
	if !opts.Filter || o.Addr != "" {
		if o.Addr != m.Addr {
			return false
		}
	}
	return true
}

func (m *ControllerKey) CopyInFields(src *ControllerKey) {
	m.Addr = src.Addr
}

func (m *ControllerKey) GetKeyString() string {
	key, err := json.Marshal(m)
	if err != nil {
		log.FatalLog("Failed to marshal ControllerKey key string", "obj", m)
	}
	return string(key)
}

func ControllerKeyStringParse(str string, key *ControllerKey) {
	err := json.Unmarshal([]byte(str), key)
	if err != nil {
		log.FatalLog("Failed to unmarshal ControllerKey key string", "str", str)
	}
}

// Helper method to check that enums have valid values
func (m *ControllerKey) ValidateEnums() error {
	return nil
}

func (m *Controller) Matches(o *Controller, fopts ...MatchOpt) bool {
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
	if !opts.IgnoreBackend {
		if !opts.Filter || o.BuildMaster != "" {
			if o.BuildMaster != m.BuildMaster {
				return false
			}
		}
	}
	if !opts.IgnoreBackend {
		if !opts.Filter || o.BuildHead != "" {
			if o.BuildHead != m.BuildHead {
				return false
			}
		}
	}
	if !opts.IgnoreBackend {
		if !opts.Filter || o.BuildAuthor != "" {
			if o.BuildAuthor != m.BuildAuthor {
				return false
			}
		}
	}
	if !opts.IgnoreBackend {
		if !opts.Filter || o.Hostname != "" {
			if o.Hostname != m.Hostname {
				return false
			}
		}
	}
	return true
}

const ControllerFieldKey = "2"
const ControllerFieldKeyAddr = "2.1"
const ControllerFieldBuildMaster = "4"
const ControllerFieldBuildHead = "5"
const ControllerFieldBuildAuthor = "6"
const ControllerFieldHostname = "7"

var ControllerAllFields = []string{
	ControllerFieldKeyAddr,
	ControllerFieldBuildMaster,
	ControllerFieldBuildHead,
	ControllerFieldBuildAuthor,
	ControllerFieldHostname,
}

var ControllerAllFieldsMap = map[string]struct{}{
	ControllerFieldKeyAddr:     struct{}{},
	ControllerFieldBuildMaster: struct{}{},
	ControllerFieldBuildHead:   struct{}{},
	ControllerFieldBuildAuthor: struct{}{},
	ControllerFieldHostname:    struct{}{},
}

var ControllerAllFieldsStringMap = map[string]string{
	ControllerFieldKeyAddr:     "Controller Field Key Addr",
	ControllerFieldBuildMaster: "Controller Field Build Master",
	ControllerFieldBuildHead:   "Controller Field Build Head",
	ControllerFieldBuildAuthor: "Controller Field Build Author",
	ControllerFieldHostname:    "Controller Field Hostname",
}

func (m *Controller) IsKeyField(s string) bool {
	return strings.HasPrefix(s, ControllerFieldKey+".")
}

func (m *Controller) DiffFields(o *Controller, fields map[string]struct{}) {
	if m.Key.Addr != o.Key.Addr {
		fields[ControllerFieldKeyAddr] = struct{}{}
		fields[ControllerFieldKey] = struct{}{}
	}
	if m.BuildMaster != o.BuildMaster {
		fields[ControllerFieldBuildMaster] = struct{}{}
	}
	if m.BuildHead != o.BuildHead {
		fields[ControllerFieldBuildHead] = struct{}{}
	}
	if m.BuildAuthor != o.BuildAuthor {
		fields[ControllerFieldBuildAuthor] = struct{}{}
	}
	if m.Hostname != o.Hostname {
		fields[ControllerFieldHostname] = struct{}{}
	}
}

func (m *Controller) CopyInFields(src *Controller) {
	fmap := MakeFieldMap(src.Fields)
	if _, set := fmap["2"]; set {
		if _, set := fmap["2.1"]; set {
			m.Key.Addr = src.Key.Addr
		}
	}
	if _, set := fmap["4"]; set {
		m.BuildMaster = src.BuildMaster
	}
	if _, set := fmap["5"]; set {
		m.BuildHead = src.BuildHead
	}
	if _, set := fmap["6"]; set {
		m.BuildAuthor = src.BuildAuthor
	}
	if _, set := fmap["7"]; set {
		m.Hostname = src.Hostname
	}
}

func (s *Controller) HasFields() bool {
	return true
}

type ControllerStore struct {
	kvstore objstore.KVStore
}

func NewControllerStore(kvstore objstore.KVStore) ControllerStore {
	return ControllerStore{kvstore: kvstore}
}

func (s *ControllerStore) Create(ctx context.Context, m *Controller, wait func(int64)) (*Result, error) {
	err := m.Validate(ControllerAllFieldsMap)
	if err != nil {
		return nil, err
	}
	key := objstore.DbKeyString("Controller", m.GetKey())
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

func (s *ControllerStore) Update(ctx context.Context, m *Controller, wait func(int64)) (*Result, error) {
	fmap := MakeFieldMap(m.Fields)
	err := m.Validate(fmap)
	if err != nil {
		return nil, err
	}
	key := objstore.DbKeyString("Controller", m.GetKey())
	var vers int64 = 0
	curBytes, vers, _, err := s.kvstore.Get(key)
	if err != nil {
		return nil, err
	}
	var cur Controller
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
	rev, err := s.kvstore.Update(ctx, key, string(val), vers)
	if err != nil {
		return nil, err
	}
	if wait != nil {
		wait(rev)
	}
	return &Result{}, err
}

func (s *ControllerStore) Put(ctx context.Context, m *Controller, wait func(int64), ops ...objstore.KVOp) (*Result, error) {
	err := m.Validate(ControllerAllFieldsMap)
	m.Fields = nil
	if err != nil {
		return nil, err
	}
	key := objstore.DbKeyString("Controller", m.GetKey())
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

func (s *ControllerStore) Delete(ctx context.Context, m *Controller, wait func(int64)) (*Result, error) {
	err := m.GetKey().Validate()
	if err != nil {
		return nil, err
	}
	key := objstore.DbKeyString("Controller", m.GetKey())
	rev, err := s.kvstore.Delete(ctx, key)
	if err != nil {
		return nil, err
	}
	if wait != nil {
		wait(rev)
	}
	return &Result{}, err
}

func (s *ControllerStore) LoadOne(key string) (*Controller, int64, error) {
	val, rev, _, err := s.kvstore.Get(key)
	if err != nil {
		return nil, 0, err
	}
	var obj Controller
	err = json.Unmarshal(val, &obj)
	if err != nil {
		log.DebugLog(log.DebugLevelApi, "Failed to parse Controller data", "val", string(val))
		return nil, 0, err
	}
	return &obj, rev, nil
}

func (s *ControllerStore) STMGet(stm concurrency.STM, key *ControllerKey, buf *Controller) bool {
	keystr := objstore.DbKeyString("Controller", key)
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

func (s *ControllerStore) STMPut(stm concurrency.STM, obj *Controller, ops ...objstore.KVOp) {
	keystr := objstore.DbKeyString("Controller", obj.GetKey())
	val, err := json.Marshal(obj)
	if err != nil {
		log.InfoLog("Controller json marsahal failed", "obj", obj, "err", err)
	}
	v3opts := GetSTMOpts(ops...)
	stm.Put(keystr, string(val), v3opts...)
}

func (s *ControllerStore) STMDel(stm concurrency.STM, key *ControllerKey) {
	keystr := objstore.DbKeyString("Controller", key)
	stm.Del(keystr)
}

type ControllerKeyWatcher struct {
	cb func(ctx context.Context)
}

// ControllerCache caches Controller objects in memory in a hash table
// and keeps them in sync with the database.
type ControllerCache struct {
	Objs        map[ControllerKey]*Controller
	Mux         util.Mutex
	List        map[ControllerKey]struct{}
	NotifyCb    func(ctx context.Context, obj *ControllerKey, old *Controller)
	UpdatedCb   func(ctx context.Context, old *Controller, new *Controller)
	KeyWatchers map[ControllerKey][]*ControllerKeyWatcher
}

func NewControllerCache() *ControllerCache {
	cache := ControllerCache{}
	InitControllerCache(&cache)
	return &cache
}

func InitControllerCache(cache *ControllerCache) {
	cache.Objs = make(map[ControllerKey]*Controller)
	cache.KeyWatchers = make(map[ControllerKey][]*ControllerKeyWatcher)
}

func (c *ControllerCache) GetTypeString() string {
	return "Controller"
}

func (c *ControllerCache) Get(key *ControllerKey, valbuf *Controller) bool {
	c.Mux.Lock()
	defer c.Mux.Unlock()
	inst, found := c.Objs[*key]
	if found {
		*valbuf = *inst
	}
	return found
}

func (c *ControllerCache) HasKey(key *ControllerKey) bool {
	c.Mux.Lock()
	defer c.Mux.Unlock()
	_, found := c.Objs[*key]
	return found
}

func (c *ControllerCache) GetAllKeys(ctx context.Context, keys map[ControllerKey]context.Context) {
	c.Mux.Lock()
	defer c.Mux.Unlock()
	for key, _ := range c.Objs {
		keys[key] = ctx
	}
}

func (c *ControllerCache) Update(ctx context.Context, in *Controller, rev int64) {
	c.UpdateModFunc(ctx, &in.Key, rev, func(old *Controller) (*Controller, bool) {
		return in, true
	})
}

func (c *ControllerCache) UpdateModFunc(ctx context.Context, key *ControllerKey, rev int64, modFunc func(old *Controller) (new *Controller, changed bool)) {
	c.Mux.Lock()
	old := c.Objs[*key]
	new, changed := modFunc(old)
	if !changed {
		c.Mux.Unlock()
		return
	}
	if c.UpdatedCb != nil || c.NotifyCb != nil {
		if c.UpdatedCb != nil {
			newCopy := &Controller{}
			*newCopy = *new
			defer c.UpdatedCb(ctx, old, newCopy)
		}
		if c.NotifyCb != nil {
			defer c.NotifyCb(ctx, &new.Key, old)
		}
	}
	c.Objs[new.Key] = new
	log.SpanLog(ctx, log.DebugLevelApi, "cache update", "new", new)
	log.DebugLog(log.DebugLevelApi, "SyncUpdate Controller", "obj", new, "rev", rev)
	c.Mux.Unlock()
	c.TriggerKeyWatchers(ctx, &new.Key)
}

func (c *ControllerCache) Delete(ctx context.Context, in *Controller, rev int64) {
	c.Mux.Lock()
	old := c.Objs[in.Key]
	delete(c.Objs, in.Key)
	log.SpanLog(ctx, log.DebugLevelApi, "cache delete")
	log.DebugLog(log.DebugLevelApi, "SyncDelete Controller", "key", in.Key, "rev", rev)
	c.Mux.Unlock()
	if c.NotifyCb != nil {
		c.NotifyCb(ctx, &in.Key, old)
	}
	c.TriggerKeyWatchers(ctx, &in.Key)
}

func (c *ControllerCache) Prune(ctx context.Context, validKeys map[ControllerKey]struct{}) {
	notify := make(map[ControllerKey]*Controller)
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
			c.NotifyCb(ctx, &key, old)
		}
		c.TriggerKeyWatchers(ctx, &key)
	}
}

func (c *ControllerCache) GetCount() int {
	c.Mux.Lock()
	defer c.Mux.Unlock()
	return len(c.Objs)
}

func (c *ControllerCache) Flush(ctx context.Context, notifyId int64) {
}

func (c *ControllerCache) Show(filter *Controller, cb func(ret *Controller) error) error {
	log.DebugLog(log.DebugLevelApi, "Show Controller", "count", len(c.Objs))
	c.Mux.Lock()
	defer c.Mux.Unlock()
	for _, obj := range c.Objs {
		if !obj.Matches(filter, MatchFilter()) {
			continue
		}
		log.DebugLog(log.DebugLevelApi, "Show Controller", "obj", obj)
		err := cb(obj)
		if err != nil {
			return err
		}
	}
	return nil
}

func ControllerGenericNotifyCb(fn func(key *ControllerKey, old *Controller)) func(objstore.ObjKey, objstore.Obj) {
	return func(objkey objstore.ObjKey, obj objstore.Obj) {
		fn(objkey.(*ControllerKey), obj.(*Controller))
	}
}

func (c *ControllerCache) SetNotifyCb(fn func(ctx context.Context, obj *ControllerKey, old *Controller)) {
	c.NotifyCb = fn
}

func (c *ControllerCache) SetUpdatedCb(fn func(ctx context.Context, old *Controller, new *Controller)) {
	c.UpdatedCb = fn
}

func (c *ControllerCache) WatchKey(key *ControllerKey, cb func(ctx context.Context)) context.CancelFunc {
	c.Mux.Lock()
	defer c.Mux.Unlock()
	list, ok := c.KeyWatchers[*key]
	if !ok {
		list = make([]*ControllerKeyWatcher, 0)
	}
	watcher := ControllerKeyWatcher{cb: cb}
	c.KeyWatchers[*key] = append(list, &watcher)
	log.DebugLog(log.DebugLevelApi, "Watching Controller", "key", key)
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

func (c *ControllerCache) TriggerKeyWatchers(ctx context.Context, key *ControllerKey) {
	watchers := make([]*ControllerKeyWatcher, 0)
	c.Mux.Lock()
	if list, ok := c.KeyWatchers[*key]; ok {
		watchers = append(watchers, list...)
	}
	c.Mux.Unlock()
	for ii, _ := range watchers {
		watchers[ii].cb(ctx)
	}
}
func (c *ControllerCache) SyncUpdate(ctx context.Context, key, val []byte, rev int64) {
	obj := Controller{}
	err := json.Unmarshal(val, &obj)
	if err != nil {
		log.WarnLog("Failed to parse Controller data", "val", string(val))
		return
	}
	c.Update(ctx, &obj, rev)
	c.Mux.Lock()
	if c.List != nil {
		c.List[obj.Key] = struct{}{}
	}
	c.Mux.Unlock()
}

func (c *ControllerCache) SyncDelete(ctx context.Context, key []byte, rev int64) {
	obj := Controller{}
	keystr := objstore.DbKeyPrefixRemove(string(key))
	ControllerKeyStringParse(keystr, &obj.Key)
	c.Delete(ctx, &obj, rev)
}

func (c *ControllerCache) SyncListStart(ctx context.Context) {
	c.List = make(map[ControllerKey]struct{})
}

func (c *ControllerCache) SyncListEnd(ctx context.Context) {
	deleted := make(map[ControllerKey]*Controller)
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
			c.NotifyCb(ctx, &key, val)
			c.TriggerKeyWatchers(ctx, &key)
		}
	}
}

func (m *Controller) GetKey() objstore.ObjKey {
	return &m.Key
}

func CmpSortController(a Controller, b Controller) bool {
	return a.Key.GetKeyString() < b.Key.GetKeyString()
}

// Helper method to check that enums have valid values
// NOTE: ValidateEnums checks all Fields even if some are not set
func (m *Controller) ValidateEnums() error {
	if err := m.Key.ValidateEnums(); err != nil {
		return err
	}
	return nil
}

func IgnoreControllerFields(taglist string) cmp.Option {
	names := []string{}
	tags := make(map[string]struct{})
	for _, tag := range strings.Split(taglist, ",") {
		tags[tag] = struct{}{}
	}
	if _, found := tags["nocmp"]; found {
		names = append(names, "BuildMaster")
	}
	if _, found := tags["nocmp"]; found {
		names = append(names, "BuildHead")
	}
	if _, found := tags["nocmp"]; found {
		names = append(names, "BuildAuthor")
	}
	if _, found := tags["nocmp"]; found {
		names = append(names, "Hostname")
	}
	return cmpopts.IgnoreFields(Controller{}, names...)
}

func (m *ControllerKey) Size() (n int) {
	var l int
	_ = l
	l = len(m.Addr)
	if l > 0 {
		n += 1 + l + sovController(uint64(l))
	}
	return n
}

func (m *Controller) Size() (n int) {
	var l int
	_ = l
	if len(m.Fields) > 0 {
		for _, s := range m.Fields {
			l = len(s)
			n += 1 + l + sovController(uint64(l))
		}
	}
	l = m.Key.Size()
	n += 1 + l + sovController(uint64(l))
	l = len(m.BuildMaster)
	if l > 0 {
		n += 1 + l + sovController(uint64(l))
	}
	l = len(m.BuildHead)
	if l > 0 {
		n += 1 + l + sovController(uint64(l))
	}
	l = len(m.BuildAuthor)
	if l > 0 {
		n += 1 + l + sovController(uint64(l))
	}
	l = len(m.Hostname)
	if l > 0 {
		n += 1 + l + sovController(uint64(l))
	}
	return n
}

func sovController(x uint64) (n int) {
	for {
		n++
		x >>= 7
		if x == 0 {
			break
		}
	}
	return n
}
func sozController(x uint64) (n int) {
	return sovController(uint64((x << 1) ^ uint64((int64(x) >> 63))))
}
func (m *ControllerKey) Unmarshal(dAtA []byte) error {
	l := len(dAtA)
	iNdEx := 0
	for iNdEx < l {
		preIndex := iNdEx
		var wire uint64
		for shift := uint(0); ; shift += 7 {
			if shift >= 64 {
				return ErrIntOverflowController
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
			return fmt.Errorf("proto: ControllerKey: wiretype end group for non-group")
		}
		if fieldNum <= 0 {
			return fmt.Errorf("proto: ControllerKey: illegal tag %d (wire type %d)", fieldNum, wire)
		}
		switch fieldNum {
		case 1:
			if wireType != 2 {
				return fmt.Errorf("proto: wrong wireType = %d for field Addr", wireType)
			}
			var stringLen uint64
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowController
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
				return ErrInvalidLengthController
			}
			postIndex := iNdEx + intStringLen
			if postIndex > l {
				return io.ErrUnexpectedEOF
			}
			m.Addr = string(dAtA[iNdEx:postIndex])
			iNdEx = postIndex
		default:
			iNdEx = preIndex
			skippy, err := skipController(dAtA[iNdEx:])
			if err != nil {
				return err
			}
			if skippy < 0 {
				return ErrInvalidLengthController
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
func (m *Controller) Unmarshal(dAtA []byte) error {
	l := len(dAtA)
	iNdEx := 0
	for iNdEx < l {
		preIndex := iNdEx
		var wire uint64
		for shift := uint(0); ; shift += 7 {
			if shift >= 64 {
				return ErrIntOverflowController
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
			return fmt.Errorf("proto: Controller: wiretype end group for non-group")
		}
		if fieldNum <= 0 {
			return fmt.Errorf("proto: Controller: illegal tag %d (wire type %d)", fieldNum, wire)
		}
		switch fieldNum {
		case 1:
			if wireType != 2 {
				return fmt.Errorf("proto: wrong wireType = %d for field Fields", wireType)
			}
			var stringLen uint64
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowController
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
				return ErrInvalidLengthController
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
					return ErrIntOverflowController
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
				return ErrInvalidLengthController
			}
			postIndex := iNdEx + msglen
			if postIndex > l {
				return io.ErrUnexpectedEOF
			}
			if err := m.Key.Unmarshal(dAtA[iNdEx:postIndex]); err != nil {
				return err
			}
			iNdEx = postIndex
		case 4:
			if wireType != 2 {
				return fmt.Errorf("proto: wrong wireType = %d for field BuildMaster", wireType)
			}
			var stringLen uint64
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowController
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
				return ErrInvalidLengthController
			}
			postIndex := iNdEx + intStringLen
			if postIndex > l {
				return io.ErrUnexpectedEOF
			}
			m.BuildMaster = string(dAtA[iNdEx:postIndex])
			iNdEx = postIndex
		case 5:
			if wireType != 2 {
				return fmt.Errorf("proto: wrong wireType = %d for field BuildHead", wireType)
			}
			var stringLen uint64
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowController
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
				return ErrInvalidLengthController
			}
			postIndex := iNdEx + intStringLen
			if postIndex > l {
				return io.ErrUnexpectedEOF
			}
			m.BuildHead = string(dAtA[iNdEx:postIndex])
			iNdEx = postIndex
		case 6:
			if wireType != 2 {
				return fmt.Errorf("proto: wrong wireType = %d for field BuildAuthor", wireType)
			}
			var stringLen uint64
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowController
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
				return ErrInvalidLengthController
			}
			postIndex := iNdEx + intStringLen
			if postIndex > l {
				return io.ErrUnexpectedEOF
			}
			m.BuildAuthor = string(dAtA[iNdEx:postIndex])
			iNdEx = postIndex
		case 7:
			if wireType != 2 {
				return fmt.Errorf("proto: wrong wireType = %d for field Hostname", wireType)
			}
			var stringLen uint64
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowController
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
				return ErrInvalidLengthController
			}
			postIndex := iNdEx + intStringLen
			if postIndex > l {
				return io.ErrUnexpectedEOF
			}
			m.Hostname = string(dAtA[iNdEx:postIndex])
			iNdEx = postIndex
		default:
			iNdEx = preIndex
			skippy, err := skipController(dAtA[iNdEx:])
			if err != nil {
				return err
			}
			if skippy < 0 {
				return ErrInvalidLengthController
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
func skipController(dAtA []byte) (n int, err error) {
	l := len(dAtA)
	iNdEx := 0
	for iNdEx < l {
		var wire uint64
		for shift := uint(0); ; shift += 7 {
			if shift >= 64 {
				return 0, ErrIntOverflowController
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
					return 0, ErrIntOverflowController
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
					return 0, ErrIntOverflowController
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
				return 0, ErrInvalidLengthController
			}
			return iNdEx, nil
		case 3:
			for {
				var innerWire uint64
				var start int = iNdEx
				for shift := uint(0); ; shift += 7 {
					if shift >= 64 {
						return 0, ErrIntOverflowController
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
				next, err := skipController(dAtA[start:])
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
	ErrInvalidLengthController = fmt.Errorf("proto: negative length found during unmarshaling")
	ErrIntOverflowController   = fmt.Errorf("proto: integer overflow")
)

func init() { proto.RegisterFile("controller.proto", fileDescriptorController) }

var fileDescriptorController = []byte{
	// 421 bytes of a gzipped FileDescriptorProto
	0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0xff, 0x8c, 0x92, 0x41, 0x8b, 0xd3, 0x40,
	0x1c, 0xc5, 0x77, 0xba, 0xdd, 0x6a, 0x67, 0x77, 0xa5, 0x0c, 0xae, 0x8c, 0x55, 0xb2, 0x25, 0xa7,
	0x2a, 0x36, 0x53, 0xd7, 0x8b, 0xec, 0x6d, 0xeb, 0x41, 0x41, 0xbc, 0xc4, 0xb3, 0xc8, 0x24, 0x33,
	0x4e, 0x82, 0xc9, 0xfc, 0x43, 0x32, 0x61, 0xdd, 0x9b, 0xf8, 0x11, 0xf4, 0x0b, 0xe8, 0xcd, 0xa3,
	0xf8, 0x29, 0x7a, 0x14, 0xbc, 0x8b, 0x16, 0x0f, 0x1e, 0x85, 0xee, 0xc1, 0xa3, 0x64, 0x52, 0xd3,
	0x0a, 0x11, 0xbc, 0x84, 0xf7, 0xff, 0xe7, 0xf7, 0x5e, 0x32, 0x8f, 0xc1, 0x83, 0x10, 0xb4, 0xc9,
	0x21, 0x49, 0x64, 0xee, 0x65, 0x39, 0x18, 0x20, 0x7d, 0x29, 0x94, 0xb4, 0x72, 0x78, 0x5d, 0x01,
	0xa8, 0x44, 0x32, 0x9e, 0xc5, 0x8c, 0x6b, 0x0d, 0x86, 0x9b, 0x18, 0x74, 0x51, 0x83, 0xc3, 0xcb,
	0x0a, 0x14, 0x58, 0xc9, 0x2a, 0xb5, 0xda, 0xde, 0x55, 0xb1, 0x89, 0xca, 0xc0, 0x0b, 0x21, 0x65,
	0x29, 0x04, 0x71, 0x52, 0xc5, 0xbd, 0x60, 0xd5, 0x73, 0x12, 0x26, 0x50, 0x0a, 0x66, 0x39, 0x25,
	0x75, 0x23, 0x56, 0xce, 0xfb, 0xff, 0xe7, 0x0c, 0x27, 0x4a, 0xea, 0x49, 0x98, 0xfe, 0x19, 0x37,
	0x44, 0x1d, 0xe4, 0xde, 0xc6, 0xfb, 0xf7, 0x9a, 0x53, 0x3d, 0x94, 0x67, 0x84, 0xe0, 0x2e, 0x17,
	0x22, 0xa7, 0x68, 0x84, 0xc6, 0x7d, 0xdf, 0xea, 0xe3, 0xbd, 0x1f, 0x4b, 0x8a, 0x7e, 0x2d, 0x29,
	0xfa, 0xf0, 0xf6, 0x10, 0xb9, 0xef, 0x3a, 0x18, 0xaf, 0x3d, 0xe4, 0x0a, 0xee, 0x3d, 0x8b, 0x65,
	0x22, 0x0a, 0x8a, 0x46, 0xdb, 0xe3, 0xbe, 0xbf, 0x9a, 0xc8, 0x14, 0x6f, 0x3f, 0x97, 0x67, 0xb4,
	0x33, 0x42, 0xe3, 0xdd, 0x23, 0xea, 0x35, 0x4d, 0x79, 0x7f, 0x7d, 0x6f, 0xd6, 0x9d, 0x7f, 0x39,
	0xdc, 0xf2, 0x2b, 0x94, 0x4c, 0xf1, 0x5e, 0x50, 0xc6, 0x89, 0x78, 0x9a, 0xf2, 0xc2, 0xc8, 0x9c,
	0x76, 0xab, 0x5f, 0x98, 0xed, 0xbf, 0x3f, 0xa7, 0xe8, 0xf5, 0xc7, 0xab, 0x3b, 0x1a, 0xc2, 0x34,
	0xf3, 0x77, 0x2d, 0xf2, 0xc8, 0x12, 0xe4, 0x16, 0xc6, 0xb5, 0x23, 0x92, 0x5c, 0xd0, 0x9d, 0x36,
	0xbe, 0x6f, 0x81, 0x07, 0x92, 0x8b, 0x75, 0x3e, 0x2f, 0x4d, 0x04, 0x39, 0xed, 0xfd, 0x3b, 0xff,
	0xc4, 0x12, 0xe4, 0x06, 0xbe, 0x18, 0x41, 0x61, 0x34, 0x4f, 0x25, 0xbd, 0xd0, 0x46, 0x37, 0xaf,
	0xeb, 0x8e, 0x7e, 0x2e, 0x29, 0x7a, 0x79, 0x4e, 0xd1, 0x91, 0xde, 0xac, 0xf5, 0x24, 0x8b, 0xc9,
	0x13, 0x7c, 0xe9, 0x71, 0x04, 0xa7, 0x1b, 0xbd, 0x1d, 0xb4, 0x56, 0x32, 0x6c, 0x5f, 0xbb, 0xd7,
	0x5e, 0x7d, 0xfe, 0xfe, 0xa6, 0x73, 0xe0, 0x0e, 0x58, 0x11, 0xc1, 0x29, 0x5b, 0xdf, 0xc4, 0x63,
	0x74, 0x73, 0x8a, 0x66, 0x83, 0xf9, 0x37, 0x67, 0x6b, 0xbe, 0x70, 0xd0, 0xa7, 0x85, 0x83, 0xbe,
	0x2e, 0x1c, 0x14, 0xf4, 0x6c, 0xc4, 0x9d, 0xdf, 0x01, 0x00, 0x00, 0xff, 0xff, 0xbb, 0xf0, 0x01,
	0xdd, 0xb5, 0x02, 0x00, 0x00,
}
