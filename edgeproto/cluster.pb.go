// Code generated by protoc-gen-gogo. DO NOT EDIT.
// source: cluster.proto

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

// ClusterKey uniquely identifies a Cluster.
type ClusterKey struct {
	// Cluster name
	Name string `protobuf:"bytes,1,opt,name=name,proto3" json:"name,omitempty"`
}

func (m *ClusterKey) Reset()                    { *m = ClusterKey{} }
func (m *ClusterKey) String() string            { return proto.CompactTextString(m) }
func (*ClusterKey) ProtoMessage()               {}
func (*ClusterKey) Descriptor() ([]byte, []int) { return fileDescriptorCluster, []int{0} }

// Clusters define a set of resources that are provided to one or more Apps tied to the cluster. The set of resources is defined by the Cluster flavor. The Cluster definition here is analogous to a Kubernetes cluster.
// Like Apps, a Cluster is merely a definition, but is not instantiated on any Cloudlets. ClusterInsts are Clusters instantiated on a particular Cloudlet.
// In comparison to ClusterFlavors which are fairly static and controller by administrators, Clusters are much more dynamic and created and deleted by the user.
type Cluster struct {
	// Fields are used for the Update API to specify which fields to apply
	Fields []string `protobuf:"bytes,1,rep,name=fields" json:"fields,omitempty"`
	// Unique key
	Key ClusterKey `protobuf:"bytes,2,opt,name=key" json:"key"`
	// Default flavor of the Cluster, may be overridden on the ClusterInst
	DefaultFlavor ClusterFlavorKey `protobuf:"bytes,3,opt,name=default_flavor,json=defaultFlavor" json:"default_flavor"`
	// Auto is set to true when automatically created by back-end (internal use only)
	Auto bool `protobuf:"varint,5,opt,name=auto,proto3" json:"auto,omitempty"`
}

func (m *Cluster) Reset()                    { *m = Cluster{} }
func (m *Cluster) String() string            { return proto.CompactTextString(m) }
func (*Cluster) ProtoMessage()               {}
func (*Cluster) Descriptor() ([]byte, []int) { return fileDescriptorCluster, []int{1} }

func init() {
	proto.RegisterType((*ClusterKey)(nil), "edgeproto.ClusterKey")
	proto.RegisterType((*Cluster)(nil), "edgeproto.Cluster")
}
func (this *ClusterKey) GoString() string {
	if this == nil {
		return "nil"
	}
	s := make([]string, 0, 5)
	s = append(s, "&edgeproto.ClusterKey{")
	s = append(s, "Name: "+fmt.Sprintf("%#v", this.Name)+",\n")
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

// Reference imports to suppress errors if they are not otherwise used.
var _ context.Context
var _ grpc.ClientConn

// This is a compile-time assertion to ensure that this generated file
// is compatible with the grpc package it is being compiled against.
const _ = grpc.SupportPackageIsVersion4

// Client API for ClusterApi service

type ClusterApiClient interface {
	// Create a Cluster
	CreateCluster(ctx context.Context, in *Cluster, opts ...grpc.CallOption) (*Result, error)
	// Delete a Cluster
	DeleteCluster(ctx context.Context, in *Cluster, opts ...grpc.CallOption) (*Result, error)
	// Update a Cluster
	UpdateCluster(ctx context.Context, in *Cluster, opts ...grpc.CallOption) (*Result, error)
	// Show Clusters
	ShowCluster(ctx context.Context, in *Cluster, opts ...grpc.CallOption) (ClusterApi_ShowClusterClient, error)
}

type clusterApiClient struct {
	cc *grpc.ClientConn
}

func NewClusterApiClient(cc *grpc.ClientConn) ClusterApiClient {
	return &clusterApiClient{cc}
}

func (c *clusterApiClient) CreateCluster(ctx context.Context, in *Cluster, opts ...grpc.CallOption) (*Result, error) {
	out := new(Result)
	err := grpc.Invoke(ctx, "/edgeproto.ClusterApi/CreateCluster", in, out, c.cc, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *clusterApiClient) DeleteCluster(ctx context.Context, in *Cluster, opts ...grpc.CallOption) (*Result, error) {
	out := new(Result)
	err := grpc.Invoke(ctx, "/edgeproto.ClusterApi/DeleteCluster", in, out, c.cc, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *clusterApiClient) UpdateCluster(ctx context.Context, in *Cluster, opts ...grpc.CallOption) (*Result, error) {
	out := new(Result)
	err := grpc.Invoke(ctx, "/edgeproto.ClusterApi/UpdateCluster", in, out, c.cc, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *clusterApiClient) ShowCluster(ctx context.Context, in *Cluster, opts ...grpc.CallOption) (ClusterApi_ShowClusterClient, error) {
	stream, err := grpc.NewClientStream(ctx, &_ClusterApi_serviceDesc.Streams[0], c.cc, "/edgeproto.ClusterApi/ShowCluster", opts...)
	if err != nil {
		return nil, err
	}
	x := &clusterApiShowClusterClient{stream}
	if err := x.ClientStream.SendMsg(in); err != nil {
		return nil, err
	}
	if err := x.ClientStream.CloseSend(); err != nil {
		return nil, err
	}
	return x, nil
}

type ClusterApi_ShowClusterClient interface {
	Recv() (*Cluster, error)
	grpc.ClientStream
}

type clusterApiShowClusterClient struct {
	grpc.ClientStream
}

func (x *clusterApiShowClusterClient) Recv() (*Cluster, error) {
	m := new(Cluster)
	if err := x.ClientStream.RecvMsg(m); err != nil {
		return nil, err
	}
	return m, nil
}

// Server API for ClusterApi service

type ClusterApiServer interface {
	// Create a Cluster
	CreateCluster(context.Context, *Cluster) (*Result, error)
	// Delete a Cluster
	DeleteCluster(context.Context, *Cluster) (*Result, error)
	// Update a Cluster
	UpdateCluster(context.Context, *Cluster) (*Result, error)
	// Show Clusters
	ShowCluster(*Cluster, ClusterApi_ShowClusterServer) error
}

func RegisterClusterApiServer(s *grpc.Server, srv ClusterApiServer) {
	s.RegisterService(&_ClusterApi_serviceDesc, srv)
}

func _ClusterApi_CreateCluster_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(Cluster)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(ClusterApiServer).CreateCluster(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/edgeproto.ClusterApi/CreateCluster",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(ClusterApiServer).CreateCluster(ctx, req.(*Cluster))
	}
	return interceptor(ctx, in, info, handler)
}

func _ClusterApi_DeleteCluster_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(Cluster)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(ClusterApiServer).DeleteCluster(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/edgeproto.ClusterApi/DeleteCluster",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(ClusterApiServer).DeleteCluster(ctx, req.(*Cluster))
	}
	return interceptor(ctx, in, info, handler)
}

func _ClusterApi_UpdateCluster_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(Cluster)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(ClusterApiServer).UpdateCluster(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/edgeproto.ClusterApi/UpdateCluster",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(ClusterApiServer).UpdateCluster(ctx, req.(*Cluster))
	}
	return interceptor(ctx, in, info, handler)
}

func _ClusterApi_ShowCluster_Handler(srv interface{}, stream grpc.ServerStream) error {
	m := new(Cluster)
	if err := stream.RecvMsg(m); err != nil {
		return err
	}
	return srv.(ClusterApiServer).ShowCluster(m, &clusterApiShowClusterServer{stream})
}

type ClusterApi_ShowClusterServer interface {
	Send(*Cluster) error
	grpc.ServerStream
}

type clusterApiShowClusterServer struct {
	grpc.ServerStream
}

func (x *clusterApiShowClusterServer) Send(m *Cluster) error {
	return x.ServerStream.SendMsg(m)
}

var _ClusterApi_serviceDesc = grpc.ServiceDesc{
	ServiceName: "edgeproto.ClusterApi",
	HandlerType: (*ClusterApiServer)(nil),
	Methods: []grpc.MethodDesc{
		{
			MethodName: "CreateCluster",
			Handler:    _ClusterApi_CreateCluster_Handler,
		},
		{
			MethodName: "DeleteCluster",
			Handler:    _ClusterApi_DeleteCluster_Handler,
		},
		{
			MethodName: "UpdateCluster",
			Handler:    _ClusterApi_UpdateCluster_Handler,
		},
	},
	Streams: []grpc.StreamDesc{
		{
			StreamName:    "ShowCluster",
			Handler:       _ClusterApi_ShowCluster_Handler,
			ServerStreams: true,
		},
	},
	Metadata: "cluster.proto",
}

func (m *ClusterKey) Marshal() (dAtA []byte, err error) {
	size := m.Size()
	dAtA = make([]byte, size)
	n, err := m.MarshalTo(dAtA)
	if err != nil {
		return nil, err
	}
	return dAtA[:n], nil
}

func (m *ClusterKey) MarshalTo(dAtA []byte) (int, error) {
	var i int
	_ = i
	var l int
	_ = l
	if len(m.Name) > 0 {
		dAtA[i] = 0xa
		i++
		i = encodeVarintCluster(dAtA, i, uint64(len(m.Name)))
		i += copy(dAtA[i:], m.Name)
	}
	return i, nil
}

func (m *Cluster) Marshal() (dAtA []byte, err error) {
	size := m.Size()
	dAtA = make([]byte, size)
	n, err := m.MarshalTo(dAtA)
	if err != nil {
		return nil, err
	}
	return dAtA[:n], nil
}

func (m *Cluster) MarshalTo(dAtA []byte) (int, error) {
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
	i = encodeVarintCluster(dAtA, i, uint64(m.Key.Size()))
	n1, err := m.Key.MarshalTo(dAtA[i:])
	if err != nil {
		return 0, err
	}
	i += n1
	dAtA[i] = 0x1a
	i++
	i = encodeVarintCluster(dAtA, i, uint64(m.DefaultFlavor.Size()))
	n2, err := m.DefaultFlavor.MarshalTo(dAtA[i:])
	if err != nil {
		return 0, err
	}
	i += n2
	if m.Auto {
		dAtA[i] = 0x28
		i++
		if m.Auto {
			dAtA[i] = 1
		} else {
			dAtA[i] = 0
		}
		i++
	}
	return i, nil
}

func encodeVarintCluster(dAtA []byte, offset int, v uint64) int {
	for v >= 1<<7 {
		dAtA[offset] = uint8(v&0x7f | 0x80)
		v >>= 7
		offset++
	}
	dAtA[offset] = uint8(v)
	return offset + 1
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
	return true
}

func (m *ClusterKey) CopyInFields(src *ClusterKey) {
	m.Name = src.Name
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

// Helper method to check that enums have valid values
func (m *ClusterKey) ValidateEnums() error {
	return nil
}

func (m *Cluster) Matches(o *Cluster, fopts ...MatchOpt) bool {
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
	if !m.DefaultFlavor.Matches(&o.DefaultFlavor, fopts...) {
		return false
	}
	if !opts.IgnoreBackend {
		if !opts.Filter || o.Auto != false {
			if o.Auto != m.Auto {
				return false
			}
		}
	}
	return true
}

const ClusterFieldKey = "2"
const ClusterFieldKeyName = "2.1"
const ClusterFieldDefaultFlavor = "3"
const ClusterFieldDefaultFlavorName = "3.1"
const ClusterFieldAuto = "5"

var ClusterAllFields = []string{
	ClusterFieldKeyName,
	ClusterFieldDefaultFlavorName,
	ClusterFieldAuto,
}

var ClusterAllFieldsMap = map[string]struct{}{
	ClusterFieldKeyName:           struct{}{},
	ClusterFieldDefaultFlavorName: struct{}{},
	ClusterFieldAuto:              struct{}{},
}

func (m *Cluster) DiffFields(o *Cluster, fields map[string]struct{}) {
	if m.Key.Name != o.Key.Name {
		fields[ClusterFieldKeyName] = struct{}{}
		fields[ClusterFieldKey] = struct{}{}
	}
	if m.DefaultFlavor.Name != o.DefaultFlavor.Name {
		fields[ClusterFieldDefaultFlavorName] = struct{}{}
		fields[ClusterFieldDefaultFlavor] = struct{}{}
	}
	if m.Auto != o.Auto {
		fields[ClusterFieldAuto] = struct{}{}
	}
}

func (m *Cluster) CopyInFields(src *Cluster) {
	fmap := MakeFieldMap(src.Fields)
	if _, set := fmap["2"]; set {
		if _, set := fmap["2.1"]; set {
			m.Key.Name = src.Key.Name
		}
	}
	if _, set := fmap["3"]; set {
		if _, set := fmap["3.1"]; set {
			m.DefaultFlavor.Name = src.DefaultFlavor.Name
		}
	}
	if _, set := fmap["5"]; set {
		m.Auto = src.Auto
	}
}

func (s *Cluster) HasFields() bool {
	return true
}

type ClusterStore struct {
	kvstore objstore.KVStore
}

func NewClusterStore(kvstore objstore.KVStore) ClusterStore {
	return ClusterStore{kvstore: kvstore}
}

func (s *ClusterStore) Create(m *Cluster, wait func(int64)) (*Result, error) {
	err := m.Validate(ClusterAllFieldsMap)
	if err != nil {
		return nil, err
	}
	key := objstore.DbKeyString("Cluster", m.GetKey())
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

func (s *ClusterStore) Update(m *Cluster, wait func(int64)) (*Result, error) {
	fmap := MakeFieldMap(m.Fields)
	err := m.Validate(fmap)
	if err != nil {
		return nil, err
	}
	key := objstore.DbKeyString("Cluster", m.GetKey())
	var vers int64 = 0
	curBytes, vers, _, err := s.kvstore.Get(key)
	if err != nil {
		return nil, err
	}
	var cur Cluster
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

func (s *ClusterStore) Put(m *Cluster, wait func(int64), ops ...objstore.KVOp) (*Result, error) {
	fmap := MakeFieldMap(m.Fields)
	err := m.Validate(fmap)
	if err != nil {
		return nil, err
	}
	key := objstore.DbKeyString("Cluster", m.GetKey())
	var val []byte
	curBytes, _, _, err := s.kvstore.Get(key)
	if err == nil {
		var cur Cluster
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

func (s *ClusterStore) Delete(m *Cluster, wait func(int64)) (*Result, error) {
	err := m.GetKey().Validate()
	if err != nil {
		return nil, err
	}
	key := objstore.DbKeyString("Cluster", m.GetKey())
	rev, err := s.kvstore.Delete(key)
	if err != nil {
		return nil, err
	}
	if wait != nil {
		wait(rev)
	}
	return &Result{}, err
}

func (s *ClusterStore) LoadOne(key string) (*Cluster, int64, error) {
	val, rev, _, err := s.kvstore.Get(key)
	if err != nil {
		return nil, 0, err
	}
	var obj Cluster
	err = json.Unmarshal(val, &obj)
	if err != nil {
		log.DebugLog(log.DebugLevelApi, "Failed to parse Cluster data", "val", string(val))
		return nil, 0, err
	}
	return &obj, rev, nil
}

func (s *ClusterStore) STMGet(stm concurrency.STM, key *ClusterKey, buf *Cluster) bool {
	keystr := objstore.DbKeyString("Cluster", key)
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

func (s *ClusterStore) STMPut(stm concurrency.STM, obj *Cluster) {
	keystr := objstore.DbKeyString("Cluster", obj.GetKey())
	val, _ := json.Marshal(obj)
	stm.Put(keystr, string(val))
}

func (s *ClusterStore) STMDel(stm concurrency.STM, key *ClusterKey) {
	keystr := objstore.DbKeyString("Cluster", key)
	stm.Del(keystr)
}

type ClusterKeyWatcher struct {
	cb func()
}

// ClusterCache caches Cluster objects in memory in a hash table
// and keeps them in sync with the database.
type ClusterCache struct {
	Objs        map[ClusterKey]*Cluster
	Mux         util.Mutex
	List        map[ClusterKey]struct{}
	NotifyCb    func(obj *ClusterKey, old *Cluster)
	UpdatedCb   func(old *Cluster, new *Cluster)
	KeyWatchers map[ClusterKey][]*ClusterKeyWatcher
}

func NewClusterCache() *ClusterCache {
	cache := ClusterCache{}
	InitClusterCache(&cache)
	return &cache
}

func InitClusterCache(cache *ClusterCache) {
	cache.Objs = make(map[ClusterKey]*Cluster)
	cache.KeyWatchers = make(map[ClusterKey][]*ClusterKeyWatcher)
}

func (c *ClusterCache) GetTypeString() string {
	return "Cluster"
}

func (c *ClusterCache) Get(key *ClusterKey, valbuf *Cluster) bool {
	c.Mux.Lock()
	defer c.Mux.Unlock()
	inst, found := c.Objs[*key]
	if found {
		*valbuf = *inst
	}
	return found
}

func (c *ClusterCache) HasKey(key *ClusterKey) bool {
	c.Mux.Lock()
	defer c.Mux.Unlock()
	_, found := c.Objs[*key]
	return found
}

func (c *ClusterCache) GetAllKeys(keys map[ClusterKey]struct{}) {
	c.Mux.Lock()
	defer c.Mux.Unlock()
	for key, _ := range c.Objs {
		keys[key] = struct{}{}
	}
}

func (c *ClusterCache) Update(in *Cluster, rev int64) {
	c.UpdateModFunc(&in.Key, rev, func(old *Cluster) (*Cluster, bool) {
		return in, true
	})
}

func (c *ClusterCache) UpdateModFunc(key *ClusterKey, rev int64, modFunc func(old *Cluster) (new *Cluster, changed bool)) {
	c.Mux.Lock()
	old := c.Objs[*key]
	new, changed := modFunc(old)
	if !changed {
		c.Mux.Unlock()
		return
	}
	if c.UpdatedCb != nil || c.NotifyCb != nil {
		if c.UpdatedCb != nil {
			newCopy := &Cluster{}
			*newCopy = *new
			defer c.UpdatedCb(old, newCopy)
		}
		if c.NotifyCb != nil {
			defer c.NotifyCb(&new.Key, old)
		}
	}
	c.Objs[new.Key] = new
	log.DebugLog(log.DebugLevelApi, "SyncUpdate Cluster", "obj", new, "rev", rev)
	c.Mux.Unlock()
	c.TriggerKeyWatchers(&new.Key)
}

func (c *ClusterCache) Delete(in *Cluster, rev int64) {
	c.Mux.Lock()
	old := c.Objs[in.Key]
	delete(c.Objs, in.Key)
	log.DebugLog(log.DebugLevelApi, "SyncDelete Cluster", "key", in.Key, "rev", rev)
	c.Mux.Unlock()
	if c.NotifyCb != nil {
		c.NotifyCb(&in.Key, old)
	}
	c.TriggerKeyWatchers(&in.Key)
}

func (c *ClusterCache) Prune(validKeys map[ClusterKey]struct{}) {
	notify := make(map[ClusterKey]*Cluster)
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

func (c *ClusterCache) GetCount() int {
	c.Mux.Lock()
	defer c.Mux.Unlock()
	return len(c.Objs)
}

func (c *ClusterCache) Flush(notifyId int64) {
}

func (c *ClusterCache) Show(filter *Cluster, cb func(ret *Cluster) error) error {
	log.DebugLog(log.DebugLevelApi, "Show Cluster", "count", len(c.Objs))
	c.Mux.Lock()
	defer c.Mux.Unlock()
	for _, obj := range c.Objs {
		if !obj.Matches(filter, MatchFilter()) {
			continue
		}
		log.DebugLog(log.DebugLevelApi, "Show Cluster", "obj", obj)
		err := cb(obj)
		if err != nil {
			return err
		}
	}
	return nil
}

func ClusterGenericNotifyCb(fn func(key *ClusterKey, old *Cluster)) func(objstore.ObjKey, objstore.Obj) {
	return func(objkey objstore.ObjKey, obj objstore.Obj) {
		fn(objkey.(*ClusterKey), obj.(*Cluster))
	}
}

func (c *ClusterCache) SetNotifyCb(fn func(obj *ClusterKey, old *Cluster)) {
	c.NotifyCb = fn
}

func (c *ClusterCache) SetUpdatedCb(fn func(old *Cluster, new *Cluster)) {
	c.UpdatedCb = fn
}

func (c *ClusterCache) WatchKey(key *ClusterKey, cb func()) context.CancelFunc {
	c.Mux.Lock()
	defer c.Mux.Unlock()
	list, ok := c.KeyWatchers[*key]
	if !ok {
		list = make([]*ClusterKeyWatcher, 0)
	}
	watcher := ClusterKeyWatcher{cb: cb}
	c.KeyWatchers[*key] = append(list, &watcher)
	log.DebugLog(log.DebugLevelApi, "Watching Cluster", "key", key)
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

func (c *ClusterCache) TriggerKeyWatchers(key *ClusterKey) {
	watchers := make([]*ClusterKeyWatcher, 0)
	c.Mux.Lock()
	if list, ok := c.KeyWatchers[*key]; ok {
		watchers = append(watchers, list...)
	}
	c.Mux.Unlock()
	for ii, _ := range watchers {
		watchers[ii].cb()
	}
}
func (c *ClusterCache) SyncUpdate(key, val []byte, rev int64) {
	obj := Cluster{}
	err := json.Unmarshal(val, &obj)
	if err != nil {
		log.WarnLog("Failed to parse Cluster data", "val", string(val))
		return
	}
	c.Update(&obj, rev)
	c.Mux.Lock()
	if c.List != nil {
		c.List[obj.Key] = struct{}{}
	}
	c.Mux.Unlock()
}

func (c *ClusterCache) SyncDelete(key []byte, rev int64) {
	obj := Cluster{}
	keystr := objstore.DbKeyPrefixRemove(string(key))
	ClusterKeyStringParse(keystr, &obj.Key)
	c.Delete(&obj, rev)
}

func (c *ClusterCache) SyncListStart() {
	c.List = make(map[ClusterKey]struct{})
}

func (c *ClusterCache) SyncListEnd() {
	deleted := make(map[ClusterKey]*Cluster)
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

func (m *Cluster) GetKey() objstore.ObjKey {
	return &m.Key
}

func CmpSortCluster(a Cluster, b Cluster) bool {
	return a.Key.GetKeyString() < b.Key.GetKeyString()
}

// Helper method to check that enums have valid values
// NOTE: ValidateEnums checks all Fields even if some are not set
func (m *Cluster) ValidateEnums() error {
	if err := m.Key.ValidateEnums(); err != nil {
		return err
	}
	if err := m.DefaultFlavor.ValidateEnums(); err != nil {
		return err
	}
	return nil
}

func (m *ClusterKey) Size() (n int) {
	var l int
	_ = l
	l = len(m.Name)
	if l > 0 {
		n += 1 + l + sovCluster(uint64(l))
	}
	return n
}

func (m *Cluster) Size() (n int) {
	var l int
	_ = l
	if len(m.Fields) > 0 {
		for _, s := range m.Fields {
			l = len(s)
			n += 1 + l + sovCluster(uint64(l))
		}
	}
	l = m.Key.Size()
	n += 1 + l + sovCluster(uint64(l))
	l = m.DefaultFlavor.Size()
	n += 1 + l + sovCluster(uint64(l))
	if m.Auto {
		n += 2
	}
	return n
}

func sovCluster(x uint64) (n int) {
	for {
		n++
		x >>= 7
		if x == 0 {
			break
		}
	}
	return n
}
func sozCluster(x uint64) (n int) {
	return sovCluster(uint64((x << 1) ^ uint64((int64(x) >> 63))))
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
			wire |= (uint64(b) & 0x7F) << shift
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
				stringLen |= (uint64(b) & 0x7F) << shift
				if b < 0x80 {
					break
				}
			}
			intStringLen := int(stringLen)
			if intStringLen < 0 {
				return ErrInvalidLengthCluster
			}
			postIndex := iNdEx + intStringLen
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
			if skippy < 0 {
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
func (m *Cluster) Unmarshal(dAtA []byte) error {
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
			wire |= (uint64(b) & 0x7F) << shift
			if b < 0x80 {
				break
			}
		}
		fieldNum := int32(wire >> 3)
		wireType := int(wire & 0x7)
		if wireType == 4 {
			return fmt.Errorf("proto: Cluster: wiretype end group for non-group")
		}
		if fieldNum <= 0 {
			return fmt.Errorf("proto: Cluster: illegal tag %d (wire type %d)", fieldNum, wire)
		}
		switch fieldNum {
		case 1:
			if wireType != 2 {
				return fmt.Errorf("proto: wrong wireType = %d for field Fields", wireType)
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
				stringLen |= (uint64(b) & 0x7F) << shift
				if b < 0x80 {
					break
				}
			}
			intStringLen := int(stringLen)
			if intStringLen < 0 {
				return ErrInvalidLengthCluster
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
					return ErrIntOverflowCluster
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
				return ErrInvalidLengthCluster
			}
			postIndex := iNdEx + msglen
			if postIndex > l {
				return io.ErrUnexpectedEOF
			}
			if err := m.Key.Unmarshal(dAtA[iNdEx:postIndex]); err != nil {
				return err
			}
			iNdEx = postIndex
		case 3:
			if wireType != 2 {
				return fmt.Errorf("proto: wrong wireType = %d for field DefaultFlavor", wireType)
			}
			var msglen int
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowCluster
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
				return ErrInvalidLengthCluster
			}
			postIndex := iNdEx + msglen
			if postIndex > l {
				return io.ErrUnexpectedEOF
			}
			if err := m.DefaultFlavor.Unmarshal(dAtA[iNdEx:postIndex]); err != nil {
				return err
			}
			iNdEx = postIndex
		case 5:
			if wireType != 0 {
				return fmt.Errorf("proto: wrong wireType = %d for field Auto", wireType)
			}
			var v int
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowCluster
				}
				if iNdEx >= l {
					return io.ErrUnexpectedEOF
				}
				b := dAtA[iNdEx]
				iNdEx++
				v |= (int(b) & 0x7F) << shift
				if b < 0x80 {
					break
				}
			}
			m.Auto = bool(v != 0)
		default:
			iNdEx = preIndex
			skippy, err := skipCluster(dAtA[iNdEx:])
			if err != nil {
				return err
			}
			if skippy < 0 {
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
			return iNdEx, nil
		case 1:
			iNdEx += 8
			return iNdEx, nil
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
			iNdEx += length
			if length < 0 {
				return 0, ErrInvalidLengthCluster
			}
			return iNdEx, nil
		case 3:
			for {
				var innerWire uint64
				var start int = iNdEx
				for shift := uint(0); ; shift += 7 {
					if shift >= 64 {
						return 0, ErrIntOverflowCluster
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
				next, err := skipCluster(dAtA[start:])
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
	ErrInvalidLengthCluster = fmt.Errorf("proto: negative length found during unmarshaling")
	ErrIntOverflowCluster   = fmt.Errorf("proto: integer overflow")
)

func init() { proto.RegisterFile("cluster.proto", fileDescriptorCluster) }

var fileDescriptorCluster = []byte{
	// 518 bytes of a gzipped FileDescriptorProto
	0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0xff, 0xbc, 0x52, 0x41, 0x8b, 0xd3, 0x40,
	0x14, 0xde, 0xd9, 0xc6, 0xd5, 0xce, 0x6e, 0x5d, 0x1d, 0x57, 0x19, 0xeb, 0xd2, 0x2d, 0xb9, 0x58,
	0x65, 0x9b, 0xc8, 0x7a, 0x91, 0xde, 0xda, 0x8a, 0x2b, 0x88, 0x97, 0x88, 0x5e, 0x65, 0x9a, 0xbc,
	0xa6, 0x61, 0xa7, 0x99, 0x90, 0x4c, 0xb6, 0x2e, 0x08, 0x8a, 0x47, 0x41, 0x10, 0xbc, 0x78, 0xf4,
	0xe8, 0x51, 0xfc, 0x15, 0x3d, 0x8a, 0xde, 0x45, 0x8b, 0x07, 0xd9, 0x93, 0xd0, 0x1c, 0x3c, 0x4a,
	0x26, 0x49, 0xb7, 0x58, 0x15, 0x4f, 0x7b, 0x09, 0xdf, 0xfb, 0xf2, 0xbe, 0x7c, 0xdf, 0x7b, 0x2f,
	0xb8, 0x62, 0xf3, 0x38, 0x92, 0x10, 0x1a, 0x41, 0x28, 0xa4, 0x20, 0x65, 0x70, 0x5c, 0x50, 0xb0,
	0xba, 0xe9, 0x0a, 0xe1, 0x72, 0x30, 0x59, 0xe0, 0x99, 0xcc, 0xf7, 0x85, 0x64, 0xd2, 0x13, 0x7e,
	0x94, 0x35, 0x56, 0x6f, 0xb8, 0x9e, 0x1c, 0xc4, 0x3d, 0xc3, 0x16, 0x43, 0x73, 0x28, 0x7a, 0x1e,
	0x4f, 0x85, 0x8f, 0xcc, 0xf4, 0xd9, 0xb4, 0xb9, 0x88, 0x1d, 0x53, 0xf5, 0xb9, 0xe0, 0xcf, 0x40,
	0xae, 0xdc, 0xfd, 0x3f, 0xa5, 0xdd, 0x74, 0xc1, 0x6f, 0xda, 0xc3, 0xa2, 0x9c, 0x03, 0xf9, 0x87,
	0xd6, 0x42, 0x88, 0x62, 0x2e, 0xf3, 0x6a, 0xdd, 0x81, 0x7d, 0xe0, 0x22, 0x28, 0x46, 0xa9, 0x9e,
	0xcb, 0x27, 0xeb, 0x73, 0xb6, 0x2f, 0x0a, 0x72, 0xc3, 0x15, 0xae, 0x50, 0xd0, 0x4c, 0x51, 0xc6,
	0xea, 0x06, 0xc6, 0xdd, 0xac, 0xf9, 0x0e, 0x1c, 0x10, 0x82, 0x35, 0x9f, 0x0d, 0x81, 0xa2, 0x3a,
	0x6a, 0x94, 0x2d, 0x85, 0x5b, 0x6b, 0xdf, 0xa7, 0x14, 0xfd, 0x9c, 0x52, 0xf4, 0xee, 0xcd, 0x16,
	0xd2, 0x3f, 0x22, 0x7c, 0x32, 0x17, 0x90, 0x0b, 0x78, 0xa5, 0xef, 0x01, 0x77, 0x22, 0x8a, 0xea,
	0xa5, 0x46, 0xd9, 0xca, 0x2b, 0xd2, 0xc4, 0xa5, 0x3d, 0x38, 0xa0, 0xcb, 0x75, 0xd4, 0x58, 0xdd,
	0x39, 0x6f, 0xcc, 0xf6, 0x6a, 0x1c, 0x39, 0x75, 0xb4, 0xf1, 0xe7, 0xad, 0x25, 0x2b, 0xed, 0x23,
	0xb7, 0xf1, 0x69, 0x07, 0xfa, 0x2c, 0xe6, 0xf2, 0x61, 0x16, 0x98, 0x96, 0x94, 0xf2, 0xd2, 0xa2,
	0xf2, 0x96, 0x7a, 0x7f, 0xa4, 0xaf, 0xe4, 0xc2, 0x8c, 0x27, 0x14, 0x6b, 0x2c, 0x96, 0x82, 0x9e,
	0xa8, 0xa3, 0xc6, 0xa9, 0x8e, 0xf6, 0x36, 0xa1, 0xc8, 0x52, 0x4c, 0x6b, 0x33, 0x1d, 0xe2, 0xc7,
	0x94, 0xa2, 0xa7, 0x09, 0x45, 0x2f, 0x13, 0x8a, 0x5e, 0x27, 0x14, 0x3d, 0x7f, 0x7f, 0x51, 0x6b,
	0xc7, 0x52, 0xec, 0xbc, 0xd0, 0x66, 0x5b, 0x68, 0x07, 0x1e, 0x79, 0x82, 0x2b, 0xdd, 0x10, 0x98,
	0x84, 0x62, 0x50, 0xb2, 0x98, 0xa4, 0x7a, 0x76, 0x8e, 0xb3, 0xd4, 0x35, 0xf4, 0xdd, 0xc3, 0x84,
	0x5e, 0xb1, 0x20, 0x12, 0x71, 0x68, 0x17, 0xda, 0x68, 0xbb, 0x6d, 0xa7, 0x3f, 0xcf, 0x5d, 0xe6,
	0x33, 0x17, 0xb6, 0xa3, 0x3d, 0x2f, 0x00, 0xbf, 0x2f, 0x42, 0x1b, 0x9e, 0x7d, 0xfa, 0xf6, 0x6a,
	0x79, 0x43, 0x5f, 0x37, 0x6d, 0xe5, 0x65, 0xe6, 0x37, 0x6b, 0xa1, 0xab, 0x69, 0x80, 0x9b, 0xc0,
	0xe1, 0xb8, 0x02, 0x38, 0xca, 0xeb, 0xb7, 0x00, 0xf7, 0x03, 0xe7, 0xd8, 0x36, 0x10, 0x2b, 0xaf,
	0xf9, 0x00, 0x8f, 0xf1, 0xea, 0xbd, 0x81, 0x18, 0xfd, 0xcb, 0xfe, 0x0f, 0x9c, 0xde, 0x3d, 0x4c,
	0xe8, 0xe5, 0xbf, 0xf8, 0x3f, 0xf0, 0x60, 0xb4, 0xe0, 0x4e, 0xf4, 0x8a, 0x19, 0x0d, 0xc4, 0x68,
	0xce, 0xfb, 0x1a, 0xea, 0x9c, 0x19, 0x7f, 0xad, 0x2d, 0x8d, 0x27, 0x35, 0xf4, 0x61, 0x52, 0x43,
	0x5f, 0x26, 0x35, 0xd4, 0x5b, 0x51, 0x3e, 0xd7, 0x7f, 0x05, 0x00, 0x00, 0xff, 0xff, 0x38, 0xb9,
	0xea, 0x5e, 0x34, 0x04, 0x00, 0x00,
}
