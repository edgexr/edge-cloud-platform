// Code generated by protoc-gen-gogo. DO NOT EDIT.
// source: app.proto

/*
	Package edgeproto is a generated protocol buffer package.

	It is generated from these files:
		app.proto
		app_inst.proto
		cloud-resource-manager.proto
		cloudlet.proto
		developer.proto
		notice.proto
		operator.proto
		result.proto

	It has these top-level messages:
		AppKey
		App
		AppInstKey
		AppInst
		CloudResource
		EdgeCloudApp
		EdgeCloudApplication
		CloudletKey
		Cloudlet
		DeveloperKey
		Developer
		NoticeReply
		NoticeRequest
		OperatorCode
		OperatorKey
		Operator
		Result
*/
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

// key that uniquely identifies an application
// It is important that embedded structs are not referenced by a
// pointer, otherwise the enclosing struct cannot properly function
// as the key to a hash table. Thus embedded structs have nullable false.
type AppKey struct {
	// developer key
	DeveloperKey DeveloperKey `protobuf:"bytes,1,opt,name=developer_key,json=developerKey" json:"developer_key"`
	// application name
	Name string `protobuf:"bytes,2,opt,name=name,proto3" json:"name,omitempty"`
	// version of the app
	Version string `protobuf:"bytes,3,opt,name=version,proto3" json:"version,omitempty"`
}

func (m *AppKey) Reset()                    { *m = AppKey{} }
func (m *AppKey) String() string            { return proto.CompactTextString(m) }
func (*AppKey) ProtoMessage()               {}
func (*AppKey) Descriptor() ([]byte, []int) { return fileDescriptorApp, []int{0} }

// Applications are created and uploaded by developers
// Only registered applications can access location and cloudlet services
type App struct {
	Fields []string `protobuf:"bytes,1,rep,name=fields" json:"fields,omitempty"`
	// Unique identifier key
	Key AppKey `protobuf:"bytes,2,opt,name=key" json:"key"`
	// Path to the application binary on shared storage
	AppPath string `protobuf:"bytes,4,opt,name=app_path,json=appPath,proto3" json:"app_path,omitempty"`
}

func (m *App) Reset()                    { *m = App{} }
func (m *App) String() string            { return proto.CompactTextString(m) }
func (*App) ProtoMessage()               {}
func (*App) Descriptor() ([]byte, []int) { return fileDescriptorApp, []int{1} }

func init() {
	proto.RegisterType((*AppKey)(nil), "edgeproto.AppKey")
	proto.RegisterType((*App)(nil), "edgeproto.App")
}
func (this *AppKey) GoString() string {
	if this == nil {
		return "nil"
	}
	s := make([]string, 0, 7)
	s = append(s, "&edgeproto.AppKey{")
	s = append(s, "DeveloperKey: "+strings.Replace(this.DeveloperKey.GoString(), `&`, ``, 1)+",\n")
	s = append(s, "Name: "+fmt.Sprintf("%#v", this.Name)+",\n")
	s = append(s, "Version: "+fmt.Sprintf("%#v", this.Version)+",\n")
	s = append(s, "}")
	return strings.Join(s, "")
}
func valueToGoStringApp(v interface{}, typ string) string {
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

// Client API for AppApi service

type AppApiClient interface {
	CreateApp(ctx context.Context, in *App, opts ...grpc.CallOption) (*Result, error)
	DeleteApp(ctx context.Context, in *App, opts ...grpc.CallOption) (*Result, error)
	UpdateApp(ctx context.Context, in *App, opts ...grpc.CallOption) (*Result, error)
	ShowApp(ctx context.Context, in *App, opts ...grpc.CallOption) (AppApi_ShowAppClient, error)
}

type appApiClient struct {
	cc *grpc.ClientConn
}

func NewAppApiClient(cc *grpc.ClientConn) AppApiClient {
	return &appApiClient{cc}
}

func (c *appApiClient) CreateApp(ctx context.Context, in *App, opts ...grpc.CallOption) (*Result, error) {
	out := new(Result)
	err := grpc.Invoke(ctx, "/edgeproto.AppApi/CreateApp", in, out, c.cc, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *appApiClient) DeleteApp(ctx context.Context, in *App, opts ...grpc.CallOption) (*Result, error) {
	out := new(Result)
	err := grpc.Invoke(ctx, "/edgeproto.AppApi/DeleteApp", in, out, c.cc, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *appApiClient) UpdateApp(ctx context.Context, in *App, opts ...grpc.CallOption) (*Result, error) {
	out := new(Result)
	err := grpc.Invoke(ctx, "/edgeproto.AppApi/UpdateApp", in, out, c.cc, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *appApiClient) ShowApp(ctx context.Context, in *App, opts ...grpc.CallOption) (AppApi_ShowAppClient, error) {
	stream, err := grpc.NewClientStream(ctx, &_AppApi_serviceDesc.Streams[0], c.cc, "/edgeproto.AppApi/ShowApp", opts...)
	if err != nil {
		return nil, err
	}
	x := &appApiShowAppClient{stream}
	if err := x.ClientStream.SendMsg(in); err != nil {
		return nil, err
	}
	if err := x.ClientStream.CloseSend(); err != nil {
		return nil, err
	}
	return x, nil
}

type AppApi_ShowAppClient interface {
	Recv() (*App, error)
	grpc.ClientStream
}

type appApiShowAppClient struct {
	grpc.ClientStream
}

func (x *appApiShowAppClient) Recv() (*App, error) {
	m := new(App)
	if err := x.ClientStream.RecvMsg(m); err != nil {
		return nil, err
	}
	return m, nil
}

// Server API for AppApi service

type AppApiServer interface {
	CreateApp(context.Context, *App) (*Result, error)
	DeleteApp(context.Context, *App) (*Result, error)
	UpdateApp(context.Context, *App) (*Result, error)
	ShowApp(*App, AppApi_ShowAppServer) error
}

func RegisterAppApiServer(s *grpc.Server, srv AppApiServer) {
	s.RegisterService(&_AppApi_serviceDesc, srv)
}

func _AppApi_CreateApp_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(App)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(AppApiServer).CreateApp(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/edgeproto.AppApi/CreateApp",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(AppApiServer).CreateApp(ctx, req.(*App))
	}
	return interceptor(ctx, in, info, handler)
}

func _AppApi_DeleteApp_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(App)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(AppApiServer).DeleteApp(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/edgeproto.AppApi/DeleteApp",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(AppApiServer).DeleteApp(ctx, req.(*App))
	}
	return interceptor(ctx, in, info, handler)
}

func _AppApi_UpdateApp_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(App)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(AppApiServer).UpdateApp(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/edgeproto.AppApi/UpdateApp",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(AppApiServer).UpdateApp(ctx, req.(*App))
	}
	return interceptor(ctx, in, info, handler)
}

func _AppApi_ShowApp_Handler(srv interface{}, stream grpc.ServerStream) error {
	m := new(App)
	if err := stream.RecvMsg(m); err != nil {
		return err
	}
	return srv.(AppApiServer).ShowApp(m, &appApiShowAppServer{stream})
}

type AppApi_ShowAppServer interface {
	Send(*App) error
	grpc.ServerStream
}

type appApiShowAppServer struct {
	grpc.ServerStream
}

func (x *appApiShowAppServer) Send(m *App) error {
	return x.ServerStream.SendMsg(m)
}

var _AppApi_serviceDesc = grpc.ServiceDesc{
	ServiceName: "edgeproto.AppApi",
	HandlerType: (*AppApiServer)(nil),
	Methods: []grpc.MethodDesc{
		{
			MethodName: "CreateApp",
			Handler:    _AppApi_CreateApp_Handler,
		},
		{
			MethodName: "DeleteApp",
			Handler:    _AppApi_DeleteApp_Handler,
		},
		{
			MethodName: "UpdateApp",
			Handler:    _AppApi_UpdateApp_Handler,
		},
	},
	Streams: []grpc.StreamDesc{
		{
			StreamName:    "ShowApp",
			Handler:       _AppApi_ShowApp_Handler,
			ServerStreams: true,
		},
	},
	Metadata: "app.proto",
}

func (m *AppKey) Marshal() (dAtA []byte, err error) {
	size := m.Size()
	dAtA = make([]byte, size)
	n, err := m.MarshalTo(dAtA)
	if err != nil {
		return nil, err
	}
	return dAtA[:n], nil
}

func (m *AppKey) MarshalTo(dAtA []byte) (int, error) {
	var i int
	_ = i
	var l int
	_ = l
	dAtA[i] = 0xa
	i++
	i = encodeVarintApp(dAtA, i, uint64(m.DeveloperKey.Size()))
	n1, err := m.DeveloperKey.MarshalTo(dAtA[i:])
	if err != nil {
		return 0, err
	}
	i += n1
	if len(m.Name) > 0 {
		dAtA[i] = 0x12
		i++
		i = encodeVarintApp(dAtA, i, uint64(len(m.Name)))
		i += copy(dAtA[i:], m.Name)
	}
	if len(m.Version) > 0 {
		dAtA[i] = 0x1a
		i++
		i = encodeVarintApp(dAtA, i, uint64(len(m.Version)))
		i += copy(dAtA[i:], m.Version)
	}
	return i, nil
}

func (m *App) Marshal() (dAtA []byte, err error) {
	size := m.Size()
	dAtA = make([]byte, size)
	n, err := m.MarshalTo(dAtA)
	if err != nil {
		return nil, err
	}
	return dAtA[:n], nil
}

func (m *App) MarshalTo(dAtA []byte) (int, error) {
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
	i = encodeVarintApp(dAtA, i, uint64(m.Key.Size()))
	n2, err := m.Key.MarshalTo(dAtA[i:])
	if err != nil {
		return 0, err
	}
	i += n2
	if len(m.AppPath) > 0 {
		dAtA[i] = 0x22
		i++
		i = encodeVarintApp(dAtA, i, uint64(len(m.AppPath)))
		i += copy(dAtA[i:], m.AppPath)
	}
	return i, nil
}

func encodeVarintApp(dAtA []byte, offset int, v uint64) int {
	for v >= 1<<7 {
		dAtA[offset] = uint8(v&0x7f | 0x80)
		v >>= 7
		offset++
	}
	dAtA[offset] = uint8(v)
	return offset + 1
}
func (m *AppKey) Matches(filter *AppKey) bool {
	if filter == nil {
		return true
	}
	if !m.DeveloperKey.Matches(&filter.DeveloperKey) {
		return false
	}
	if filter.Name != "" && filter.Name != m.Name {
		return false
	}
	if filter.Version != "" && filter.Version != m.Version {
		return false
	}
	return true
}

func (m *AppKey) CopyInFields(src *AppKey) {
	m.DeveloperKey.Name = src.DeveloperKey.Name
	m.Name = src.Name
	m.Version = src.Version
}

func (m *AppKey) GetKeyString() string {
	key, err := json.Marshal(m)
	if err != nil {
		util.FatalLog("Failed to marshal AppKey key string", "obj", m)
	}
	return string(key)
}

func AppKeyStringParse(str string, key *AppKey) {
	err := json.Unmarshal([]byte(str), key)
	if err != nil {
		util.FatalLog("Failed to unmarshal AppKey key string", "str", str)
	}
}

func (m *App) Matches(filter *App) bool {
	if filter == nil {
		return true
	}
	if !m.Key.Matches(&filter.Key) {
		return false
	}
	if filter.AppPath != "" && filter.AppPath != m.AppPath {
		return false
	}
	return true
}

const AppFieldKey = "2"
const AppFieldKeyDeveloperKey = "2.1"
const AppFieldKeyDeveloperKeyName = "2.1.2"
const AppFieldKeyName = "2.2"
const AppFieldKeyVersion = "2.3"
const AppFieldAppPath = "4"

var AppAllFields = []string{
	AppFieldKeyDeveloperKeyName,
	AppFieldKeyName,
	AppFieldKeyVersion,
	AppFieldAppPath,
}

var AppAllFieldsMap = map[string]struct{}{
	AppFieldKeyDeveloperKeyName: struct{}{},
	AppFieldKeyName:             struct{}{},
	AppFieldKeyVersion:          struct{}{},
	AppFieldAppPath:             struct{}{},
}

func (m *App) CopyInFields(src *App) {
	fmap := MakeFieldMap(src.Fields)
	if _, set := fmap["2"]; set {
		if _, set := fmap["2.1"]; set {
			if _, set := fmap["2.1.2"]; set {
				m.Key.DeveloperKey.Name = src.Key.DeveloperKey.Name
			}
		}
		if _, set := fmap["2.2"]; set {
			m.Key.Name = src.Key.Name
		}
		if _, set := fmap["2.3"]; set {
			m.Key.Version = src.Key.Version
		}
	}
	if _, set := fmap["4"]; set {
		m.AppPath = src.AppPath
	}
}

func (s *App) HasFields() bool {
	return true
}

type AppStore struct {
	objstore objstore.ObjStore
}

func NewAppStore(objstore objstore.ObjStore) AppStore {
	return AppStore{objstore: objstore}
}

func (s *AppStore) Create(m *App, wait func(int64)) (*Result, error) {
	err := m.Validate(AppAllFieldsMap)
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

func (s *AppStore) Update(m *App, wait func(int64)) (*Result, error) {
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
	var cur App
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

func (s *AppStore) Delete(m *App, wait func(int64)) (*Result, error) {
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

type AppCb func(m *App) error

func (s *AppStore) LoadAll(cb AppCb) error {
	loadkey := objstore.DbKeyPrefixString(&AppKey{})
	err := s.objstore.List(loadkey, func(key, val []byte, rev int64) error {
		var obj App
		err := json.Unmarshal(val, &obj)
		if err != nil {
			util.WarnLog("Failed to parse App data", "val", string(val))
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

func (s *AppStore) LoadOne(key string) (*App, int64, error) {
	val, rev, err := s.objstore.Get(key)
	if err != nil {
		return nil, 0, err
	}
	var obj App
	err = json.Unmarshal(val, &obj)
	if err != nil {
		util.DebugLog(util.DebugLevelApi, "Failed to parse App data", "val", string(val))
		return nil, 0, err
	}
	return &obj, rev, nil
}

// AppCache caches App objects in memory in a hash table
// and keeps them in sync with the database.
type AppCache struct {
	Objs      map[AppKey]*App
	Mux       util.Mutex
	List      map[AppKey]struct{}
	NotifyCb  func(obj *AppKey)
	UpdatedCb func(old *App, new *App)
}

func InitAppCache(cache *AppCache) {
	cache.Objs = make(map[AppKey]*App)
}

func (c *AppCache) Get(key *AppKey, valbuf *App) bool {
	c.Mux.Lock()
	defer c.Mux.Unlock()
	inst, found := c.Objs[*key]
	if found {
		*valbuf = *inst
	}
	return found
}

func (c *AppCache) HasKey(key *AppKey) bool {
	c.Mux.Lock()
	defer c.Mux.Unlock()
	_, found := c.Objs[*key]
	return found
}

func (c *AppCache) GetAllKeys(keys map[AppKey]struct{}) {
	c.Mux.Lock()
	defer c.Mux.Unlock()
	for key, _ := range c.Objs {
		keys[key] = struct{}{}
	}
}

func (c *AppCache) Update(in *App, rev int64) {
	c.Mux.Lock()
	if c.UpdatedCb != nil {
		old := c.Objs[*in.GetKey()]
		new := &App{}
		*new = *in
		defer c.UpdatedCb(old, new)
	}
	c.Objs[*in.GetKey()] = in
	util.DebugLog(util.DebugLevelApi, "SyncUpdate", "obj", in, "rev", rev)
	c.Mux.Unlock()
	if c.NotifyCb != nil {
		c.NotifyCb(in.GetKey())
	}
}

func (c *AppCache) Delete(in *App, rev int64) {
	c.Mux.Lock()
	delete(c.Objs, *in.GetKey())
	util.DebugLog(util.DebugLevelApi, "SyncUpdate", "key", in.GetKey(), "rev", rev)
	c.Mux.Unlock()
	if c.NotifyCb != nil {
		c.NotifyCb(in.GetKey())
	}
}

func (c *AppCache) Show(filter *App, cb func(ret *App) error) error {
	util.DebugLog(util.DebugLevelApi, "Show App", "count", len(c.Objs))
	c.Mux.Lock()
	defer c.Mux.Unlock()
	for _, obj := range c.Objs {
		if !obj.Matches(filter) {
			continue
		}
		util.DebugLog(util.DebugLevelApi, "Show App", "obj", obj)
		err := cb(obj)
		if err != nil {
			return err
		}
	}
	return nil
}

func (c *AppCache) SetNotifyCb(fn func(obj *AppKey)) {
	c.NotifyCb = fn
}

func (c *AppCache) SetUpdatedCb(fn func(old *App, new *App)) {
	c.UpdatedCb = fn
}

func (c *AppCache) SyncUpdate(key, val []byte, rev int64) {
	obj := App{}
	err := json.Unmarshal(val, &obj)
	if err != nil {
		util.WarnLog("Failed to parse App data", "val", string(val))
		return
	}
	c.Update(&obj, rev)
	c.Mux.Lock()
	if c.List != nil {
		c.List[obj.Key] = struct{}{}
	}
	c.Mux.Unlock()
}

func (c *AppCache) SyncDelete(key []byte, rev int64) {
	obj := App{}
	keystr := objstore.DbKeyPrefixRemove(string(key))
	AppKeyStringParse(keystr, obj.GetKey())
	c.Delete(&obj, rev)
}

func (c *AppCache) SyncListStart() {
	c.List = make(map[AppKey]struct{})
}

func (c *AppCache) SyncListEnd() {
	deleted := make(map[AppKey]struct{})
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

func (m *App) GetKey() *AppKey {
	return &m.Key
}

func (m *AppKey) Size() (n int) {
	var l int
	_ = l
	l = m.DeveloperKey.Size()
	n += 1 + l + sovApp(uint64(l))
	l = len(m.Name)
	if l > 0 {
		n += 1 + l + sovApp(uint64(l))
	}
	l = len(m.Version)
	if l > 0 {
		n += 1 + l + sovApp(uint64(l))
	}
	return n
}

func (m *App) Size() (n int) {
	var l int
	_ = l
	if len(m.Fields) > 0 {
		for _, s := range m.Fields {
			l = len(s)
			n += 1 + l + sovApp(uint64(l))
		}
	}
	l = m.Key.Size()
	n += 1 + l + sovApp(uint64(l))
	l = len(m.AppPath)
	if l > 0 {
		n += 1 + l + sovApp(uint64(l))
	}
	return n
}

func sovApp(x uint64) (n int) {
	for {
		n++
		x >>= 7
		if x == 0 {
			break
		}
	}
	return n
}
func sozApp(x uint64) (n int) {
	return sovApp(uint64((x << 1) ^ uint64((int64(x) >> 63))))
}
func (m *AppKey) Unmarshal(dAtA []byte) error {
	l := len(dAtA)
	iNdEx := 0
	for iNdEx < l {
		preIndex := iNdEx
		var wire uint64
		for shift := uint(0); ; shift += 7 {
			if shift >= 64 {
				return ErrIntOverflowApp
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
			return fmt.Errorf("proto: AppKey: wiretype end group for non-group")
		}
		if fieldNum <= 0 {
			return fmt.Errorf("proto: AppKey: illegal tag %d (wire type %d)", fieldNum, wire)
		}
		switch fieldNum {
		case 1:
			if wireType != 2 {
				return fmt.Errorf("proto: wrong wireType = %d for field DeveloperKey", wireType)
			}
			var msglen int
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowApp
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
				return ErrInvalidLengthApp
			}
			postIndex := iNdEx + msglen
			if postIndex > l {
				return io.ErrUnexpectedEOF
			}
			if err := m.DeveloperKey.Unmarshal(dAtA[iNdEx:postIndex]); err != nil {
				return err
			}
			iNdEx = postIndex
		case 2:
			if wireType != 2 {
				return fmt.Errorf("proto: wrong wireType = %d for field Name", wireType)
			}
			var stringLen uint64
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowApp
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
				return ErrInvalidLengthApp
			}
			postIndex := iNdEx + intStringLen
			if postIndex > l {
				return io.ErrUnexpectedEOF
			}
			m.Name = string(dAtA[iNdEx:postIndex])
			iNdEx = postIndex
		case 3:
			if wireType != 2 {
				return fmt.Errorf("proto: wrong wireType = %d for field Version", wireType)
			}
			var stringLen uint64
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowApp
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
				return ErrInvalidLengthApp
			}
			postIndex := iNdEx + intStringLen
			if postIndex > l {
				return io.ErrUnexpectedEOF
			}
			m.Version = string(dAtA[iNdEx:postIndex])
			iNdEx = postIndex
		default:
			iNdEx = preIndex
			skippy, err := skipApp(dAtA[iNdEx:])
			if err != nil {
				return err
			}
			if skippy < 0 {
				return ErrInvalidLengthApp
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
func (m *App) Unmarshal(dAtA []byte) error {
	l := len(dAtA)
	iNdEx := 0
	for iNdEx < l {
		preIndex := iNdEx
		var wire uint64
		for shift := uint(0); ; shift += 7 {
			if shift >= 64 {
				return ErrIntOverflowApp
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
			return fmt.Errorf("proto: App: wiretype end group for non-group")
		}
		if fieldNum <= 0 {
			return fmt.Errorf("proto: App: illegal tag %d (wire type %d)", fieldNum, wire)
		}
		switch fieldNum {
		case 1:
			if wireType != 2 {
				return fmt.Errorf("proto: wrong wireType = %d for field Fields", wireType)
			}
			var stringLen uint64
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowApp
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
				return ErrInvalidLengthApp
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
					return ErrIntOverflowApp
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
				return ErrInvalidLengthApp
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
				return fmt.Errorf("proto: wrong wireType = %d for field AppPath", wireType)
			}
			var stringLen uint64
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowApp
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
				return ErrInvalidLengthApp
			}
			postIndex := iNdEx + intStringLen
			if postIndex > l {
				return io.ErrUnexpectedEOF
			}
			m.AppPath = string(dAtA[iNdEx:postIndex])
			iNdEx = postIndex
		default:
			iNdEx = preIndex
			skippy, err := skipApp(dAtA[iNdEx:])
			if err != nil {
				return err
			}
			if skippy < 0 {
				return ErrInvalidLengthApp
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
func skipApp(dAtA []byte) (n int, err error) {
	l := len(dAtA)
	iNdEx := 0
	for iNdEx < l {
		var wire uint64
		for shift := uint(0); ; shift += 7 {
			if shift >= 64 {
				return 0, ErrIntOverflowApp
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
					return 0, ErrIntOverflowApp
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
					return 0, ErrIntOverflowApp
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
				return 0, ErrInvalidLengthApp
			}
			return iNdEx, nil
		case 3:
			for {
				var innerWire uint64
				var start int = iNdEx
				for shift := uint(0); ; shift += 7 {
					if shift >= 64 {
						return 0, ErrIntOverflowApp
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
				next, err := skipApp(dAtA[start:])
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
	ErrInvalidLengthApp = fmt.Errorf("proto: negative length found during unmarshaling")
	ErrIntOverflowApp   = fmt.Errorf("proto: integer overflow")
)

func init() { proto.RegisterFile("app.proto", fileDescriptorApp) }

var fileDescriptorApp = []byte{
	// 442 bytes of a gzipped FileDescriptorProto
	0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0xff, 0x9c, 0x91, 0x31, 0x6f, 0xd3, 0x40,
	0x14, 0xc7, 0x7b, 0x49, 0x94, 0xe2, 0x6b, 0x28, 0xe5, 0x84, 0xca, 0x11, 0x21, 0x37, 0xf2, 0x14,
	0x90, 0xea, 0x43, 0x65, 0x41, 0xdd, 0x1c, 0x2a, 0x96, 0x2e, 0xc8, 0x88, 0xb9, 0x3a, 0xc7, 0xaf,
	0xb6, 0x85, 0xe3, 0x7b, 0xd8, 0xe7, 0x96, 0x6c, 0x88, 0x89, 0x9d, 0x2f, 0x80, 0xc4, 0x17, 0xe0,
	0x63, 0x64, 0x44, 0x62, 0x47, 0x10, 0x31, 0x30, 0x22, 0x85, 0x81, 0x11, 0xf9, 0xec, 0x44, 0x06,
	0x31, 0x75, 0xb1, 0xde, 0xff, 0xf9, 0xfd, 0x7f, 0xef, 0xff, 0x74, 0xd4, 0x92, 0x88, 0x2e, 0xe6,
	0x4a, 0x2b, 0x66, 0x41, 0x18, 0x81, 0x29, 0x87, 0x77, 0x23, 0xa5, 0xa2, 0x14, 0x84, 0xc4, 0x44,
	0xc8, 0x2c, 0x53, 0x5a, 0xea, 0x44, 0x65, 0x45, 0x3d, 0x38, 0x1c, 0xe4, 0x50, 0x94, 0xa9, 0x6e,
	0xd4, 0xa3, 0x28, 0xd1, 0x71, 0x19, 0xb8, 0x53, 0x35, 0x13, 0x33, 0x15, 0x24, 0x69, 0x85, 0x79,
	0x25, 0xaa, 0xef, 0xe1, 0x34, 0x55, 0x65, 0x28, 0xcc, 0x5c, 0x04, 0xd9, 0xa6, 0x68, 0x9c, 0x37,
	0x42, 0xb8, 0x80, 0x54, 0x21, 0xe4, 0x4d, 0xe3, 0xb0, 0x85, 0x8a, 0x54, 0xa4, 0x6a, 0x43, 0x50,
	0x9e, 0x1b, 0x65, 0x84, 0xa9, 0xea, 0x71, 0xe7, 0x2d, 0xa1, 0x7d, 0x0f, 0xf1, 0x14, 0xe6, 0x6c,
	0x42, 0xaf, 0x6f, 0x60, 0x67, 0x2f, 0x60, 0xce, 0xc9, 0x88, 0x8c, 0x77, 0x8e, 0x6e, 0xbb, 0x9b,
	0x9b, 0xdc, 0x93, 0xf5, 0xff, 0x53, 0x98, 0x4f, 0x7a, 0x8b, 0x2f, 0x07, 0x5b, 0xfe, 0x20, 0x6c,
	0xf5, 0x18, 0xa3, 0xbd, 0x4c, 0xce, 0x80, 0x77, 0x46, 0x64, 0x6c, 0xf9, 0xa6, 0x66, 0x9c, 0x6e,
	0x5f, 0x40, 0x5e, 0x24, 0x2a, 0xe3, 0x5d, 0xd3, 0x5e, 0xcb, 0xe3, 0xc1, 0x8f, 0x15, 0x27, 0xbf,
	0x57, 0x9c, 0x7c, 0x7c, 0x7f, 0x40, 0x9c, 0x97, 0xb4, 0xeb, 0x21, 0xb2, 0x7d, 0xda, 0x3f, 0x4f,
	0x20, 0x0d, 0x0b, 0x4e, 0x46, 0xdd, 0xb1, 0xe5, 0x37, 0x8a, 0xdd, 0xa3, 0xdd, 0x2a, 0x54, 0xc7,
	0x84, 0xba, 0xd9, 0x0a, 0x55, 0xc7, 0x6f, 0xe2, 0x54, 0x33, 0xec, 0x0e, 0xbd, 0x26, 0x11, 0xcf,
	0x50, 0xea, 0x98, 0xf7, 0xea, 0x95, 0x12, 0xf1, 0xa9, 0xd4, 0x71, 0xbd, 0xf2, 0xe7, 0x8a, 0x93,
	0xd7, 0xbf, 0x38, 0x39, 0xfa, 0xd0, 0x31, 0xd7, 0x7b, 0x98, 0xb0, 0x27, 0xd4, 0x7a, 0x9c, 0x83,
	0xd4, 0x50, 0x65, 0xd8, 0xfd, 0x1b, 0x3f, 0x6c, 0xaf, 0xf3, 0xcd, 0xc3, 0x39, 0xfb, 0x6f, 0x3e,
	0x7f, 0x7f, 0xd7, 0xd9, 0x73, 0x76, 0xc4, 0xd4, 0xd8, 0x84, 0x44, 0x3c, 0x26, 0xf7, 0x2b, 0xce,
	0x09, 0xa4, 0x70, 0x05, 0x4e, 0x68, 0x6c, 0x2d, 0xce, 0x73, 0x0c, 0xaf, 0x92, 0xa7, 0x34, 0xb6,
	0x35, 0xc7, 0xa3, 0xdb, 0xcf, 0x62, 0x75, 0xf9, 0x3f, 0xca, 0x3f, 0xda, 0xb9, 0x65, 0x10, 0xbb,
	0x8e, 0x25, 0x8a, 0x58, 0x5d, 0x36, 0x80, 0x07, 0x64, 0xb2, 0xb7, 0xf8, 0x66, 0x6f, 0x2d, 0x96,
	0x36, 0xf9, 0xb4, 0xb4, 0xc9, 0xd7, 0xa5, 0x4d, 0x82, 0xbe, 0x31, 0x3d, 0xfc, 0x13, 0x00, 0x00,
	0xff, 0xff, 0x50, 0xae, 0xa1, 0x0d, 0xfa, 0x02, 0x00, 0x00,
}
