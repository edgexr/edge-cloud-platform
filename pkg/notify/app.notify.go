// Code generated by protoc-gen-gogo. DO NOT EDIT.
// source: app.proto

package notify

import (
	"context"
	fmt "fmt"
	_ "github.com/edgexr/edge-cloud-platform/api/dme-proto"
	edgeproto "github.com/edgexr/edge-cloud-platform/api/edgeproto"
	"github.com/edgexr/edge-cloud-platform/pkg/log"
	_ "github.com/edgexr/edge-cloud-platform/tools/protogen"
	_ "github.com/gogo/googleapis/google/api"
	_ "github.com/gogo/protobuf/gogoproto"
	proto "github.com/gogo/protobuf/proto"
	"github.com/gogo/protobuf/types"
	opentracing "github.com/opentracing/opentracing-go"
	math "math"
	"sync"
)

// Reference imports to suppress errors if they are not otherwise used.
var _ = proto.Marshal
var _ = fmt.Errorf
var _ = math.Inf

// Auto-generated code: DO NOT EDIT

type SendAppHandler interface {
	GetAllLocked(ctx context.Context, cb func(key *edgeproto.App, modRev int64))
	GetWithRev(key *edgeproto.AppKey, buf *edgeproto.App, modRev *int64) bool
}

type RecvAppHandler interface {
	Update(ctx context.Context, in *edgeproto.App, rev int64)
	Delete(ctx context.Context, in *edgeproto.App, rev int64)
	Prune(ctx context.Context, keys map[edgeproto.AppKey]struct{})
	Flush(ctx context.Context, notifyId int64)
}

type AppCacheHandler interface {
	SendAppHandler
	RecvAppHandler
	AddNotifyCb(fn func(ctx context.Context, obj *edgeproto.App, modRev int64))
}

type AppSend struct {
	Name        string
	MessageName string
	handler     SendAppHandler
	Keys        map[edgeproto.AppKey]AppSendContext
	keysToSend  map[edgeproto.AppKey]AppSendContext
	notifyId    int64
	Mux         sync.Mutex
	buf         edgeproto.App
	SendCount   uint64
	sendrecv    *SendRecv
}

type AppSendContext struct {
	ctx         context.Context
	modRev      int64
	forceDelete bool
}

func NewAppSend(handler SendAppHandler) *AppSend {
	send := &AppSend{}
	send.Name = "App"
	send.MessageName = proto.MessageName((*edgeproto.App)(nil))
	send.handler = handler
	send.Keys = make(map[edgeproto.AppKey]AppSendContext)
	return send
}

func (s *AppSend) SetSendRecv(sendrecv *SendRecv) {
	s.sendrecv = sendrecv
}

func (s *AppSend) GetMessageName() string {
	return s.MessageName
}

func (s *AppSend) GetName() string {
	return s.Name
}

func (s *AppSend) GetSendCount() uint64 {
	return s.SendCount
}

func (s *AppSend) GetNotifyId() int64 {
	return s.notifyId
}
func (s *AppSend) UpdateAll(ctx context.Context) {
	if !s.sendrecv.isRemoteWanted(s.MessageName) {
		return
	}
	s.Mux.Lock()
	s.handler.GetAllLocked(ctx, func(obj *edgeproto.App, modRev int64) {
		if !s.UpdateAllOkLocked(obj) { // to be implemented by hand
			return
		}
		s.Keys[*obj.GetKey()] = AppSendContext{
			ctx:    ctx,
			modRev: modRev,
		}
	})
	s.Mux.Unlock()
}

func (s *AppSend) Update(ctx context.Context, obj *edgeproto.App, modRev int64) {
	if !s.sendrecv.isRemoteWanted(s.MessageName) {
		return
	}
	if !s.UpdateOk(ctx, obj) { // to be implemented by hand
		return
	}
	forceDelete := false
	s.updateInternal(ctx, obj.GetKey(), modRev, forceDelete)
}

func (s *AppSend) ForceDelete(ctx context.Context, key *edgeproto.AppKey, modRev int64) {
	forceDelete := true
	s.updateInternal(ctx, key, modRev, forceDelete)
}

func (s *AppSend) updateInternal(ctx context.Context, key *edgeproto.AppKey, modRev int64, forceDelete bool) {
	s.Mux.Lock()
	log.SpanLog(ctx, log.DebugLevelNotify, "updateInternal App", "key", key, "modRev", modRev)
	s.Keys[*key] = AppSendContext{
		ctx:         ctx,
		modRev:      modRev,
		forceDelete: forceDelete,
	}
	s.Mux.Unlock()
	s.sendrecv.wakeup()
}

func (s *AppSend) SendForCloudlet(ctx context.Context, action edgeproto.NoticeAction, cloudlet *edgeproto.Cloudlet) {
}

func (s *AppSend) Send(stream StreamNotify, notice *edgeproto.Notice, peer string) error {
	s.Mux.Lock()
	keys := s.keysToSend
	s.keysToSend = nil
	s.Mux.Unlock()
	for key, sendContext := range keys {
		ctx := sendContext.ctx
		found := s.handler.GetWithRev(&key, &s.buf, &notice.ModRev)
		if found && !sendContext.forceDelete {
			notice.Action = edgeproto.NoticeAction_UPDATE
		} else {
			notice.Action = edgeproto.NoticeAction_DELETE
			notice.ModRev = sendContext.modRev
			s.buf.Reset()
			s.buf.SetKey(&key)
		}
		any, err := types.MarshalAny(&s.buf)
		if err != nil {
			s.sendrecv.stats.MarshalErrors++
			err = nil
			continue
		}
		notice.Any = *any
		notice.Span = log.SpanToString(ctx)
		log.SpanLog(ctx, log.DebugLevelNotify,
			fmt.Sprintf("%s send App", s.sendrecv.cliserv),
			"peerAddr", peer,
			"peer", s.sendrecv.peer,
			"local", s.sendrecv.name,
			"action", notice.Action,
			"key", key,
			"modRev", notice.ModRev)
		err = stream.Send(notice)
		if err != nil {
			s.sendrecv.stats.SendErrors++
			return err
		}
		s.sendrecv.stats.Send++
		// object specific counter
		s.SendCount++
	}
	return nil
}

func (s *AppSend) PrepData() bool {
	s.Mux.Lock()
	defer s.Mux.Unlock()
	if len(s.Keys) > 0 {
		s.keysToSend = s.Keys
		s.Keys = make(map[edgeproto.AppKey]AppSendContext)
		return true
	}
	return false
}

// Server accepts multiple clients so needs to track multiple
// peers to send to.
type AppSendMany struct {
	handler SendAppHandler
	Mux     sync.Mutex
	sends   map[string]*AppSend
}

func NewAppSendMany(handler SendAppHandler) *AppSendMany {
	s := &AppSendMany{}
	s.handler = handler
	s.sends = make(map[string]*AppSend)
	return s
}

func (s *AppSendMany) NewSend(peerAddr string, notifyId int64) NotifySend {
	send := NewAppSend(s.handler)
	send.notifyId = notifyId
	s.Mux.Lock()
	s.sends[peerAddr] = send
	s.Mux.Unlock()
	return send
}

func (s *AppSendMany) DoneSend(peerAddr string, send NotifySend) {
	asend, ok := send.(*AppSend)
	if !ok {
		return
	}
	// another connection may come from the same client so remove
	// only if it matches
	s.Mux.Lock()
	if remove, _ := s.sends[peerAddr]; remove == asend {
		delete(s.sends, peerAddr)
	}
	s.Mux.Unlock()
}
func (s *AppSendMany) Update(ctx context.Context, obj *edgeproto.App, modRev int64) {
	s.Mux.Lock()
	defer s.Mux.Unlock()
	for _, send := range s.sends {
		send.Update(ctx, obj, modRev)
	}
}

func (s *AppSendMany) GetTypeString() string {
	return "App"
}

type AppRecv struct {
	Name        string
	MessageName string
	handler     RecvAppHandler
	sendAllKeys map[edgeproto.AppKey]struct{}
	Mux         sync.Mutex
	buf         edgeproto.App
	RecvCount   uint64
	sendrecv    *SendRecv
}

func NewAppRecv(handler RecvAppHandler) *AppRecv {
	recv := &AppRecv{}
	recv.Name = "App"
	recv.MessageName = proto.MessageName((*edgeproto.App)(nil))
	recv.handler = handler
	return recv
}

func (s *AppRecv) SetSendRecv(sendrecv *SendRecv) {
	s.sendrecv = sendrecv
}

func (s *AppRecv) GetMessageName() string {
	return s.MessageName
}

func (s *AppRecv) GetName() string {
	return s.Name
}

func (s *AppRecv) GetRecvCount() uint64 {
	return s.RecvCount
}

func (s *AppRecv) Recv(ctx context.Context, notice *edgeproto.Notice, notifyId int64, peerAddr string) {
	span := opentracing.SpanFromContext(ctx)
	if span != nil {
		span.SetTag("objtype", "App")
	}

	buf := &edgeproto.App{}
	err := types.UnmarshalAny(&notice.Any, buf)
	if err != nil {
		s.sendrecv.stats.UnmarshalErrors++
		log.SpanLog(ctx, log.DebugLevelNotify, "Unmarshal Error", "err", err)
		return
	}
	if span != nil {
		log.SetTags(span, buf.GetKey().GetTags())
	}
	log.SpanLog(ctx, log.DebugLevelNotify,
		fmt.Sprintf("%s recv App", s.sendrecv.cliserv),
		"peerAddr", peerAddr,
		"peer", s.sendrecv.peer,
		"local", s.sendrecv.name,
		"action", notice.Action,
		"key", buf.GetKeyVal(),
		"modRev", notice.ModRev)
	if notice.Action == edgeproto.NoticeAction_UPDATE {
		s.handler.Update(ctx, buf, notice.ModRev)
		s.Mux.Lock()
		if s.sendAllKeys != nil {
			s.sendAllKeys[buf.GetKeyVal()] = struct{}{}
		}
		s.Mux.Unlock()
	} else if notice.Action == edgeproto.NoticeAction_DELETE {
		s.handler.Delete(ctx, buf, notice.ModRev)
	}
	s.sendrecv.stats.Recv++
	// object specific counter
	s.RecvCount++
}

func (s *AppRecv) RecvAllStart() {
	s.Mux.Lock()
	defer s.Mux.Unlock()
	s.sendAllKeys = make(map[edgeproto.AppKey]struct{})
}

func (s *AppRecv) RecvAllEnd(ctx context.Context, cleanup Cleanup) {
	s.Mux.Lock()
	validKeys := s.sendAllKeys
	s.sendAllKeys = nil
	s.Mux.Unlock()
	if cleanup == CleanupPrune {
		s.handler.Prune(ctx, validKeys)
	}
}
func (s *AppRecv) Flush(ctx context.Context, notifyId int64) {
	s.handler.Flush(ctx, notifyId)
}

type AppRecvMany struct {
	handler RecvAppHandler
}

func NewAppRecvMany(handler RecvAppHandler) *AppRecvMany {
	s := &AppRecvMany{}
	s.handler = handler
	return s
}

func (s *AppRecvMany) NewRecv() NotifyRecv {
	recv := NewAppRecv(s.handler)
	return recv
}

func (s *AppRecvMany) Flush(ctx context.Context, notifyId int64) {
	s.handler.Flush(ctx, notifyId)
}
func (mgr *ServerMgr) RegisterSendAppCache(cache AppCacheHandler) {
	send := NewAppSendMany(cache)
	mgr.RegisterSend(send)
	cache.AddNotifyCb(send.Update)
}

func (mgr *ServerMgr) RegisterRecvAppCache(cache AppCacheHandler) {
	recv := NewAppRecvMany(cache)
	mgr.RegisterRecv(recv)
}

func (s *Client) RegisterSendAppCache(cache AppCacheHandler) {
	send := NewAppSend(cache)
	s.RegisterSend(send)
	cache.AddNotifyCb(send.Update)
}

func (s *Client) RegisterRecvAppCache(cache AppCacheHandler) {
	recv := NewAppRecv(cache)
	s.RegisterRecv(recv)
}
