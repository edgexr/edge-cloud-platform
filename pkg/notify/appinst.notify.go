// Code generated by protoc-gen-gogo. DO NOT EDIT.
// source: appinst.proto

package notify

import (
	"context"
	fmt "fmt"
	_ "github.com/edgexr/edge-cloud-platform/api/distributed_match_engine"
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

type SendAppInstHandler interface {
	GetAllLocked(ctx context.Context, cb func(key *edgeproto.AppInst, modRev int64))
	GetWithRev(key *edgeproto.AppInstKey, buf *edgeproto.AppInst, modRev *int64) bool
	GetForCloudlet(cloudlet *edgeproto.Cloudlet, cb func(data *edgeproto.AppInstCacheData))
}

type RecvAppInstHandler interface {
	Update(ctx context.Context, in *edgeproto.AppInst, rev int64)
	Delete(ctx context.Context, in *edgeproto.AppInst, rev int64)
	Prune(ctx context.Context, keys map[edgeproto.AppInstKey]struct{})
	Flush(ctx context.Context, notifyId int64)
}

type AppInstCacheHandler interface {
	SendAppInstHandler
	RecvAppInstHandler
	AddNotifyCb(fn func(ctx context.Context, obj *edgeproto.AppInst, modRev int64))
}

type AppInstSend struct {
	Name        string
	MessageName string
	handler     SendAppInstHandler
	Keys        map[edgeproto.AppInstKey]AppInstSendContext
	keysToSend  map[edgeproto.AppInstKey]AppInstSendContext
	notifyId    int64
	Mux         sync.Mutex
	buf         edgeproto.AppInst
	SendCount   uint64
	sendrecv    *SendRecv
}

type AppInstSendContext struct {
	ctx         context.Context
	modRev      int64
	forceDelete bool
}

func NewAppInstSend(handler SendAppInstHandler) *AppInstSend {
	send := &AppInstSend{}
	send.Name = "AppInst"
	send.MessageName = proto.MessageName((*edgeproto.AppInst)(nil))
	send.handler = handler
	send.Keys = make(map[edgeproto.AppInstKey]AppInstSendContext)
	return send
}

func (s *AppInstSend) SetSendRecv(sendrecv *SendRecv) {
	s.sendrecv = sendrecv
}

func (s *AppInstSend) GetMessageName() string {
	return s.MessageName
}

func (s *AppInstSend) GetName() string {
	return s.Name
}

func (s *AppInstSend) GetSendCount() uint64 {
	return s.SendCount
}

func (s *AppInstSend) GetNotifyId() int64 {
	return s.notifyId
}
func (s *AppInstSend) UpdateAll(ctx context.Context) {
	if !s.sendrecv.isRemoteWanted(s.MessageName) {
		return
	}
	s.Mux.Lock()
	s.handler.GetAllLocked(ctx, func(obj *edgeproto.AppInst, modRev int64) {
		if !s.UpdateAllOkLocked(obj) { // to be implemented by hand
			return
		}
		s.Keys[*obj.GetKey()] = AppInstSendContext{
			ctx:    ctx,
			modRev: modRev,
		}
	})
	s.Mux.Unlock()
}

func (s *AppInstSend) Update(ctx context.Context, obj *edgeproto.AppInst, modRev int64) {
	if !s.sendrecv.isRemoteWanted(s.MessageName) {
		return
	}
	if !s.UpdateOk(ctx, obj) { // to be implemented by hand
		return
	}
	forceDelete := false
	s.updateInternal(ctx, obj.GetKey(), modRev, forceDelete)
}

func (s *AppInstSend) ForceDelete(ctx context.Context, key *edgeproto.AppInstKey, modRev int64) {
	forceDelete := true
	s.updateInternal(ctx, key, modRev, forceDelete)
}

func (s *AppInstSend) updateInternal(ctx context.Context, key *edgeproto.AppInstKey, modRev int64, forceDelete bool) {
	s.Mux.Lock()
	log.SpanLog(ctx, log.DebugLevelNotify, "updateInternal AppInst", "key", key, "modRev", modRev)
	s.Keys[*key] = AppInstSendContext{
		ctx:         ctx,
		modRev:      modRev,
		forceDelete: forceDelete,
	}
	s.Mux.Unlock()
	s.sendrecv.wakeup()
}

func (s *AppInstSend) SendForCloudlet(ctx context.Context, action edgeproto.NoticeAction, cloudlet *edgeproto.Cloudlet) {
	keys := make(map[edgeproto.AppInstKey]*edgeproto.AppInstCacheData)
	s.handler.GetForCloudlet(cloudlet, func(data *edgeproto.AppInstCacheData) {
		if data.Obj == nil {
			return
		}
		keys[*data.Obj.GetKey()] = data
	})
	for k, data := range keys {
		if action == edgeproto.NoticeAction_UPDATE {
			s.Update(ctx, data.Obj, data.ModRev)
		} else if action == edgeproto.NoticeAction_DELETE {
			s.ForceDelete(ctx, &k, data.ModRev)
		}
	}
}

func (s *AppInstSend) Send(stream StreamNotify, notice *edgeproto.Notice, peer string) error {
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
			fmt.Sprintf("%s send AppInst", s.sendrecv.cliserv),
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

func (s *AppInstSend) PrepData() bool {
	s.Mux.Lock()
	defer s.Mux.Unlock()
	if len(s.Keys) > 0 {
		s.keysToSend = s.Keys
		s.Keys = make(map[edgeproto.AppInstKey]AppInstSendContext)
		return true
	}
	return false
}

// Server accepts multiple clients so needs to track multiple
// peers to send to.
type AppInstSendMany struct {
	handler SendAppInstHandler
	Mux     sync.Mutex
	sends   map[string]*AppInstSend
}

func NewAppInstSendMany(handler SendAppInstHandler) *AppInstSendMany {
	s := &AppInstSendMany{}
	s.handler = handler
	s.sends = make(map[string]*AppInstSend)
	return s
}

func (s *AppInstSendMany) NewSend(peerAddr string, notifyId int64) NotifySend {
	send := NewAppInstSend(s.handler)
	send.notifyId = notifyId
	s.Mux.Lock()
	s.sends[peerAddr] = send
	s.Mux.Unlock()
	return send
}

func (s *AppInstSendMany) DoneSend(peerAddr string, send NotifySend) {
	asend, ok := send.(*AppInstSend)
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
func (s *AppInstSendMany) Update(ctx context.Context, obj *edgeproto.AppInst, modRev int64) {
	s.Mux.Lock()
	defer s.Mux.Unlock()
	for _, send := range s.sends {
		send.Update(ctx, obj, modRev)
	}
}

func (s *AppInstSendMany) GetTypeString() string {
	return "AppInst"
}

type AppInstRecv struct {
	Name        string
	MessageName string
	handler     RecvAppInstHandler
	sendAllKeys map[edgeproto.AppInstKey]struct{}
	Mux         sync.Mutex
	buf         edgeproto.AppInst
	RecvCount   uint64
	sendrecv    *SendRecv
}

func NewAppInstRecv(handler RecvAppInstHandler) *AppInstRecv {
	recv := &AppInstRecv{}
	recv.Name = "AppInst"
	recv.MessageName = proto.MessageName((*edgeproto.AppInst)(nil))
	recv.handler = handler
	return recv
}

func (s *AppInstRecv) SetSendRecv(sendrecv *SendRecv) {
	s.sendrecv = sendrecv
}

func (s *AppInstRecv) GetMessageName() string {
	return s.MessageName
}

func (s *AppInstRecv) GetName() string {
	return s.Name
}

func (s *AppInstRecv) GetRecvCount() uint64 {
	return s.RecvCount
}

func (s *AppInstRecv) Recv(ctx context.Context, notice *edgeproto.Notice, notifyId int64, peerAddr string) {
	span := opentracing.SpanFromContext(ctx)
	if span != nil {
		span.SetTag("objtype", "AppInst")
	}

	buf := &edgeproto.AppInst{}
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
		fmt.Sprintf("%s recv AppInst", s.sendrecv.cliserv),
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

func (s *AppInstRecv) RecvAllStart() {
	s.Mux.Lock()
	defer s.Mux.Unlock()
	s.sendAllKeys = make(map[edgeproto.AppInstKey]struct{})
}

func (s *AppInstRecv) RecvAllEnd(ctx context.Context, cleanup Cleanup) {
	s.Mux.Lock()
	validKeys := s.sendAllKeys
	s.sendAllKeys = nil
	s.Mux.Unlock()
	if cleanup == CleanupPrune {
		s.handler.Prune(ctx, validKeys)
	}
}
func (s *AppInstRecv) Flush(ctx context.Context, notifyId int64) {
	s.handler.Flush(ctx, notifyId)
}

type AppInstRecvMany struct {
	handler RecvAppInstHandler
}

func NewAppInstRecvMany(handler RecvAppInstHandler) *AppInstRecvMany {
	s := &AppInstRecvMany{}
	s.handler = handler
	return s
}

func (s *AppInstRecvMany) NewRecv() NotifyRecv {
	recv := NewAppInstRecv(s.handler)
	return recv
}

func (s *AppInstRecvMany) Flush(ctx context.Context, notifyId int64) {
	s.handler.Flush(ctx, notifyId)
}
func (mgr *ServerMgr) RegisterSendAppInstCache(cache AppInstCacheHandler) {
	send := NewAppInstSendMany(cache)
	mgr.RegisterSend(send)
	cache.AddNotifyCb(send.Update)
}

func (mgr *ServerMgr) RegisterRecvAppInstCache(cache AppInstCacheHandler) {
	recv := NewAppInstRecvMany(cache)
	mgr.RegisterRecv(recv)
}

func (s *Client) RegisterSendAppInstCache(cache AppInstCacheHandler) {
	send := NewAppInstSend(cache)
	s.RegisterSend(send)
	cache.AddNotifyCb(send.Update)
}

func (s *Client) RegisterRecvAppInstCache(cache AppInstCacheHandler) {
	recv := NewAppInstRecv(cache)
	s.RegisterRecv(recv)
}

type SendAppInstInfoHandler interface {
	GetAllLocked(ctx context.Context, cb func(key *edgeproto.AppInstInfo, modRev int64))
	GetWithRev(key *edgeproto.AppInstKey, buf *edgeproto.AppInstInfo, modRev *int64) bool
}

type RecvAppInstInfoHandler interface {
	Update(ctx context.Context, in *edgeproto.AppInstInfo, rev int64)
	Delete(ctx context.Context, in *edgeproto.AppInstInfo, rev int64)
	Prune(ctx context.Context, keys map[edgeproto.AppInstKey]struct{})
	Flush(ctx context.Context, notifyId int64)
}

type AppInstInfoCacheHandler interface {
	SendAppInstInfoHandler
	RecvAppInstInfoHandler
	AddNotifyCb(fn func(ctx context.Context, obj *edgeproto.AppInstInfo, modRev int64))
}

type AppInstInfoSend struct {
	Name        string
	MessageName string
	handler     SendAppInstInfoHandler
	Keys        map[edgeproto.AppInstKey]AppInstInfoSendContext
	keysToSend  map[edgeproto.AppInstKey]AppInstInfoSendContext
	notifyId    int64
	Mux         sync.Mutex
	buf         edgeproto.AppInstInfo
	SendCount   uint64
	sendrecv    *SendRecv
}

type AppInstInfoSendContext struct {
	ctx         context.Context
	modRev      int64
	forceDelete bool
}

func NewAppInstInfoSend(handler SendAppInstInfoHandler) *AppInstInfoSend {
	send := &AppInstInfoSend{}
	send.Name = "AppInstInfo"
	send.MessageName = proto.MessageName((*edgeproto.AppInstInfo)(nil))
	send.handler = handler
	send.Keys = make(map[edgeproto.AppInstKey]AppInstInfoSendContext)
	return send
}

func (s *AppInstInfoSend) SetSendRecv(sendrecv *SendRecv) {
	s.sendrecv = sendrecv
}

func (s *AppInstInfoSend) GetMessageName() string {
	return s.MessageName
}

func (s *AppInstInfoSend) GetName() string {
	return s.Name
}

func (s *AppInstInfoSend) GetSendCount() uint64 {
	return s.SendCount
}

func (s *AppInstInfoSend) GetNotifyId() int64 {
	return s.notifyId
}
func (s *AppInstInfoSend) UpdateAll(ctx context.Context) {
	if !s.sendrecv.isRemoteWanted(s.MessageName) {
		return
	}
	s.Mux.Lock()
	s.handler.GetAllLocked(ctx, func(obj *edgeproto.AppInstInfo, modRev int64) {
		s.Keys[*obj.GetKey()] = AppInstInfoSendContext{
			ctx:    ctx,
			modRev: modRev,
		}
	})
	s.Mux.Unlock()
}

func (s *AppInstInfoSend) Update(ctx context.Context, obj *edgeproto.AppInstInfo, modRev int64) {
	if !s.sendrecv.isRemoteWanted(s.MessageName) {
		return
	}
	forceDelete := false
	s.updateInternal(ctx, obj.GetKey(), modRev, forceDelete)
}

func (s *AppInstInfoSend) ForceDelete(ctx context.Context, key *edgeproto.AppInstKey, modRev int64) {
	forceDelete := true
	s.updateInternal(ctx, key, modRev, forceDelete)
}

func (s *AppInstInfoSend) updateInternal(ctx context.Context, key *edgeproto.AppInstKey, modRev int64, forceDelete bool) {
	s.Mux.Lock()
	log.SpanLog(ctx, log.DebugLevelNotify, "updateInternal AppInstInfo", "key", key, "modRev", modRev)
	s.Keys[*key] = AppInstInfoSendContext{
		ctx:         ctx,
		modRev:      modRev,
		forceDelete: forceDelete,
	}
	s.Mux.Unlock()
	s.sendrecv.wakeup()
}

func (s *AppInstInfoSend) SendForCloudlet(ctx context.Context, action edgeproto.NoticeAction, cloudlet *edgeproto.Cloudlet) {
}

func (s *AppInstInfoSend) Send(stream StreamNotify, notice *edgeproto.Notice, peer string) error {
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
			fmt.Sprintf("%s send AppInstInfo", s.sendrecv.cliserv),
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

func (s *AppInstInfoSend) PrepData() bool {
	s.Mux.Lock()
	defer s.Mux.Unlock()
	if len(s.Keys) > 0 {
		s.keysToSend = s.Keys
		s.Keys = make(map[edgeproto.AppInstKey]AppInstInfoSendContext)
		return true
	}
	return false
}

// Server accepts multiple clients so needs to track multiple
// peers to send to.
type AppInstInfoSendMany struct {
	handler SendAppInstInfoHandler
	Mux     sync.Mutex
	sends   map[string]*AppInstInfoSend
}

func NewAppInstInfoSendMany(handler SendAppInstInfoHandler) *AppInstInfoSendMany {
	s := &AppInstInfoSendMany{}
	s.handler = handler
	s.sends = make(map[string]*AppInstInfoSend)
	return s
}

func (s *AppInstInfoSendMany) NewSend(peerAddr string, notifyId int64) NotifySend {
	send := NewAppInstInfoSend(s.handler)
	send.notifyId = notifyId
	s.Mux.Lock()
	s.sends[peerAddr] = send
	s.Mux.Unlock()
	return send
}

func (s *AppInstInfoSendMany) DoneSend(peerAddr string, send NotifySend) {
	asend, ok := send.(*AppInstInfoSend)
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
func (s *AppInstInfoSendMany) Update(ctx context.Context, obj *edgeproto.AppInstInfo, modRev int64) {
	s.Mux.Lock()
	defer s.Mux.Unlock()
	for _, send := range s.sends {
		send.Update(ctx, obj, modRev)
	}
}

func (s *AppInstInfoSendMany) GetTypeString() string {
	return "AppInstInfo"
}

type AppInstInfoRecv struct {
	Name        string
	MessageName string
	handler     RecvAppInstInfoHandler
	sendAllKeys map[edgeproto.AppInstKey]struct{}
	Mux         sync.Mutex
	buf         edgeproto.AppInstInfo
	RecvCount   uint64
	sendrecv    *SendRecv
}

func NewAppInstInfoRecv(handler RecvAppInstInfoHandler) *AppInstInfoRecv {
	recv := &AppInstInfoRecv{}
	recv.Name = "AppInstInfo"
	recv.MessageName = proto.MessageName((*edgeproto.AppInstInfo)(nil))
	recv.handler = handler
	return recv
}

func (s *AppInstInfoRecv) SetSendRecv(sendrecv *SendRecv) {
	s.sendrecv = sendrecv
}

func (s *AppInstInfoRecv) GetMessageName() string {
	return s.MessageName
}

func (s *AppInstInfoRecv) GetName() string {
	return s.Name
}

func (s *AppInstInfoRecv) GetRecvCount() uint64 {
	return s.RecvCount
}

func (s *AppInstInfoRecv) Recv(ctx context.Context, notice *edgeproto.Notice, notifyId int64, peerAddr string) {
	span := opentracing.SpanFromContext(ctx)
	if span != nil {
		span.SetTag("objtype", "AppInstInfo")
	}

	buf := &edgeproto.AppInstInfo{}
	err := types.UnmarshalAny(&notice.Any, buf)
	if err != nil {
		s.sendrecv.stats.UnmarshalErrors++
		log.SpanLog(ctx, log.DebugLevelNotify, "Unmarshal Error", "err", err)
		return
	}
	buf.NotifyId = notifyId
	if span != nil {
		log.SetTags(span, buf.GetKey().GetTags())
	}
	log.SpanLog(ctx, log.DebugLevelNotify,
		fmt.Sprintf("%s recv AppInstInfo", s.sendrecv.cliserv),
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

func (s *AppInstInfoRecv) RecvAllStart() {
	s.Mux.Lock()
	defer s.Mux.Unlock()
	s.sendAllKeys = make(map[edgeproto.AppInstKey]struct{})
}

func (s *AppInstInfoRecv) RecvAllEnd(ctx context.Context, cleanup Cleanup) {
	s.Mux.Lock()
	validKeys := s.sendAllKeys
	s.sendAllKeys = nil
	s.Mux.Unlock()
	if cleanup == CleanupPrune {
		s.handler.Prune(ctx, validKeys)
	}
}
func (s *AppInstInfoRecv) Flush(ctx context.Context, notifyId int64) {
	s.handler.Flush(ctx, notifyId)
}

type AppInstInfoRecvMany struct {
	handler RecvAppInstInfoHandler
}

func NewAppInstInfoRecvMany(handler RecvAppInstInfoHandler) *AppInstInfoRecvMany {
	s := &AppInstInfoRecvMany{}
	s.handler = handler
	return s
}

func (s *AppInstInfoRecvMany) NewRecv() NotifyRecv {
	recv := NewAppInstInfoRecv(s.handler)
	return recv
}

func (s *AppInstInfoRecvMany) Flush(ctx context.Context, notifyId int64) {
	s.handler.Flush(ctx, notifyId)
}
func (mgr *ServerMgr) RegisterSendAppInstInfoCache(cache AppInstInfoCacheHandler) {
	send := NewAppInstInfoSendMany(cache)
	mgr.RegisterSend(send)
	cache.AddNotifyCb(send.Update)
}

func (mgr *ServerMgr) RegisterRecvAppInstInfoCache(cache AppInstInfoCacheHandler) {
	recv := NewAppInstInfoRecvMany(cache)
	mgr.RegisterRecv(recv)
}

func (s *Client) RegisterSendAppInstInfoCache(cache AppInstInfoCacheHandler) {
	send := NewAppInstInfoSend(cache)
	s.RegisterSend(send)
	cache.AddNotifyCb(send.Update)
}

func (s *Client) RegisterRecvAppInstInfoCache(cache AppInstInfoCacheHandler) {
	recv := NewAppInstInfoRecv(cache)
	s.RegisterRecv(recv)
}

type RecvFedAppInstEventHandler interface {
	RecvFedAppInstEvent(ctx context.Context, msg *edgeproto.FedAppInstEvent)
}

type FedAppInstEventSend struct {
	Name        string
	MessageName string
	Data        []*edgeproto.FedAppInstEvent
	dataToSend  []*edgeproto.FedAppInstEvent
	Ctxs        []context.Context
	ctxsToSend  []context.Context
	notifyId    int64
	Mux         sync.Mutex
	buf         edgeproto.FedAppInstEvent
	SendCount   uint64
	sendrecv    *SendRecv
}

type FedAppInstEventSendContext struct {
	ctx         context.Context
	modRev      int64
	forceDelete bool
}

func NewFedAppInstEventSend() *FedAppInstEventSend {
	send := &FedAppInstEventSend{}
	send.Name = "FedAppInstEvent"
	send.MessageName = proto.MessageName((*edgeproto.FedAppInstEvent)(nil))
	send.Data = make([]*edgeproto.FedAppInstEvent, 0)
	return send
}

func (s *FedAppInstEventSend) SetSendRecv(sendrecv *SendRecv) {
	s.sendrecv = sendrecv
}

func (s *FedAppInstEventSend) GetMessageName() string {
	return s.MessageName
}

func (s *FedAppInstEventSend) GetName() string {
	return s.Name
}

func (s *FedAppInstEventSend) GetSendCount() uint64 {
	return s.SendCount
}

func (s *FedAppInstEventSend) GetNotifyId() int64 {
	return s.notifyId
}
func (s *FedAppInstEventSend) UpdateAll(ctx context.Context) {}

func (s *FedAppInstEventSend) Update(ctx context.Context, msg *edgeproto.FedAppInstEvent) bool {
	if !s.sendrecv.isRemoteWanted(s.MessageName) {
		return false
	}
	s.Mux.Lock()
	s.Data = append(s.Data, msg)
	s.Ctxs = append(s.Ctxs, ctx)
	s.Mux.Unlock()
	s.sendrecv.wakeup()
	return true
}

func (s *FedAppInstEventSend) SendForCloudlet(ctx context.Context, action edgeproto.NoticeAction, cloudlet *edgeproto.Cloudlet) {
}

func (s *FedAppInstEventSend) Send(stream StreamNotify, notice *edgeproto.Notice, peer string) error {
	s.Mux.Lock()
	data := s.dataToSend
	s.dataToSend = nil
	ctxs := s.ctxsToSend
	s.ctxsToSend = nil
	s.Mux.Unlock()
	for ii, msg := range data {
		any, err := types.MarshalAny(msg)
		ctx := ctxs[ii]
		if err != nil {
			s.sendrecv.stats.MarshalErrors++
			err = nil
			continue
		}
		notice.Any = *any
		notice.Span = log.SpanToString(ctx)
		log.SpanLog(ctx, log.DebugLevelNotify,
			fmt.Sprintf("%s send FedAppInstEvent", s.sendrecv.cliserv),
			"peerAddr", peer,
			"peer", s.sendrecv.peer,
			"local", s.sendrecv.name,
			"message", msg)
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

func (s *FedAppInstEventSend) PrepData() bool {
	s.Mux.Lock()
	defer s.Mux.Unlock()
	if len(s.Data) > 0 {
		s.dataToSend = s.Data
		s.Data = make([]*edgeproto.FedAppInstEvent, 0)
		s.ctxsToSend = s.Ctxs
		s.Ctxs = make([]context.Context, 0)
		return true
	}
	return false
}

// Server accepts multiple clients so needs to track multiple
// peers to send to.
type FedAppInstEventSendMany struct {
	Mux   sync.Mutex
	sends map[string]*FedAppInstEventSend
}

func NewFedAppInstEventSendMany() *FedAppInstEventSendMany {
	s := &FedAppInstEventSendMany{}
	s.sends = make(map[string]*FedAppInstEventSend)
	return s
}

func (s *FedAppInstEventSendMany) NewSend(peerAddr string, notifyId int64) NotifySend {
	send := NewFedAppInstEventSend()
	send.notifyId = notifyId
	s.Mux.Lock()
	s.sends[peerAddr] = send
	s.Mux.Unlock()
	return send
}

func (s *FedAppInstEventSendMany) DoneSend(peerAddr string, send NotifySend) {
	asend, ok := send.(*FedAppInstEventSend)
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
func (s *FedAppInstEventSendMany) Update(ctx context.Context, msg *edgeproto.FedAppInstEvent) int {
	s.Mux.Lock()
	defer s.Mux.Unlock()
	count := 0
	for _, send := range s.sends {
		if send.Update(ctx, msg) {
			count++
		}
	}
	return count
}

func (s *FedAppInstEventSendMany) UpdateFiltered(ctx context.Context, msg *edgeproto.FedAppInstEvent, sendOk func(ctx context.Context, send *FedAppInstEventSend, msg *edgeproto.FedAppInstEvent) bool) int {
	s.Mux.Lock()
	defer s.Mux.Unlock()
	count := 0
	for _, send := range s.sends {
		if !sendOk(ctx, send, msg) {
			continue
		}
		if send.Update(ctx, msg) {
			count++
		}
	}
	return count
}

func (s *FedAppInstEventSendMany) GetTypeString() string {
	return "FedAppInstEvent"
}

type FedAppInstEventRecv struct {
	Name        string
	MessageName string
	handler     RecvFedAppInstEventHandler
	Mux         sync.Mutex
	buf         edgeproto.FedAppInstEvent
	RecvCount   uint64
	sendrecv    *SendRecv
}

func NewFedAppInstEventRecv(handler RecvFedAppInstEventHandler) *FedAppInstEventRecv {
	recv := &FedAppInstEventRecv{}
	recv.Name = "FedAppInstEvent"
	recv.MessageName = proto.MessageName((*edgeproto.FedAppInstEvent)(nil))
	recv.handler = handler
	return recv
}

func (s *FedAppInstEventRecv) SetSendRecv(sendrecv *SendRecv) {
	s.sendrecv = sendrecv
}

func (s *FedAppInstEventRecv) GetMessageName() string {
	return s.MessageName
}

func (s *FedAppInstEventRecv) GetName() string {
	return s.Name
}

func (s *FedAppInstEventRecv) GetRecvCount() uint64 {
	return s.RecvCount
}

func (s *FedAppInstEventRecv) Recv(ctx context.Context, notice *edgeproto.Notice, notifyId int64, peerAddr string) {
	span := opentracing.SpanFromContext(ctx)
	if span != nil {
		span.SetTag("objtype", "FedAppInstEvent")
	}

	buf := &edgeproto.FedAppInstEvent{}
	err := types.UnmarshalAny(&notice.Any, buf)
	if err != nil {
		s.sendrecv.stats.UnmarshalErrors++
		log.SpanLog(ctx, log.DebugLevelNotify, "Unmarshal Error", "err", err)
		return
	}
	if span != nil {
		span.SetTag("msg", buf)
	}
	log.SpanLog(ctx, log.DebugLevelNotify,
		fmt.Sprintf("%s recv FedAppInstEvent", s.sendrecv.cliserv),
		"peerAddr", peerAddr,
		"peer", s.sendrecv.peer,
		"local", s.sendrecv.name,
		"message", buf)
	s.handler.RecvFedAppInstEvent(ctx, buf)
	s.sendrecv.stats.Recv++
	// object specific counter
	s.RecvCount++
}

func (s *FedAppInstEventRecv) RecvAllStart() {
}

func (s *FedAppInstEventRecv) RecvAllEnd(ctx context.Context, cleanup Cleanup) {
}

type FedAppInstEventRecvMany struct {
	handler RecvFedAppInstEventHandler
}

func NewFedAppInstEventRecvMany(handler RecvFedAppInstEventHandler) *FedAppInstEventRecvMany {
	s := &FedAppInstEventRecvMany{}
	s.handler = handler
	return s
}

func (s *FedAppInstEventRecvMany) NewRecv() NotifyRecv {
	recv := NewFedAppInstEventRecv(s.handler)
	return recv
}

func (s *FedAppInstEventRecvMany) Flush(ctx context.Context, notifyId int64) {
}
