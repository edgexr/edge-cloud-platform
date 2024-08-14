// Code generated by protoc-gen-gogo. DO NOT EDIT.
// source: refs.proto

package notify

import (
	"context"
	fmt "fmt"
	edgeproto "github.com/edgexr/edge-cloud-platform/api/edgeproto"
	"github.com/edgexr/edge-cloud-platform/pkg/log"
	_ "github.com/edgexr/edge-cloud-platform/tools/protogen"
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

type SendClusterRefsHandler interface {
	GetAllLocked(ctx context.Context, cb func(key *edgeproto.ClusterRefs, modRev int64))
	GetWithRev(key *edgeproto.ClusterKey, buf *edgeproto.ClusterRefs, modRev *int64) bool
}

type RecvClusterRefsHandler interface {
	Update(ctx context.Context, in *edgeproto.ClusterRefs, rev int64)
	Delete(ctx context.Context, in *edgeproto.ClusterRefs, rev int64)
	Prune(ctx context.Context, keys map[edgeproto.ClusterKey]struct{})
	Flush(ctx context.Context, notifyId int64)
}

type ClusterRefsCacheHandler interface {
	SendClusterRefsHandler
	RecvClusterRefsHandler
	AddNotifyCb(fn func(ctx context.Context, obj *edgeproto.ClusterRefs, modRev int64))
}

type ClusterRefsSend struct {
	Name        string
	MessageName string
	handler     SendClusterRefsHandler
	Keys        map[edgeproto.ClusterKey]ClusterRefsSendContext
	keysToSend  map[edgeproto.ClusterKey]ClusterRefsSendContext
	notifyId    int64
	Mux         sync.Mutex
	buf         edgeproto.ClusterRefs
	SendCount   uint64
	sendrecv    *SendRecv
}

type ClusterRefsSendContext struct {
	ctx         context.Context
	modRev      int64
	forceDelete bool
}

func NewClusterRefsSend(handler SendClusterRefsHandler) *ClusterRefsSend {
	send := &ClusterRefsSend{}
	send.Name = "ClusterRefs"
	send.MessageName = proto.MessageName((*edgeproto.ClusterRefs)(nil))
	send.handler = handler
	send.Keys = make(map[edgeproto.ClusterKey]ClusterRefsSendContext)
	return send
}

func (s *ClusterRefsSend) SetSendRecv(sendrecv *SendRecv) {
	s.sendrecv = sendrecv
}

func (s *ClusterRefsSend) GetMessageName() string {
	return s.MessageName
}

func (s *ClusterRefsSend) GetName() string {
	return s.Name
}

func (s *ClusterRefsSend) GetSendCount() uint64 {
	return s.SendCount
}

func (s *ClusterRefsSend) GetNotifyId() int64 {
	return s.notifyId
}
func (s *ClusterRefsSend) UpdateAll(ctx context.Context) {
	if !s.sendrecv.isRemoteWanted(s.MessageName) {
		return
	}
	s.Mux.Lock()
	s.handler.GetAllLocked(ctx, func(obj *edgeproto.ClusterRefs, modRev int64) {
		s.Keys[*obj.GetKey()] = ClusterRefsSendContext{
			ctx:    ctx,
			modRev: modRev,
		}
	})
	s.Mux.Unlock()
}

func (s *ClusterRefsSend) Update(ctx context.Context, obj *edgeproto.ClusterRefs, modRev int64) {
	if !s.sendrecv.isRemoteWanted(s.MessageName) {
		return
	}
	forceDelete := false
	s.updateInternal(ctx, obj.GetKey(), modRev, forceDelete)
}

func (s *ClusterRefsSend) ForceDelete(ctx context.Context, key *edgeproto.ClusterKey, modRev int64) {
	forceDelete := true
	s.updateInternal(ctx, key, modRev, forceDelete)
}

func (s *ClusterRefsSend) updateInternal(ctx context.Context, key *edgeproto.ClusterKey, modRev int64, forceDelete bool) {
	s.Mux.Lock()
	log.SpanLog(ctx, log.DebugLevelNotify, "updateInternal ClusterRefs", "key", key, "modRev", modRev)
	s.Keys[*key] = ClusterRefsSendContext{
		ctx:         ctx,
		modRev:      modRev,
		forceDelete: forceDelete,
	}
	s.Mux.Unlock()
	s.sendrecv.wakeup()
}

func (s *ClusterRefsSend) SendForCloudlet(ctx context.Context, action edgeproto.NoticeAction, cloudlet *edgeproto.Cloudlet) {
}

func (s *ClusterRefsSend) Send(stream StreamNotify, notice *edgeproto.Notice, peer string) error {
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
			fmt.Sprintf("%s send ClusterRefs", s.sendrecv.cliserv),
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

func (s *ClusterRefsSend) PrepData() bool {
	s.Mux.Lock()
	defer s.Mux.Unlock()
	if len(s.Keys) > 0 {
		s.keysToSend = s.Keys
		s.Keys = make(map[edgeproto.ClusterKey]ClusterRefsSendContext)
		return true
	}
	return false
}

// Server accepts multiple clients so needs to track multiple
// peers to send to.
type ClusterRefsSendMany struct {
	handler SendClusterRefsHandler
	Mux     sync.Mutex
	sends   map[string]*ClusterRefsSend
}

func NewClusterRefsSendMany(handler SendClusterRefsHandler) *ClusterRefsSendMany {
	s := &ClusterRefsSendMany{}
	s.handler = handler
	s.sends = make(map[string]*ClusterRefsSend)
	return s
}

func (s *ClusterRefsSendMany) NewSend(peerAddr string, notifyId int64) NotifySend {
	send := NewClusterRefsSend(s.handler)
	send.notifyId = notifyId
	s.Mux.Lock()
	s.sends[peerAddr] = send
	s.Mux.Unlock()
	return send
}

func (s *ClusterRefsSendMany) DoneSend(peerAddr string, send NotifySend) {
	asend, ok := send.(*ClusterRefsSend)
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
func (s *ClusterRefsSendMany) Update(ctx context.Context, obj *edgeproto.ClusterRefs, modRev int64) {
	s.Mux.Lock()
	defer s.Mux.Unlock()
	for _, send := range s.sends {
		send.Update(ctx, obj, modRev)
	}
}

func (s *ClusterRefsSendMany) GetTypeString() string {
	return "ClusterRefs"
}

type ClusterRefsRecv struct {
	Name        string
	MessageName string
	handler     RecvClusterRefsHandler
	sendAllKeys map[edgeproto.ClusterKey]struct{}
	Mux         sync.Mutex
	buf         edgeproto.ClusterRefs
	RecvCount   uint64
	sendrecv    *SendRecv
}

func NewClusterRefsRecv(handler RecvClusterRefsHandler) *ClusterRefsRecv {
	recv := &ClusterRefsRecv{}
	recv.Name = "ClusterRefs"
	recv.MessageName = proto.MessageName((*edgeproto.ClusterRefs)(nil))
	recv.handler = handler
	return recv
}

func (s *ClusterRefsRecv) SetSendRecv(sendrecv *SendRecv) {
	s.sendrecv = sendrecv
}

func (s *ClusterRefsRecv) GetMessageName() string {
	return s.MessageName
}

func (s *ClusterRefsRecv) GetName() string {
	return s.Name
}

func (s *ClusterRefsRecv) GetRecvCount() uint64 {
	return s.RecvCount
}

func (s *ClusterRefsRecv) Recv(ctx context.Context, notice *edgeproto.Notice, notifyId int64, peerAddr string) {
	span := opentracing.SpanFromContext(ctx)
	if span != nil {
		span.SetTag("objtype", "ClusterRefs")
	}

	buf := &edgeproto.ClusterRefs{}
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
		fmt.Sprintf("%s recv ClusterRefs", s.sendrecv.cliserv),
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

func (s *ClusterRefsRecv) RecvAllStart() {
	s.Mux.Lock()
	defer s.Mux.Unlock()
	s.sendAllKeys = make(map[edgeproto.ClusterKey]struct{})
}

func (s *ClusterRefsRecv) RecvAllEnd(ctx context.Context, cleanup Cleanup) {
	s.Mux.Lock()
	validKeys := s.sendAllKeys
	s.sendAllKeys = nil
	s.Mux.Unlock()
	if cleanup == CleanupPrune {
		s.handler.Prune(ctx, validKeys)
	}
}
func (s *ClusterRefsRecv) Flush(ctx context.Context, notifyId int64) {
	s.handler.Flush(ctx, notifyId)
}

type ClusterRefsRecvMany struct {
	handler RecvClusterRefsHandler
}

func NewClusterRefsRecvMany(handler RecvClusterRefsHandler) *ClusterRefsRecvMany {
	s := &ClusterRefsRecvMany{}
	s.handler = handler
	return s
}

func (s *ClusterRefsRecvMany) NewRecv() NotifyRecv {
	recv := NewClusterRefsRecv(s.handler)
	return recv
}

func (s *ClusterRefsRecvMany) Flush(ctx context.Context, notifyId int64) {
	s.handler.Flush(ctx, notifyId)
}
func (mgr *ServerMgr) RegisterSendClusterRefsCache(cache ClusterRefsCacheHandler) {
	send := NewClusterRefsSendMany(cache)
	mgr.RegisterSend(send)
	cache.AddNotifyCb(send.Update)
}

func (mgr *ServerMgr) RegisterRecvClusterRefsCache(cache ClusterRefsCacheHandler) {
	recv := NewClusterRefsRecvMany(cache)
	mgr.RegisterRecv(recv)
}

func (s *Client) RegisterSendClusterRefsCache(cache ClusterRefsCacheHandler) {
	send := NewClusterRefsSend(cache)
	s.RegisterSend(send)
	cache.AddNotifyCb(send.Update)
}

func (s *Client) RegisterRecvClusterRefsCache(cache ClusterRefsCacheHandler) {
	recv := NewClusterRefsRecv(cache)
	s.RegisterRecv(recv)
}

type SendAppInstRefsHandler interface {
	GetAllLocked(ctx context.Context, cb func(key *edgeproto.AppInstRefs, modRev int64))
	GetWithRev(key *edgeproto.AppKey, buf *edgeproto.AppInstRefs, modRev *int64) bool
}

type RecvAppInstRefsHandler interface {
	Update(ctx context.Context, in *edgeproto.AppInstRefs, rev int64)
	Delete(ctx context.Context, in *edgeproto.AppInstRefs, rev int64)
	Prune(ctx context.Context, keys map[edgeproto.AppKey]struct{})
	Flush(ctx context.Context, notifyId int64)
}

type AppInstRefsCacheHandler interface {
	SendAppInstRefsHandler
	RecvAppInstRefsHandler
	AddNotifyCb(fn func(ctx context.Context, obj *edgeproto.AppInstRefs, modRev int64))
}

type AppInstRefsSend struct {
	Name        string
	MessageName string
	handler     SendAppInstRefsHandler
	Keys        map[edgeproto.AppKey]AppInstRefsSendContext
	keysToSend  map[edgeproto.AppKey]AppInstRefsSendContext
	notifyId    int64
	Mux         sync.Mutex
	buf         edgeproto.AppInstRefs
	SendCount   uint64
	sendrecv    *SendRecv
}

type AppInstRefsSendContext struct {
	ctx         context.Context
	modRev      int64
	forceDelete bool
}

func NewAppInstRefsSend(handler SendAppInstRefsHandler) *AppInstRefsSend {
	send := &AppInstRefsSend{}
	send.Name = "AppInstRefs"
	send.MessageName = proto.MessageName((*edgeproto.AppInstRefs)(nil))
	send.handler = handler
	send.Keys = make(map[edgeproto.AppKey]AppInstRefsSendContext)
	return send
}

func (s *AppInstRefsSend) SetSendRecv(sendrecv *SendRecv) {
	s.sendrecv = sendrecv
}

func (s *AppInstRefsSend) GetMessageName() string {
	return s.MessageName
}

func (s *AppInstRefsSend) GetName() string {
	return s.Name
}

func (s *AppInstRefsSend) GetSendCount() uint64 {
	return s.SendCount
}

func (s *AppInstRefsSend) GetNotifyId() int64 {
	return s.notifyId
}
func (s *AppInstRefsSend) UpdateAll(ctx context.Context) {
	if !s.sendrecv.isRemoteWanted(s.MessageName) {
		return
	}
	s.Mux.Lock()
	s.handler.GetAllLocked(ctx, func(obj *edgeproto.AppInstRefs, modRev int64) {
		s.Keys[*obj.GetKey()] = AppInstRefsSendContext{
			ctx:    ctx,
			modRev: modRev,
		}
	})
	s.Mux.Unlock()
}

func (s *AppInstRefsSend) Update(ctx context.Context, obj *edgeproto.AppInstRefs, modRev int64) {
	if !s.sendrecv.isRemoteWanted(s.MessageName) {
		return
	}
	forceDelete := false
	s.updateInternal(ctx, obj.GetKey(), modRev, forceDelete)
}

func (s *AppInstRefsSend) ForceDelete(ctx context.Context, key *edgeproto.AppKey, modRev int64) {
	forceDelete := true
	s.updateInternal(ctx, key, modRev, forceDelete)
}

func (s *AppInstRefsSend) updateInternal(ctx context.Context, key *edgeproto.AppKey, modRev int64, forceDelete bool) {
	s.Mux.Lock()
	log.SpanLog(ctx, log.DebugLevelNotify, "updateInternal AppInstRefs", "key", key, "modRev", modRev)
	s.Keys[*key] = AppInstRefsSendContext{
		ctx:         ctx,
		modRev:      modRev,
		forceDelete: forceDelete,
	}
	s.Mux.Unlock()
	s.sendrecv.wakeup()
}

func (s *AppInstRefsSend) SendForCloudlet(ctx context.Context, action edgeproto.NoticeAction, cloudlet *edgeproto.Cloudlet) {
}

func (s *AppInstRefsSend) Send(stream StreamNotify, notice *edgeproto.Notice, peer string) error {
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
			fmt.Sprintf("%s send AppInstRefs", s.sendrecv.cliserv),
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

func (s *AppInstRefsSend) PrepData() bool {
	s.Mux.Lock()
	defer s.Mux.Unlock()
	if len(s.Keys) > 0 {
		s.keysToSend = s.Keys
		s.Keys = make(map[edgeproto.AppKey]AppInstRefsSendContext)
		return true
	}
	return false
}

// Server accepts multiple clients so needs to track multiple
// peers to send to.
type AppInstRefsSendMany struct {
	handler SendAppInstRefsHandler
	Mux     sync.Mutex
	sends   map[string]*AppInstRefsSend
}

func NewAppInstRefsSendMany(handler SendAppInstRefsHandler) *AppInstRefsSendMany {
	s := &AppInstRefsSendMany{}
	s.handler = handler
	s.sends = make(map[string]*AppInstRefsSend)
	return s
}

func (s *AppInstRefsSendMany) NewSend(peerAddr string, notifyId int64) NotifySend {
	send := NewAppInstRefsSend(s.handler)
	send.notifyId = notifyId
	s.Mux.Lock()
	s.sends[peerAddr] = send
	s.Mux.Unlock()
	return send
}

func (s *AppInstRefsSendMany) DoneSend(peerAddr string, send NotifySend) {
	asend, ok := send.(*AppInstRefsSend)
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
func (s *AppInstRefsSendMany) Update(ctx context.Context, obj *edgeproto.AppInstRefs, modRev int64) {
	s.Mux.Lock()
	defer s.Mux.Unlock()
	for _, send := range s.sends {
		send.Update(ctx, obj, modRev)
	}
}

func (s *AppInstRefsSendMany) GetTypeString() string {
	return "AppInstRefs"
}

type AppInstRefsRecv struct {
	Name        string
	MessageName string
	handler     RecvAppInstRefsHandler
	sendAllKeys map[edgeproto.AppKey]struct{}
	Mux         sync.Mutex
	buf         edgeproto.AppInstRefs
	RecvCount   uint64
	sendrecv    *SendRecv
}

func NewAppInstRefsRecv(handler RecvAppInstRefsHandler) *AppInstRefsRecv {
	recv := &AppInstRefsRecv{}
	recv.Name = "AppInstRefs"
	recv.MessageName = proto.MessageName((*edgeproto.AppInstRefs)(nil))
	recv.handler = handler
	return recv
}

func (s *AppInstRefsRecv) SetSendRecv(sendrecv *SendRecv) {
	s.sendrecv = sendrecv
}

func (s *AppInstRefsRecv) GetMessageName() string {
	return s.MessageName
}

func (s *AppInstRefsRecv) GetName() string {
	return s.Name
}

func (s *AppInstRefsRecv) GetRecvCount() uint64 {
	return s.RecvCount
}

func (s *AppInstRefsRecv) Recv(ctx context.Context, notice *edgeproto.Notice, notifyId int64, peerAddr string) {
	span := opentracing.SpanFromContext(ctx)
	if span != nil {
		span.SetTag("objtype", "AppInstRefs")
	}

	buf := &edgeproto.AppInstRefs{}
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
		fmt.Sprintf("%s recv AppInstRefs", s.sendrecv.cliserv),
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

func (s *AppInstRefsRecv) RecvAllStart() {
	s.Mux.Lock()
	defer s.Mux.Unlock()
	s.sendAllKeys = make(map[edgeproto.AppKey]struct{})
}

func (s *AppInstRefsRecv) RecvAllEnd(ctx context.Context, cleanup Cleanup) {
	s.Mux.Lock()
	validKeys := s.sendAllKeys
	s.sendAllKeys = nil
	s.Mux.Unlock()
	if cleanup == CleanupPrune {
		s.handler.Prune(ctx, validKeys)
	}
}
func (s *AppInstRefsRecv) Flush(ctx context.Context, notifyId int64) {
	s.handler.Flush(ctx, notifyId)
}

type AppInstRefsRecvMany struct {
	handler RecvAppInstRefsHandler
}

func NewAppInstRefsRecvMany(handler RecvAppInstRefsHandler) *AppInstRefsRecvMany {
	s := &AppInstRefsRecvMany{}
	s.handler = handler
	return s
}

func (s *AppInstRefsRecvMany) NewRecv() NotifyRecv {
	recv := NewAppInstRefsRecv(s.handler)
	return recv
}

func (s *AppInstRefsRecvMany) Flush(ctx context.Context, notifyId int64) {
	s.handler.Flush(ctx, notifyId)
}
func (mgr *ServerMgr) RegisterSendAppInstRefsCache(cache AppInstRefsCacheHandler) {
	send := NewAppInstRefsSendMany(cache)
	mgr.RegisterSend(send)
	cache.AddNotifyCb(send.Update)
}

func (mgr *ServerMgr) RegisterRecvAppInstRefsCache(cache AppInstRefsCacheHandler) {
	recv := NewAppInstRefsRecvMany(cache)
	mgr.RegisterRecv(recv)
}

func (s *Client) RegisterSendAppInstRefsCache(cache AppInstRefsCacheHandler) {
	send := NewAppInstRefsSend(cache)
	s.RegisterSend(send)
	cache.AddNotifyCb(send.Update)
}

func (s *Client) RegisterRecvAppInstRefsCache(cache AppInstRefsCacheHandler) {
	recv := NewAppInstRefsRecv(cache)
	s.RegisterRecv(recv)
}
