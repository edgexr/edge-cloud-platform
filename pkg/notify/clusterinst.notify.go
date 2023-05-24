// Code generated by protoc-gen-gogo. DO NOT EDIT.
// source: clusterinst.proto

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

type SendClusterInstHandler interface {
	GetAllLocked(ctx context.Context, cb func(key *edgeproto.ClusterInst, modRev int64))
	GetWithRev(key *edgeproto.ClusterInstKey, buf *edgeproto.ClusterInst, modRev *int64) bool
	GetForCloudlet(cloudlet *edgeproto.Cloudlet, cb func(data *edgeproto.ClusterInstCacheData))
}

type RecvClusterInstHandler interface {
	Update(ctx context.Context, in *edgeproto.ClusterInst, rev int64)
	Delete(ctx context.Context, in *edgeproto.ClusterInst, rev int64)
	Prune(ctx context.Context, keys map[edgeproto.ClusterInstKey]struct{})
	Flush(ctx context.Context, notifyId int64)
}

type ClusterInstCacheHandler interface {
	SendClusterInstHandler
	RecvClusterInstHandler
	AddNotifyCb(fn func(ctx context.Context, obj *edgeproto.ClusterInst, modRev int64))
}

type ClusterInstSend struct {
	Name        string
	MessageName string
	handler     SendClusterInstHandler
	Keys        map[edgeproto.ClusterInstKey]ClusterInstSendContext
	keysToSend  map[edgeproto.ClusterInstKey]ClusterInstSendContext
	notifyId    int64
	Mux         sync.Mutex
	buf         edgeproto.ClusterInst
	SendCount   uint64
	sendrecv    *SendRecv
}

type ClusterInstSendContext struct {
	ctx         context.Context
	modRev      int64
	forceDelete bool
}

func NewClusterInstSend(handler SendClusterInstHandler) *ClusterInstSend {
	send := &ClusterInstSend{}
	send.Name = "ClusterInst"
	send.MessageName = proto.MessageName((*edgeproto.ClusterInst)(nil))
	send.handler = handler
	send.Keys = make(map[edgeproto.ClusterInstKey]ClusterInstSendContext)
	return send
}

func (s *ClusterInstSend) SetSendRecv(sendrecv *SendRecv) {
	s.sendrecv = sendrecv
}

func (s *ClusterInstSend) GetMessageName() string {
	return s.MessageName
}

func (s *ClusterInstSend) GetName() string {
	return s.Name
}

func (s *ClusterInstSend) GetSendCount() uint64 {
	return s.SendCount
}

func (s *ClusterInstSend) GetNotifyId() int64 {
	return s.notifyId
}
func (s *ClusterInstSend) UpdateAll(ctx context.Context) {
	if !s.sendrecv.isRemoteWanted(s.MessageName) {
		return
	}
	s.Mux.Lock()
	s.handler.GetAllLocked(ctx, func(obj *edgeproto.ClusterInst, modRev int64) {
		if !s.UpdateAllOkLocked(obj) { // to be implemented by hand
			return
		}
		s.Keys[*obj.GetKey()] = ClusterInstSendContext{
			ctx:    ctx,
			modRev: modRev,
		}
	})
	s.Mux.Unlock()
}

func (s *ClusterInstSend) Update(ctx context.Context, obj *edgeproto.ClusterInst, modRev int64) {
	if !s.sendrecv.isRemoteWanted(s.MessageName) {
		return
	}
	if !s.UpdateOk(ctx, obj) { // to be implemented by hand
		return
	}
	forceDelete := false
	s.updateInternal(ctx, obj.GetKey(), modRev, forceDelete)
}

func (s *ClusterInstSend) ForceDelete(ctx context.Context, key *edgeproto.ClusterInstKey, modRev int64) {
	forceDelete := true
	s.updateInternal(ctx, key, modRev, forceDelete)
}

func (s *ClusterInstSend) updateInternal(ctx context.Context, key *edgeproto.ClusterInstKey, modRev int64, forceDelete bool) {
	s.Mux.Lock()
	log.SpanLog(ctx, log.DebugLevelNotify, "updateInternal ClusterInst", "key", key, "modRev", modRev)
	s.Keys[*key] = ClusterInstSendContext{
		ctx:         ctx,
		modRev:      modRev,
		forceDelete: forceDelete,
	}
	s.Mux.Unlock()
	s.sendrecv.wakeup()
}

func (s *ClusterInstSend) SendForCloudlet(ctx context.Context, action edgeproto.NoticeAction, cloudlet *edgeproto.Cloudlet) {
	keys := make(map[edgeproto.ClusterInstKey]*edgeproto.ClusterInstCacheData)
	s.handler.GetForCloudlet(cloudlet, func(data *edgeproto.ClusterInstCacheData) {
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

func (s *ClusterInstSend) Send(stream StreamNotify, notice *edgeproto.Notice, peer string) error {
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
			fmt.Sprintf("%s send ClusterInst", s.sendrecv.cliserv),
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

func (s *ClusterInstSend) PrepData() bool {
	s.Mux.Lock()
	defer s.Mux.Unlock()
	if len(s.Keys) > 0 {
		s.keysToSend = s.Keys
		s.Keys = make(map[edgeproto.ClusterInstKey]ClusterInstSendContext)
		return true
	}
	return false
}

// Server accepts multiple clients so needs to track multiple
// peers to send to.
type ClusterInstSendMany struct {
	handler SendClusterInstHandler
	Mux     sync.Mutex
	sends   map[string]*ClusterInstSend
}

func NewClusterInstSendMany(handler SendClusterInstHandler) *ClusterInstSendMany {
	s := &ClusterInstSendMany{}
	s.handler = handler
	s.sends = make(map[string]*ClusterInstSend)
	return s
}

func (s *ClusterInstSendMany) NewSend(peerAddr string, notifyId int64) NotifySend {
	send := NewClusterInstSend(s.handler)
	send.notifyId = notifyId
	s.Mux.Lock()
	s.sends[peerAddr] = send
	s.Mux.Unlock()
	return send
}

func (s *ClusterInstSendMany) DoneSend(peerAddr string, send NotifySend) {
	asend, ok := send.(*ClusterInstSend)
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
func (s *ClusterInstSendMany) Update(ctx context.Context, obj *edgeproto.ClusterInst, modRev int64) {
	s.Mux.Lock()
	defer s.Mux.Unlock()
	for _, send := range s.sends {
		send.Update(ctx, obj, modRev)
	}
}

func (s *ClusterInstSendMany) GetTypeString() string {
	return "ClusterInst"
}

type ClusterInstRecv struct {
	Name        string
	MessageName string
	handler     RecvClusterInstHandler
	sendAllKeys map[edgeproto.ClusterInstKey]struct{}
	Mux         sync.Mutex
	buf         edgeproto.ClusterInst
	RecvCount   uint64
	sendrecv    *SendRecv
}

func NewClusterInstRecv(handler RecvClusterInstHandler) *ClusterInstRecv {
	recv := &ClusterInstRecv{}
	recv.Name = "ClusterInst"
	recv.MessageName = proto.MessageName((*edgeproto.ClusterInst)(nil))
	recv.handler = handler
	return recv
}

func (s *ClusterInstRecv) SetSendRecv(sendrecv *SendRecv) {
	s.sendrecv = sendrecv
}

func (s *ClusterInstRecv) GetMessageName() string {
	return s.MessageName
}

func (s *ClusterInstRecv) GetName() string {
	return s.Name
}

func (s *ClusterInstRecv) GetRecvCount() uint64 {
	return s.RecvCount
}

func (s *ClusterInstRecv) Recv(ctx context.Context, notice *edgeproto.Notice, notifyId int64, peerAddr string) {
	span := opentracing.SpanFromContext(ctx)
	if span != nil {
		span.SetTag("objtype", "ClusterInst")
	}

	buf := &edgeproto.ClusterInst{}
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
		fmt.Sprintf("%s recv ClusterInst", s.sendrecv.cliserv),
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

func (s *ClusterInstRecv) RecvAllStart() {
	s.Mux.Lock()
	defer s.Mux.Unlock()
	s.sendAllKeys = make(map[edgeproto.ClusterInstKey]struct{})
}

func (s *ClusterInstRecv) RecvAllEnd(ctx context.Context, cleanup Cleanup) {
	s.Mux.Lock()
	validKeys := s.sendAllKeys
	s.sendAllKeys = nil
	s.Mux.Unlock()
	if cleanup == CleanupPrune {
		s.handler.Prune(ctx, validKeys)
	}
}
func (s *ClusterInstRecv) Flush(ctx context.Context, notifyId int64) {
	s.handler.Flush(ctx, notifyId)
}

type ClusterInstRecvMany struct {
	handler RecvClusterInstHandler
}

func NewClusterInstRecvMany(handler RecvClusterInstHandler) *ClusterInstRecvMany {
	s := &ClusterInstRecvMany{}
	s.handler = handler
	return s
}

func (s *ClusterInstRecvMany) NewRecv() NotifyRecv {
	recv := NewClusterInstRecv(s.handler)
	return recv
}

func (s *ClusterInstRecvMany) Flush(ctx context.Context, notifyId int64) {
	s.handler.Flush(ctx, notifyId)
}
func (mgr *ServerMgr) RegisterSendClusterInstCache(cache ClusterInstCacheHandler) {
	send := NewClusterInstSendMany(cache)
	mgr.RegisterSend(send)
	cache.AddNotifyCb(send.Update)
}

func (mgr *ServerMgr) RegisterRecvClusterInstCache(cache ClusterInstCacheHandler) {
	recv := NewClusterInstRecvMany(cache)
	mgr.RegisterRecv(recv)
}

func (s *Client) RegisterSendClusterInstCache(cache ClusterInstCacheHandler) {
	send := NewClusterInstSend(cache)
	s.RegisterSend(send)
	cache.AddNotifyCb(send.Update)
}

func (s *Client) RegisterRecvClusterInstCache(cache ClusterInstCacheHandler) {
	recv := NewClusterInstRecv(cache)
	s.RegisterRecv(recv)
}

type SendClusterInstInfoHandler interface {
	GetAllLocked(ctx context.Context, cb func(key *edgeproto.ClusterInstInfo, modRev int64))
	GetWithRev(key *edgeproto.ClusterInstKey, buf *edgeproto.ClusterInstInfo, modRev *int64) bool
}

type RecvClusterInstInfoHandler interface {
	Update(ctx context.Context, in *edgeproto.ClusterInstInfo, rev int64)
	Delete(ctx context.Context, in *edgeproto.ClusterInstInfo, rev int64)
	Prune(ctx context.Context, keys map[edgeproto.ClusterInstKey]struct{})
	Flush(ctx context.Context, notifyId int64)
}

type ClusterInstInfoCacheHandler interface {
	SendClusterInstInfoHandler
	RecvClusterInstInfoHandler
	AddNotifyCb(fn func(ctx context.Context, obj *edgeproto.ClusterInstInfo, modRev int64))
}

type ClusterInstInfoSend struct {
	Name        string
	MessageName string
	handler     SendClusterInstInfoHandler
	Keys        map[edgeproto.ClusterInstKey]ClusterInstInfoSendContext
	keysToSend  map[edgeproto.ClusterInstKey]ClusterInstInfoSendContext
	notifyId    int64
	Mux         sync.Mutex
	buf         edgeproto.ClusterInstInfo
	SendCount   uint64
	sendrecv    *SendRecv
}

type ClusterInstInfoSendContext struct {
	ctx         context.Context
	modRev      int64
	forceDelete bool
}

func NewClusterInstInfoSend(handler SendClusterInstInfoHandler) *ClusterInstInfoSend {
	send := &ClusterInstInfoSend{}
	send.Name = "ClusterInstInfo"
	send.MessageName = proto.MessageName((*edgeproto.ClusterInstInfo)(nil))
	send.handler = handler
	send.Keys = make(map[edgeproto.ClusterInstKey]ClusterInstInfoSendContext)
	return send
}

func (s *ClusterInstInfoSend) SetSendRecv(sendrecv *SendRecv) {
	s.sendrecv = sendrecv
}

func (s *ClusterInstInfoSend) GetMessageName() string {
	return s.MessageName
}

func (s *ClusterInstInfoSend) GetName() string {
	return s.Name
}

func (s *ClusterInstInfoSend) GetSendCount() uint64 {
	return s.SendCount
}

func (s *ClusterInstInfoSend) GetNotifyId() int64 {
	return s.notifyId
}
func (s *ClusterInstInfoSend) UpdateAll(ctx context.Context) {
	if !s.sendrecv.isRemoteWanted(s.MessageName) {
		return
	}
	s.Mux.Lock()
	s.handler.GetAllLocked(ctx, func(obj *edgeproto.ClusterInstInfo, modRev int64) {
		s.Keys[*obj.GetKey()] = ClusterInstInfoSendContext{
			ctx:    ctx,
			modRev: modRev,
		}
	})
	s.Mux.Unlock()
}

func (s *ClusterInstInfoSend) Update(ctx context.Context, obj *edgeproto.ClusterInstInfo, modRev int64) {
	if !s.sendrecv.isRemoteWanted(s.MessageName) {
		return
	}
	forceDelete := false
	s.updateInternal(ctx, obj.GetKey(), modRev, forceDelete)
}

func (s *ClusterInstInfoSend) ForceDelete(ctx context.Context, key *edgeproto.ClusterInstKey, modRev int64) {
	forceDelete := true
	s.updateInternal(ctx, key, modRev, forceDelete)
}

func (s *ClusterInstInfoSend) updateInternal(ctx context.Context, key *edgeproto.ClusterInstKey, modRev int64, forceDelete bool) {
	s.Mux.Lock()
	log.SpanLog(ctx, log.DebugLevelNotify, "updateInternal ClusterInstInfo", "key", key, "modRev", modRev)
	s.Keys[*key] = ClusterInstInfoSendContext{
		ctx:         ctx,
		modRev:      modRev,
		forceDelete: forceDelete,
	}
	s.Mux.Unlock()
	s.sendrecv.wakeup()
}

func (s *ClusterInstInfoSend) SendForCloudlet(ctx context.Context, action edgeproto.NoticeAction, cloudlet *edgeproto.Cloudlet) {
}

func (s *ClusterInstInfoSend) Send(stream StreamNotify, notice *edgeproto.Notice, peer string) error {
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
			fmt.Sprintf("%s send ClusterInstInfo", s.sendrecv.cliserv),
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

func (s *ClusterInstInfoSend) PrepData() bool {
	s.Mux.Lock()
	defer s.Mux.Unlock()
	if len(s.Keys) > 0 {
		s.keysToSend = s.Keys
		s.Keys = make(map[edgeproto.ClusterInstKey]ClusterInstInfoSendContext)
		return true
	}
	return false
}

// Server accepts multiple clients so needs to track multiple
// peers to send to.
type ClusterInstInfoSendMany struct {
	handler SendClusterInstInfoHandler
	Mux     sync.Mutex
	sends   map[string]*ClusterInstInfoSend
}

func NewClusterInstInfoSendMany(handler SendClusterInstInfoHandler) *ClusterInstInfoSendMany {
	s := &ClusterInstInfoSendMany{}
	s.handler = handler
	s.sends = make(map[string]*ClusterInstInfoSend)
	return s
}

func (s *ClusterInstInfoSendMany) NewSend(peerAddr string, notifyId int64) NotifySend {
	send := NewClusterInstInfoSend(s.handler)
	send.notifyId = notifyId
	s.Mux.Lock()
	s.sends[peerAddr] = send
	s.Mux.Unlock()
	return send
}

func (s *ClusterInstInfoSendMany) DoneSend(peerAddr string, send NotifySend) {
	asend, ok := send.(*ClusterInstInfoSend)
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
func (s *ClusterInstInfoSendMany) Update(ctx context.Context, obj *edgeproto.ClusterInstInfo, modRev int64) {
	s.Mux.Lock()
	defer s.Mux.Unlock()
	for _, send := range s.sends {
		send.Update(ctx, obj, modRev)
	}
}

func (s *ClusterInstInfoSendMany) GetTypeString() string {
	return "ClusterInstInfo"
}

type ClusterInstInfoRecv struct {
	Name        string
	MessageName string
	handler     RecvClusterInstInfoHandler
	sendAllKeys map[edgeproto.ClusterInstKey]struct{}
	Mux         sync.Mutex
	buf         edgeproto.ClusterInstInfo
	RecvCount   uint64
	sendrecv    *SendRecv
}

func NewClusterInstInfoRecv(handler RecvClusterInstInfoHandler) *ClusterInstInfoRecv {
	recv := &ClusterInstInfoRecv{}
	recv.Name = "ClusterInstInfo"
	recv.MessageName = proto.MessageName((*edgeproto.ClusterInstInfo)(nil))
	recv.handler = handler
	return recv
}

func (s *ClusterInstInfoRecv) SetSendRecv(sendrecv *SendRecv) {
	s.sendrecv = sendrecv
}

func (s *ClusterInstInfoRecv) GetMessageName() string {
	return s.MessageName
}

func (s *ClusterInstInfoRecv) GetName() string {
	return s.Name
}

func (s *ClusterInstInfoRecv) GetRecvCount() uint64 {
	return s.RecvCount
}

func (s *ClusterInstInfoRecv) Recv(ctx context.Context, notice *edgeproto.Notice, notifyId int64, peerAddr string) {
	span := opentracing.SpanFromContext(ctx)
	if span != nil {
		span.SetTag("objtype", "ClusterInstInfo")
	}

	buf := &edgeproto.ClusterInstInfo{}
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
		fmt.Sprintf("%s recv ClusterInstInfo", s.sendrecv.cliserv),
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

func (s *ClusterInstInfoRecv) RecvAllStart() {
	s.Mux.Lock()
	defer s.Mux.Unlock()
	s.sendAllKeys = make(map[edgeproto.ClusterInstKey]struct{})
}

func (s *ClusterInstInfoRecv) RecvAllEnd(ctx context.Context, cleanup Cleanup) {
	s.Mux.Lock()
	validKeys := s.sendAllKeys
	s.sendAllKeys = nil
	s.Mux.Unlock()
	if cleanup == CleanupPrune {
		s.handler.Prune(ctx, validKeys)
	}
}
func (s *ClusterInstInfoRecv) Flush(ctx context.Context, notifyId int64) {
	s.handler.Flush(ctx, notifyId)
}

type ClusterInstInfoRecvMany struct {
	handler RecvClusterInstInfoHandler
}

func NewClusterInstInfoRecvMany(handler RecvClusterInstInfoHandler) *ClusterInstInfoRecvMany {
	s := &ClusterInstInfoRecvMany{}
	s.handler = handler
	return s
}

func (s *ClusterInstInfoRecvMany) NewRecv() NotifyRecv {
	recv := NewClusterInstInfoRecv(s.handler)
	return recv
}

func (s *ClusterInstInfoRecvMany) Flush(ctx context.Context, notifyId int64) {
	s.handler.Flush(ctx, notifyId)
}
func (mgr *ServerMgr) RegisterSendClusterInstInfoCache(cache ClusterInstInfoCacheHandler) {
	send := NewClusterInstInfoSendMany(cache)
	mgr.RegisterSend(send)
	cache.AddNotifyCb(send.Update)
}

func (mgr *ServerMgr) RegisterRecvClusterInstInfoCache(cache ClusterInstInfoCacheHandler) {
	recv := NewClusterInstInfoRecvMany(cache)
	mgr.RegisterRecv(recv)
}

func (s *Client) RegisterSendClusterInstInfoCache(cache ClusterInstInfoCacheHandler) {
	send := NewClusterInstInfoSend(cache)
	s.RegisterSend(send)
	cache.AddNotifyCb(send.Update)
}

func (s *Client) RegisterRecvClusterInstInfoCache(cache ClusterInstInfoCacheHandler) {
	recv := NewClusterInstInfoRecv(cache)
	s.RegisterRecv(recv)
}
