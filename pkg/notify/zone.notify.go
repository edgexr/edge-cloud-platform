// Code generated by protoc-gen-gogo. DO NOT EDIT.
// source: zone.proto

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

type SendZoneHandler interface {
	GetAllLocked(ctx context.Context, cb func(key *edgeproto.Zone, modRev int64))
	GetWithRev(key *edgeproto.ZoneKey, buf *edgeproto.Zone, modRev *int64) bool
}

type RecvZoneHandler interface {
	Update(ctx context.Context, in *edgeproto.Zone, rev int64)
	Delete(ctx context.Context, in *edgeproto.Zone, rev int64)
	Prune(ctx context.Context, keys map[edgeproto.ZoneKey]struct{})
	Flush(ctx context.Context, notifyId int64)
}

type ZoneCacheHandler interface {
	SendZoneHandler
	RecvZoneHandler
	AddNotifyCb(fn func(ctx context.Context, obj *edgeproto.Zone, modRev int64))
}

type ZoneSend struct {
	Name        string
	MessageName string
	handler     SendZoneHandler
	Keys        map[edgeproto.ZoneKey]ZoneSendContext
	keysToSend  map[edgeproto.ZoneKey]ZoneSendContext
	notifyId    int64
	Mux         sync.Mutex
	buf         edgeproto.Zone
	SendCount   uint64
	sendrecv    *SendRecv
}

type ZoneSendContext struct {
	ctx         context.Context
	modRev      int64
	forceDelete bool
}

func NewZoneSend(handler SendZoneHandler) *ZoneSend {
	send := &ZoneSend{}
	send.Name = "Zone"
	send.MessageName = proto.MessageName((*edgeproto.Zone)(nil))
	send.handler = handler
	send.Keys = make(map[edgeproto.ZoneKey]ZoneSendContext)
	return send
}

func (s *ZoneSend) SetSendRecv(sendrecv *SendRecv) {
	s.sendrecv = sendrecv
}

func (s *ZoneSend) GetMessageName() string {
	return s.MessageName
}

func (s *ZoneSend) GetName() string {
	return s.Name
}

func (s *ZoneSend) GetSendCount() uint64 {
	return s.SendCount
}

func (s *ZoneSend) GetNotifyId() int64 {
	return s.notifyId
}
func (s *ZoneSend) UpdateAll(ctx context.Context) {
	if !s.sendrecv.isRemoteWanted(s.MessageName) {
		return
	}
	s.Mux.Lock()
	s.handler.GetAllLocked(ctx, func(obj *edgeproto.Zone, modRev int64) {
		s.Keys[*obj.GetKey()] = ZoneSendContext{
			ctx:    ctx,
			modRev: modRev,
		}
	})
	s.Mux.Unlock()
}

func (s *ZoneSend) Update(ctx context.Context, obj *edgeproto.Zone, modRev int64) {
	if !s.sendrecv.isRemoteWanted(s.MessageName) {
		return
	}
	forceDelete := false
	s.updateInternal(ctx, obj.GetKey(), modRev, forceDelete)
}

func (s *ZoneSend) ForceDelete(ctx context.Context, key *edgeproto.ZoneKey, modRev int64) {
	forceDelete := true
	s.updateInternal(ctx, key, modRev, forceDelete)
}

func (s *ZoneSend) updateInternal(ctx context.Context, key *edgeproto.ZoneKey, modRev int64, forceDelete bool) {
	s.Mux.Lock()
	log.SpanLog(ctx, log.DebugLevelNotify, "updateInternal Zone", "key", key, "modRev", modRev)
	s.Keys[*key] = ZoneSendContext{
		ctx:         ctx,
		modRev:      modRev,
		forceDelete: forceDelete,
	}
	s.Mux.Unlock()
	s.sendrecv.wakeup()
}

func (s *ZoneSend) SendForCloudlet(ctx context.Context, action edgeproto.NoticeAction, cloudlet *edgeproto.Cloudlet) {
}

func (s *ZoneSend) Send(stream StreamNotify, notice *edgeproto.Notice, peer string) error {
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
			fmt.Sprintf("%s send Zone", s.sendrecv.cliserv),
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

func (s *ZoneSend) PrepData() bool {
	s.Mux.Lock()
	defer s.Mux.Unlock()
	if len(s.Keys) > 0 {
		s.keysToSend = s.Keys
		s.Keys = make(map[edgeproto.ZoneKey]ZoneSendContext)
		return true
	}
	return false
}

// Server accepts multiple clients so needs to track multiple
// peers to send to.
type ZoneSendMany struct {
	handler SendZoneHandler
	Mux     sync.Mutex
	sends   map[string]*ZoneSend
}

func NewZoneSendMany(handler SendZoneHandler) *ZoneSendMany {
	s := &ZoneSendMany{}
	s.handler = handler
	s.sends = make(map[string]*ZoneSend)
	return s
}

func (s *ZoneSendMany) NewSend(peerAddr string, notifyId int64) NotifySend {
	send := NewZoneSend(s.handler)
	send.notifyId = notifyId
	s.Mux.Lock()
	s.sends[peerAddr] = send
	s.Mux.Unlock()
	return send
}

func (s *ZoneSendMany) DoneSend(peerAddr string, send NotifySend) {
	asend, ok := send.(*ZoneSend)
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
func (s *ZoneSendMany) Update(ctx context.Context, obj *edgeproto.Zone, modRev int64) {
	s.Mux.Lock()
	defer s.Mux.Unlock()
	for _, send := range s.sends {
		send.Update(ctx, obj, modRev)
	}
}

func (s *ZoneSendMany) GetTypeString() string {
	return "Zone"
}

type ZoneRecv struct {
	Name        string
	MessageName string
	handler     RecvZoneHandler
	sendAllKeys map[edgeproto.ZoneKey]struct{}
	Mux         sync.Mutex
	buf         edgeproto.Zone
	RecvCount   uint64
	sendrecv    *SendRecv
}

func NewZoneRecv(handler RecvZoneHandler) *ZoneRecv {
	recv := &ZoneRecv{}
	recv.Name = "Zone"
	recv.MessageName = proto.MessageName((*edgeproto.Zone)(nil))
	recv.handler = handler
	return recv
}

func (s *ZoneRecv) SetSendRecv(sendrecv *SendRecv) {
	s.sendrecv = sendrecv
}

func (s *ZoneRecv) GetMessageName() string {
	return s.MessageName
}

func (s *ZoneRecv) GetName() string {
	return s.Name
}

func (s *ZoneRecv) GetRecvCount() uint64 {
	return s.RecvCount
}

func (s *ZoneRecv) Recv(ctx context.Context, notice *edgeproto.Notice, notifyId int64, peerAddr string) {
	span := opentracing.SpanFromContext(ctx)
	if span != nil {
		span.SetTag("objtype", "Zone")
	}

	buf := &edgeproto.Zone{}
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
		fmt.Sprintf("%s recv Zone", s.sendrecv.cliserv),
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

func (s *ZoneRecv) RecvAllStart() {
	s.Mux.Lock()
	defer s.Mux.Unlock()
	s.sendAllKeys = make(map[edgeproto.ZoneKey]struct{})
}

func (s *ZoneRecv) RecvAllEnd(ctx context.Context, cleanup Cleanup) {
	s.Mux.Lock()
	validKeys := s.sendAllKeys
	s.sendAllKeys = nil
	s.Mux.Unlock()
	if cleanup == CleanupPrune {
		s.handler.Prune(ctx, validKeys)
	}
}
func (s *ZoneRecv) Flush(ctx context.Context, notifyId int64) {
	s.handler.Flush(ctx, notifyId)
}

type ZoneRecvMany struct {
	handler RecvZoneHandler
}

func NewZoneRecvMany(handler RecvZoneHandler) *ZoneRecvMany {
	s := &ZoneRecvMany{}
	s.handler = handler
	return s
}

func (s *ZoneRecvMany) NewRecv() NotifyRecv {
	recv := NewZoneRecv(s.handler)
	return recv
}

func (s *ZoneRecvMany) Flush(ctx context.Context, notifyId int64) {
	s.handler.Flush(ctx, notifyId)
}
func (mgr *ServerMgr) RegisterSendZoneCache(cache ZoneCacheHandler) {
	send := NewZoneSendMany(cache)
	mgr.RegisterSend(send)
	cache.AddNotifyCb(send.Update)
}

func (mgr *ServerMgr) RegisterRecvZoneCache(cache ZoneCacheHandler) {
	recv := NewZoneRecvMany(cache)
	mgr.RegisterRecv(recv)
}

func (s *Client) RegisterSendZoneCache(cache ZoneCacheHandler) {
	send := NewZoneSend(cache)
	s.RegisterSend(send)
	cache.AddNotifyCb(send.Update)
}

func (s *Client) RegisterRecvZoneCache(cache ZoneCacheHandler) {
	recv := NewZoneRecv(cache)
	s.RegisterRecv(recv)
}
