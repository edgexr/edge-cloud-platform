// Code generated by protoc-gen-gogo. DO NOT EDIT.
// source: flavor.proto

package notify

import (
	"context"
	fmt "fmt"
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

type SendFlavorHandler interface {
	GetAllLocked(ctx context.Context, cb func(key *edgeproto.Flavor, modRev int64))
	GetWithRev(key *edgeproto.FlavorKey, buf *edgeproto.Flavor, modRev *int64) bool
}

type RecvFlavorHandler interface {
	Update(ctx context.Context, in *edgeproto.Flavor, rev int64)
	Delete(ctx context.Context, in *edgeproto.Flavor, rev int64)
	Prune(ctx context.Context, keys map[edgeproto.FlavorKey]struct{})
	Flush(ctx context.Context, notifyId int64)
}

type FlavorCacheHandler interface {
	SendFlavorHandler
	RecvFlavorHandler
	AddNotifyCb(fn func(ctx context.Context, obj *edgeproto.Flavor, modRev int64))
}

type FlavorSend struct {
	Name        string
	MessageName string
	handler     SendFlavorHandler
	Keys        map[edgeproto.FlavorKey]FlavorSendContext
	keysToSend  map[edgeproto.FlavorKey]FlavorSendContext
	notifyId    int64
	Mux         sync.Mutex
	buf         edgeproto.Flavor
	SendCount   uint64
	sendrecv    *SendRecv
}

type FlavorSendContext struct {
	ctx         context.Context
	modRev      int64
	forceDelete bool
}

func NewFlavorSend(handler SendFlavorHandler) *FlavorSend {
	send := &FlavorSend{}
	send.Name = "Flavor"
	send.MessageName = proto.MessageName((*edgeproto.Flavor)(nil))
	send.handler = handler
	send.Keys = make(map[edgeproto.FlavorKey]FlavorSendContext)
	return send
}

func (s *FlavorSend) SetSendRecv(sendrecv *SendRecv) {
	s.sendrecv = sendrecv
}

func (s *FlavorSend) GetMessageName() string {
	return s.MessageName
}

func (s *FlavorSend) GetName() string {
	return s.Name
}

func (s *FlavorSend) GetSendCount() uint64 {
	return s.SendCount
}

func (s *FlavorSend) GetNotifyId() int64 {
	return s.notifyId
}
func (s *FlavorSend) UpdateAll(ctx context.Context) {
	if !s.sendrecv.isRemoteWanted(s.MessageName) {
		return
	}
	s.Mux.Lock()
	s.handler.GetAllLocked(ctx, func(obj *edgeproto.Flavor, modRev int64) {
		s.Keys[*obj.GetKey()] = FlavorSendContext{
			ctx:    ctx,
			modRev: modRev,
		}
	})
	s.Mux.Unlock()
}

func (s *FlavorSend) Update(ctx context.Context, obj *edgeproto.Flavor, modRev int64) {
	if !s.sendrecv.isRemoteWanted(s.MessageName) {
		return
	}
	forceDelete := false
	s.updateInternal(ctx, obj.GetKey(), modRev, forceDelete)
}

func (s *FlavorSend) ForceDelete(ctx context.Context, key *edgeproto.FlavorKey, modRev int64) {
	forceDelete := true
	s.updateInternal(ctx, key, modRev, forceDelete)
}

func (s *FlavorSend) updateInternal(ctx context.Context, key *edgeproto.FlavorKey, modRev int64, forceDelete bool) {
	s.Mux.Lock()
	log.SpanLog(ctx, log.DebugLevelNotify, "updateInternal Flavor", "key", key, "modRev", modRev)
	s.Keys[*key] = FlavorSendContext{
		ctx:         ctx,
		modRev:      modRev,
		forceDelete: forceDelete,
	}
	s.Mux.Unlock()
	s.sendrecv.wakeup()
}

func (s *FlavorSend) SendForCloudlet(ctx context.Context, action edgeproto.NoticeAction, cloudlet *edgeproto.Cloudlet) {
}

func (s *FlavorSend) Send(stream StreamNotify, notice *edgeproto.Notice, peer string) error {
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
			fmt.Sprintf("%s send Flavor", s.sendrecv.cliserv),
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

func (s *FlavorSend) PrepData() bool {
	s.Mux.Lock()
	defer s.Mux.Unlock()
	if len(s.Keys) > 0 {
		s.keysToSend = s.Keys
		s.Keys = make(map[edgeproto.FlavorKey]FlavorSendContext)
		return true
	}
	return false
}

// Server accepts multiple clients so needs to track multiple
// peers to send to.
type FlavorSendMany struct {
	handler SendFlavorHandler
	Mux     sync.Mutex
	sends   map[string]*FlavorSend
}

func NewFlavorSendMany(handler SendFlavorHandler) *FlavorSendMany {
	s := &FlavorSendMany{}
	s.handler = handler
	s.sends = make(map[string]*FlavorSend)
	return s
}

func (s *FlavorSendMany) NewSend(peerAddr string, notifyId int64) NotifySend {
	send := NewFlavorSend(s.handler)
	send.notifyId = notifyId
	s.Mux.Lock()
	s.sends[peerAddr] = send
	s.Mux.Unlock()
	return send
}

func (s *FlavorSendMany) DoneSend(peerAddr string, send NotifySend) {
	asend, ok := send.(*FlavorSend)
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
func (s *FlavorSendMany) Update(ctx context.Context, obj *edgeproto.Flavor, modRev int64) {
	s.Mux.Lock()
	defer s.Mux.Unlock()
	for _, send := range s.sends {
		send.Update(ctx, obj, modRev)
	}
}

func (s *FlavorSendMany) GetTypeString() string {
	return "Flavor"
}

type FlavorRecv struct {
	Name        string
	MessageName string
	handler     RecvFlavorHandler
	sendAllKeys map[edgeproto.FlavorKey]struct{}
	Mux         sync.Mutex
	buf         edgeproto.Flavor
	RecvCount   uint64
	sendrecv    *SendRecv
}

func NewFlavorRecv(handler RecvFlavorHandler) *FlavorRecv {
	recv := &FlavorRecv{}
	recv.Name = "Flavor"
	recv.MessageName = proto.MessageName((*edgeproto.Flavor)(nil))
	recv.handler = handler
	return recv
}

func (s *FlavorRecv) SetSendRecv(sendrecv *SendRecv) {
	s.sendrecv = sendrecv
}

func (s *FlavorRecv) GetMessageName() string {
	return s.MessageName
}

func (s *FlavorRecv) GetName() string {
	return s.Name
}

func (s *FlavorRecv) GetRecvCount() uint64 {
	return s.RecvCount
}

func (s *FlavorRecv) Recv(ctx context.Context, notice *edgeproto.Notice, notifyId int64, peerAddr string) {
	span := opentracing.SpanFromContext(ctx)
	if span != nil {
		span.SetTag("objtype", "Flavor")
	}

	buf := &edgeproto.Flavor{}
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
		fmt.Sprintf("%s recv Flavor", s.sendrecv.cliserv),
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

func (s *FlavorRecv) RecvAllStart() {
	s.Mux.Lock()
	defer s.Mux.Unlock()
	s.sendAllKeys = make(map[edgeproto.FlavorKey]struct{})
}

func (s *FlavorRecv) RecvAllEnd(ctx context.Context, cleanup Cleanup) {
	s.Mux.Lock()
	validKeys := s.sendAllKeys
	s.sendAllKeys = nil
	s.Mux.Unlock()
	if cleanup == CleanupPrune {
		s.handler.Prune(ctx, validKeys)
	}
}
func (s *FlavorRecv) Flush(ctx context.Context, notifyId int64) {
	s.handler.Flush(ctx, notifyId)
}

type FlavorRecvMany struct {
	handler RecvFlavorHandler
}

func NewFlavorRecvMany(handler RecvFlavorHandler) *FlavorRecvMany {
	s := &FlavorRecvMany{}
	s.handler = handler
	return s
}

func (s *FlavorRecvMany) NewRecv() NotifyRecv {
	recv := NewFlavorRecv(s.handler)
	return recv
}

func (s *FlavorRecvMany) Flush(ctx context.Context, notifyId int64) {
	s.handler.Flush(ctx, notifyId)
}
func (mgr *ServerMgr) RegisterSendFlavorCache(cache FlavorCacheHandler) {
	send := NewFlavorSendMany(cache)
	mgr.RegisterSend(send)
	cache.AddNotifyCb(send.Update)
}

func (mgr *ServerMgr) RegisterRecvFlavorCache(cache FlavorCacheHandler) {
	recv := NewFlavorRecvMany(cache)
	mgr.RegisterRecv(recv)
}

func (s *Client) RegisterSendFlavorCache(cache FlavorCacheHandler) {
	send := NewFlavorSend(cache)
	s.RegisterSend(send)
	cache.AddNotifyCb(send.Update)
}

func (s *Client) RegisterRecvFlavorCache(cache FlavorCacheHandler) {
	recv := NewFlavorRecv(cache)
	s.RegisterRecv(recv)
}
