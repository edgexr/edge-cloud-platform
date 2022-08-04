// Code generated by protoc-gen-gogo. DO NOT EDIT.
// source: ratelimit.proto

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

type SendFlowRateLimitSettingsHandler interface {
	GetAllKeys(ctx context.Context, cb func(key *edgeproto.FlowRateLimitSettingsKey, modRev int64))
	GetWithRev(key *edgeproto.FlowRateLimitSettingsKey, buf *edgeproto.FlowRateLimitSettings, modRev *int64) bool
}

type RecvFlowRateLimitSettingsHandler interface {
	Update(ctx context.Context, in *edgeproto.FlowRateLimitSettings, rev int64)
	Delete(ctx context.Context, in *edgeproto.FlowRateLimitSettings, rev int64)
	Prune(ctx context.Context, keys map[edgeproto.FlowRateLimitSettingsKey]struct{})
	Flush(ctx context.Context, notifyId int64)
}

type FlowRateLimitSettingsCacheHandler interface {
	SendFlowRateLimitSettingsHandler
	RecvFlowRateLimitSettingsHandler
	AddNotifyCb(fn func(ctx context.Context, obj *edgeproto.FlowRateLimitSettingsKey, old *edgeproto.FlowRateLimitSettings, modRev int64))
}

type FlowRateLimitSettingsSend struct {
	Name        string
	MessageName string
	handler     SendFlowRateLimitSettingsHandler
	Keys        map[edgeproto.FlowRateLimitSettingsKey]FlowRateLimitSettingsSendContext
	keysToSend  map[edgeproto.FlowRateLimitSettingsKey]FlowRateLimitSettingsSendContext
	notifyId    int64
	Mux         sync.Mutex
	buf         edgeproto.FlowRateLimitSettings
	SendCount   uint64
	sendrecv    *SendRecv
}

type FlowRateLimitSettingsSendContext struct {
	ctx    context.Context
	modRev int64
}

func NewFlowRateLimitSettingsSend(handler SendFlowRateLimitSettingsHandler) *FlowRateLimitSettingsSend {
	send := &FlowRateLimitSettingsSend{}
	send.Name = "FlowRateLimitSettings"
	send.MessageName = proto.MessageName((*edgeproto.FlowRateLimitSettings)(nil))
	send.handler = handler
	send.Keys = make(map[edgeproto.FlowRateLimitSettingsKey]FlowRateLimitSettingsSendContext)
	return send
}

func (s *FlowRateLimitSettingsSend) SetSendRecv(sendrecv *SendRecv) {
	s.sendrecv = sendrecv
}

func (s *FlowRateLimitSettingsSend) GetMessageName() string {
	return s.MessageName
}

func (s *FlowRateLimitSettingsSend) GetName() string {
	return s.Name
}

func (s *FlowRateLimitSettingsSend) GetSendCount() uint64 {
	return s.SendCount
}

func (s *FlowRateLimitSettingsSend) GetNotifyId() int64 {
	return s.notifyId
}
func (s *FlowRateLimitSettingsSend) UpdateAll(ctx context.Context) {
	if !s.sendrecv.isRemoteWanted(s.MessageName) {
		return
	}
	s.Mux.Lock()
	s.handler.GetAllKeys(ctx, func(key *edgeproto.FlowRateLimitSettingsKey, modRev int64) {
		s.Keys[*key] = FlowRateLimitSettingsSendContext{
			ctx:    ctx,
			modRev: modRev,
		}
	})
	s.Mux.Unlock()
}

func (s *FlowRateLimitSettingsSend) Update(ctx context.Context, key *edgeproto.FlowRateLimitSettingsKey, old *edgeproto.FlowRateLimitSettings, modRev int64) {
	if !s.sendrecv.isRemoteWanted(s.MessageName) {
		return
	}
	s.updateInternal(ctx, key, modRev)
}

func (s *FlowRateLimitSettingsSend) updateInternal(ctx context.Context, key *edgeproto.FlowRateLimitSettingsKey, modRev int64) {
	s.Mux.Lock()
	log.SpanLog(ctx, log.DebugLevelNotify, "updateInternal FlowRateLimitSettings", "key", key, "modRev", modRev)
	s.Keys[*key] = FlowRateLimitSettingsSendContext{
		ctx:    ctx,
		modRev: modRev,
	}
	s.Mux.Unlock()
	s.sendrecv.wakeup()
}

func (s *FlowRateLimitSettingsSend) Send(stream StreamNotify, notice *edgeproto.Notice, peer string) error {
	s.Mux.Lock()
	keys := s.keysToSend
	s.keysToSend = nil
	s.Mux.Unlock()
	for key, sendContext := range keys {
		ctx := sendContext.ctx
		found := s.handler.GetWithRev(&key, &s.buf, &notice.ModRev)
		if found {
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
			fmt.Sprintf("%s send FlowRateLimitSettings", s.sendrecv.cliserv),
			"peerAddr", peer,
			"peer", s.sendrecv.peer,
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

func (s *FlowRateLimitSettingsSend) PrepData() bool {
	s.Mux.Lock()
	defer s.Mux.Unlock()
	if len(s.Keys) > 0 {
		s.keysToSend = s.Keys
		s.Keys = make(map[edgeproto.FlowRateLimitSettingsKey]FlowRateLimitSettingsSendContext)
		return true
	}
	return false
}

// Server accepts multiple clients so needs to track multiple
// peers to send to.
type FlowRateLimitSettingsSendMany struct {
	handler SendFlowRateLimitSettingsHandler
	Mux     sync.Mutex
	sends   map[string]*FlowRateLimitSettingsSend
}

func NewFlowRateLimitSettingsSendMany(handler SendFlowRateLimitSettingsHandler) *FlowRateLimitSettingsSendMany {
	s := &FlowRateLimitSettingsSendMany{}
	s.handler = handler
	s.sends = make(map[string]*FlowRateLimitSettingsSend)
	return s
}

func (s *FlowRateLimitSettingsSendMany) NewSend(peerAddr string, notifyId int64) NotifySend {
	send := NewFlowRateLimitSettingsSend(s.handler)
	send.notifyId = notifyId
	s.Mux.Lock()
	s.sends[peerAddr] = send
	s.Mux.Unlock()
	return send
}

func (s *FlowRateLimitSettingsSendMany) DoneSend(peerAddr string, send NotifySend) {
	asend, ok := send.(*FlowRateLimitSettingsSend)
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
func (s *FlowRateLimitSettingsSendMany) Update(ctx context.Context, key *edgeproto.FlowRateLimitSettingsKey, old *edgeproto.FlowRateLimitSettings, modRev int64) {
	s.Mux.Lock()
	defer s.Mux.Unlock()
	for _, send := range s.sends {
		send.Update(ctx, key, old, modRev)
	}
}

func (s *FlowRateLimitSettingsSendMany) GetTypeString() string {
	return "FlowRateLimitSettings"
}

type FlowRateLimitSettingsRecv struct {
	Name        string
	MessageName string
	handler     RecvFlowRateLimitSettingsHandler
	sendAllKeys map[edgeproto.FlowRateLimitSettingsKey]struct{}
	Mux         sync.Mutex
	buf         edgeproto.FlowRateLimitSettings
	RecvCount   uint64
	sendrecv    *SendRecv
}

func NewFlowRateLimitSettingsRecv(handler RecvFlowRateLimitSettingsHandler) *FlowRateLimitSettingsRecv {
	recv := &FlowRateLimitSettingsRecv{}
	recv.Name = "FlowRateLimitSettings"
	recv.MessageName = proto.MessageName((*edgeproto.FlowRateLimitSettings)(nil))
	recv.handler = handler
	return recv
}

func (s *FlowRateLimitSettingsRecv) SetSendRecv(sendrecv *SendRecv) {
	s.sendrecv = sendrecv
}

func (s *FlowRateLimitSettingsRecv) GetMessageName() string {
	return s.MessageName
}

func (s *FlowRateLimitSettingsRecv) GetName() string {
	return s.Name
}

func (s *FlowRateLimitSettingsRecv) GetRecvCount() uint64 {
	return s.RecvCount
}

func (s *FlowRateLimitSettingsRecv) Recv(ctx context.Context, notice *edgeproto.Notice, notifyId int64, peerAddr string) {
	span := opentracing.SpanFromContext(ctx)
	if span != nil {
		span.SetTag("objtype", "FlowRateLimitSettings")
	}

	buf := &edgeproto.FlowRateLimitSettings{}
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
		fmt.Sprintf("%s recv FlowRateLimitSettings", s.sendrecv.cliserv),
		"peerAddr", peerAddr,
		"peer", s.sendrecv.peer,
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

func (s *FlowRateLimitSettingsRecv) RecvAllStart() {
	s.Mux.Lock()
	defer s.Mux.Unlock()
	s.sendAllKeys = make(map[edgeproto.FlowRateLimitSettingsKey]struct{})
}

func (s *FlowRateLimitSettingsRecv) RecvAllEnd(ctx context.Context, cleanup Cleanup) {
	s.Mux.Lock()
	validKeys := s.sendAllKeys
	s.sendAllKeys = nil
	s.Mux.Unlock()
	if cleanup == CleanupPrune {
		s.handler.Prune(ctx, validKeys)
	}
}
func (s *FlowRateLimitSettingsRecv) Flush(ctx context.Context, notifyId int64) {
	s.handler.Flush(ctx, notifyId)
}

type FlowRateLimitSettingsRecvMany struct {
	handler RecvFlowRateLimitSettingsHandler
}

func NewFlowRateLimitSettingsRecvMany(handler RecvFlowRateLimitSettingsHandler) *FlowRateLimitSettingsRecvMany {
	s := &FlowRateLimitSettingsRecvMany{}
	s.handler = handler
	return s
}

func (s *FlowRateLimitSettingsRecvMany) NewRecv() NotifyRecv {
	recv := NewFlowRateLimitSettingsRecv(s.handler)
	return recv
}

func (s *FlowRateLimitSettingsRecvMany) Flush(ctx context.Context, notifyId int64) {
	s.handler.Flush(ctx, notifyId)
}
func (mgr *ServerMgr) RegisterSendFlowRateLimitSettingsCache(cache FlowRateLimitSettingsCacheHandler) {
	send := NewFlowRateLimitSettingsSendMany(cache)
	mgr.RegisterSend(send)
	cache.AddNotifyCb(send.Update)
}

func (mgr *ServerMgr) RegisterRecvFlowRateLimitSettingsCache(cache FlowRateLimitSettingsCacheHandler) {
	recv := NewFlowRateLimitSettingsRecvMany(cache)
	mgr.RegisterRecv(recv)
}

func (s *Client) RegisterSendFlowRateLimitSettingsCache(cache FlowRateLimitSettingsCacheHandler) {
	send := NewFlowRateLimitSettingsSend(cache)
	s.RegisterSend(send)
	cache.AddNotifyCb(send.Update)
}

func (s *Client) RegisterRecvFlowRateLimitSettingsCache(cache FlowRateLimitSettingsCacheHandler) {
	recv := NewFlowRateLimitSettingsRecv(cache)
	s.RegisterRecv(recv)
}

type SendMaxReqsRateLimitSettingsHandler interface {
	GetAllKeys(ctx context.Context, cb func(key *edgeproto.MaxReqsRateLimitSettingsKey, modRev int64))
	GetWithRev(key *edgeproto.MaxReqsRateLimitSettingsKey, buf *edgeproto.MaxReqsRateLimitSettings, modRev *int64) bool
}

type RecvMaxReqsRateLimitSettingsHandler interface {
	Update(ctx context.Context, in *edgeproto.MaxReqsRateLimitSettings, rev int64)
	Delete(ctx context.Context, in *edgeproto.MaxReqsRateLimitSettings, rev int64)
	Prune(ctx context.Context, keys map[edgeproto.MaxReqsRateLimitSettingsKey]struct{})
	Flush(ctx context.Context, notifyId int64)
}

type MaxReqsRateLimitSettingsCacheHandler interface {
	SendMaxReqsRateLimitSettingsHandler
	RecvMaxReqsRateLimitSettingsHandler
	AddNotifyCb(fn func(ctx context.Context, obj *edgeproto.MaxReqsRateLimitSettingsKey, old *edgeproto.MaxReqsRateLimitSettings, modRev int64))
}

type MaxReqsRateLimitSettingsSend struct {
	Name        string
	MessageName string
	handler     SendMaxReqsRateLimitSettingsHandler
	Keys        map[edgeproto.MaxReqsRateLimitSettingsKey]MaxReqsRateLimitSettingsSendContext
	keysToSend  map[edgeproto.MaxReqsRateLimitSettingsKey]MaxReqsRateLimitSettingsSendContext
	notifyId    int64
	Mux         sync.Mutex
	buf         edgeproto.MaxReqsRateLimitSettings
	SendCount   uint64
	sendrecv    *SendRecv
}

type MaxReqsRateLimitSettingsSendContext struct {
	ctx    context.Context
	modRev int64
}

func NewMaxReqsRateLimitSettingsSend(handler SendMaxReqsRateLimitSettingsHandler) *MaxReqsRateLimitSettingsSend {
	send := &MaxReqsRateLimitSettingsSend{}
	send.Name = "MaxReqsRateLimitSettings"
	send.MessageName = proto.MessageName((*edgeproto.MaxReqsRateLimitSettings)(nil))
	send.handler = handler
	send.Keys = make(map[edgeproto.MaxReqsRateLimitSettingsKey]MaxReqsRateLimitSettingsSendContext)
	return send
}

func (s *MaxReqsRateLimitSettingsSend) SetSendRecv(sendrecv *SendRecv) {
	s.sendrecv = sendrecv
}

func (s *MaxReqsRateLimitSettingsSend) GetMessageName() string {
	return s.MessageName
}

func (s *MaxReqsRateLimitSettingsSend) GetName() string {
	return s.Name
}

func (s *MaxReqsRateLimitSettingsSend) GetSendCount() uint64 {
	return s.SendCount
}

func (s *MaxReqsRateLimitSettingsSend) GetNotifyId() int64 {
	return s.notifyId
}
func (s *MaxReqsRateLimitSettingsSend) UpdateAll(ctx context.Context) {
	if !s.sendrecv.isRemoteWanted(s.MessageName) {
		return
	}
	s.Mux.Lock()
	s.handler.GetAllKeys(ctx, func(key *edgeproto.MaxReqsRateLimitSettingsKey, modRev int64) {
		s.Keys[*key] = MaxReqsRateLimitSettingsSendContext{
			ctx:    ctx,
			modRev: modRev,
		}
	})
	s.Mux.Unlock()
}

func (s *MaxReqsRateLimitSettingsSend) Update(ctx context.Context, key *edgeproto.MaxReqsRateLimitSettingsKey, old *edgeproto.MaxReqsRateLimitSettings, modRev int64) {
	if !s.sendrecv.isRemoteWanted(s.MessageName) {
		return
	}
	s.updateInternal(ctx, key, modRev)
}

func (s *MaxReqsRateLimitSettingsSend) updateInternal(ctx context.Context, key *edgeproto.MaxReqsRateLimitSettingsKey, modRev int64) {
	s.Mux.Lock()
	log.SpanLog(ctx, log.DebugLevelNotify, "updateInternal MaxReqsRateLimitSettings", "key", key, "modRev", modRev)
	s.Keys[*key] = MaxReqsRateLimitSettingsSendContext{
		ctx:    ctx,
		modRev: modRev,
	}
	s.Mux.Unlock()
	s.sendrecv.wakeup()
}

func (s *MaxReqsRateLimitSettingsSend) Send(stream StreamNotify, notice *edgeproto.Notice, peer string) error {
	s.Mux.Lock()
	keys := s.keysToSend
	s.keysToSend = nil
	s.Mux.Unlock()
	for key, sendContext := range keys {
		ctx := sendContext.ctx
		found := s.handler.GetWithRev(&key, &s.buf, &notice.ModRev)
		if found {
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
			fmt.Sprintf("%s send MaxReqsRateLimitSettings", s.sendrecv.cliserv),
			"peerAddr", peer,
			"peer", s.sendrecv.peer,
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

func (s *MaxReqsRateLimitSettingsSend) PrepData() bool {
	s.Mux.Lock()
	defer s.Mux.Unlock()
	if len(s.Keys) > 0 {
		s.keysToSend = s.Keys
		s.Keys = make(map[edgeproto.MaxReqsRateLimitSettingsKey]MaxReqsRateLimitSettingsSendContext)
		return true
	}
	return false
}

// Server accepts multiple clients so needs to track multiple
// peers to send to.
type MaxReqsRateLimitSettingsSendMany struct {
	handler SendMaxReqsRateLimitSettingsHandler
	Mux     sync.Mutex
	sends   map[string]*MaxReqsRateLimitSettingsSend
}

func NewMaxReqsRateLimitSettingsSendMany(handler SendMaxReqsRateLimitSettingsHandler) *MaxReqsRateLimitSettingsSendMany {
	s := &MaxReqsRateLimitSettingsSendMany{}
	s.handler = handler
	s.sends = make(map[string]*MaxReqsRateLimitSettingsSend)
	return s
}

func (s *MaxReqsRateLimitSettingsSendMany) NewSend(peerAddr string, notifyId int64) NotifySend {
	send := NewMaxReqsRateLimitSettingsSend(s.handler)
	send.notifyId = notifyId
	s.Mux.Lock()
	s.sends[peerAddr] = send
	s.Mux.Unlock()
	return send
}

func (s *MaxReqsRateLimitSettingsSendMany) DoneSend(peerAddr string, send NotifySend) {
	asend, ok := send.(*MaxReqsRateLimitSettingsSend)
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
func (s *MaxReqsRateLimitSettingsSendMany) Update(ctx context.Context, key *edgeproto.MaxReqsRateLimitSettingsKey, old *edgeproto.MaxReqsRateLimitSettings, modRev int64) {
	s.Mux.Lock()
	defer s.Mux.Unlock()
	for _, send := range s.sends {
		send.Update(ctx, key, old, modRev)
	}
}

func (s *MaxReqsRateLimitSettingsSendMany) GetTypeString() string {
	return "MaxReqsRateLimitSettings"
}

type MaxReqsRateLimitSettingsRecv struct {
	Name        string
	MessageName string
	handler     RecvMaxReqsRateLimitSettingsHandler
	sendAllKeys map[edgeproto.MaxReqsRateLimitSettingsKey]struct{}
	Mux         sync.Mutex
	buf         edgeproto.MaxReqsRateLimitSettings
	RecvCount   uint64
	sendrecv    *SendRecv
}

func NewMaxReqsRateLimitSettingsRecv(handler RecvMaxReqsRateLimitSettingsHandler) *MaxReqsRateLimitSettingsRecv {
	recv := &MaxReqsRateLimitSettingsRecv{}
	recv.Name = "MaxReqsRateLimitSettings"
	recv.MessageName = proto.MessageName((*edgeproto.MaxReqsRateLimitSettings)(nil))
	recv.handler = handler
	return recv
}

func (s *MaxReqsRateLimitSettingsRecv) SetSendRecv(sendrecv *SendRecv) {
	s.sendrecv = sendrecv
}

func (s *MaxReqsRateLimitSettingsRecv) GetMessageName() string {
	return s.MessageName
}

func (s *MaxReqsRateLimitSettingsRecv) GetName() string {
	return s.Name
}

func (s *MaxReqsRateLimitSettingsRecv) GetRecvCount() uint64 {
	return s.RecvCount
}

func (s *MaxReqsRateLimitSettingsRecv) Recv(ctx context.Context, notice *edgeproto.Notice, notifyId int64, peerAddr string) {
	span := opentracing.SpanFromContext(ctx)
	if span != nil {
		span.SetTag("objtype", "MaxReqsRateLimitSettings")
	}

	buf := &edgeproto.MaxReqsRateLimitSettings{}
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
		fmt.Sprintf("%s recv MaxReqsRateLimitSettings", s.sendrecv.cliserv),
		"peerAddr", peerAddr,
		"peer", s.sendrecv.peer,
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

func (s *MaxReqsRateLimitSettingsRecv) RecvAllStart() {
	s.Mux.Lock()
	defer s.Mux.Unlock()
	s.sendAllKeys = make(map[edgeproto.MaxReqsRateLimitSettingsKey]struct{})
}

func (s *MaxReqsRateLimitSettingsRecv) RecvAllEnd(ctx context.Context, cleanup Cleanup) {
	s.Mux.Lock()
	validKeys := s.sendAllKeys
	s.sendAllKeys = nil
	s.Mux.Unlock()
	if cleanup == CleanupPrune {
		s.handler.Prune(ctx, validKeys)
	}
}
func (s *MaxReqsRateLimitSettingsRecv) Flush(ctx context.Context, notifyId int64) {
	s.handler.Flush(ctx, notifyId)
}

type MaxReqsRateLimitSettingsRecvMany struct {
	handler RecvMaxReqsRateLimitSettingsHandler
}

func NewMaxReqsRateLimitSettingsRecvMany(handler RecvMaxReqsRateLimitSettingsHandler) *MaxReqsRateLimitSettingsRecvMany {
	s := &MaxReqsRateLimitSettingsRecvMany{}
	s.handler = handler
	return s
}

func (s *MaxReqsRateLimitSettingsRecvMany) NewRecv() NotifyRecv {
	recv := NewMaxReqsRateLimitSettingsRecv(s.handler)
	return recv
}

func (s *MaxReqsRateLimitSettingsRecvMany) Flush(ctx context.Context, notifyId int64) {
	s.handler.Flush(ctx, notifyId)
}
func (mgr *ServerMgr) RegisterSendMaxReqsRateLimitSettingsCache(cache MaxReqsRateLimitSettingsCacheHandler) {
	send := NewMaxReqsRateLimitSettingsSendMany(cache)
	mgr.RegisterSend(send)
	cache.AddNotifyCb(send.Update)
}

func (mgr *ServerMgr) RegisterRecvMaxReqsRateLimitSettingsCache(cache MaxReqsRateLimitSettingsCacheHandler) {
	recv := NewMaxReqsRateLimitSettingsRecvMany(cache)
	mgr.RegisterRecv(recv)
}

func (s *Client) RegisterSendMaxReqsRateLimitSettingsCache(cache MaxReqsRateLimitSettingsCacheHandler) {
	send := NewMaxReqsRateLimitSettingsSend(cache)
	s.RegisterSend(send)
	cache.AddNotifyCb(send.Update)
}

func (s *Client) RegisterRecvMaxReqsRateLimitSettingsCache(cache MaxReqsRateLimitSettingsCacheHandler) {
	recv := NewMaxReqsRateLimitSettingsRecv(cache)
	s.RegisterRecv(recv)
}
