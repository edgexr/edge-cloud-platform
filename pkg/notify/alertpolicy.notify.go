// Code generated by protoc-gen-gogo. DO NOT EDIT.
// source: alertpolicy.proto

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

type SendAlertPolicyHandler interface {
	GetAllKeys(ctx context.Context, cb func(key *edgeproto.AlertPolicyKey, modRev int64))
	GetWithRev(key *edgeproto.AlertPolicyKey, buf *edgeproto.AlertPolicy, modRev *int64) bool
}

type RecvAlertPolicyHandler interface {
	Update(ctx context.Context, in *edgeproto.AlertPolicy, rev int64)
	Delete(ctx context.Context, in *edgeproto.AlertPolicy, rev int64)
	Prune(ctx context.Context, keys map[edgeproto.AlertPolicyKey]struct{})
	Flush(ctx context.Context, notifyId int64)
}

type AlertPolicyCacheHandler interface {
	SendAlertPolicyHandler
	RecvAlertPolicyHandler
	AddNotifyCb(fn func(ctx context.Context, obj *edgeproto.AlertPolicyKey, old *edgeproto.AlertPolicy, modRev int64))
}

type AlertPolicySend struct {
	Name        string
	MessageName string
	handler     SendAlertPolicyHandler
	Keys        map[edgeproto.AlertPolicyKey]AlertPolicySendContext
	keysToSend  map[edgeproto.AlertPolicyKey]AlertPolicySendContext
	notifyId    int64
	Mux         sync.Mutex
	buf         edgeproto.AlertPolicy
	SendCount   uint64
	sendrecv    *SendRecv
}

type AlertPolicySendContext struct {
	ctx         context.Context
	modRev      int64
	forceDelete bool
}

func NewAlertPolicySend(handler SendAlertPolicyHandler) *AlertPolicySend {
	send := &AlertPolicySend{}
	send.Name = "AlertPolicy"
	send.MessageName = proto.MessageName((*edgeproto.AlertPolicy)(nil))
	send.handler = handler
	send.Keys = make(map[edgeproto.AlertPolicyKey]AlertPolicySendContext)
	return send
}

func (s *AlertPolicySend) SetSendRecv(sendrecv *SendRecv) {
	s.sendrecv = sendrecv
}

func (s *AlertPolicySend) GetMessageName() string {
	return s.MessageName
}

func (s *AlertPolicySend) GetName() string {
	return s.Name
}

func (s *AlertPolicySend) GetSendCount() uint64 {
	return s.SendCount
}

func (s *AlertPolicySend) GetNotifyId() int64 {
	return s.notifyId
}
func (s *AlertPolicySend) UpdateAll(ctx context.Context) {
	if !s.sendrecv.isRemoteWanted(s.MessageName) {
		return
	}
	s.Mux.Lock()
	s.handler.GetAllKeys(ctx, func(key *edgeproto.AlertPolicyKey, modRev int64) {
		s.Keys[*key] = AlertPolicySendContext{
			ctx:    ctx,
			modRev: modRev,
		}
	})
	s.Mux.Unlock()
}

func (s *AlertPolicySend) Update(ctx context.Context, key *edgeproto.AlertPolicyKey, old *edgeproto.AlertPolicy, modRev int64) {
	if !s.sendrecv.isRemoteWanted(s.MessageName) {
		return
	}
	forceDelete := false
	s.updateInternal(ctx, key, modRev, forceDelete)
}

func (s *AlertPolicySend) ForceDelete(ctx context.Context, key *edgeproto.AlertPolicyKey, modRev int64) {
	forceDelete := true
	s.updateInternal(ctx, key, modRev, forceDelete)
}

func (s *AlertPolicySend) updateInternal(ctx context.Context, key *edgeproto.AlertPolicyKey, modRev int64, forceDelete bool) {
	s.Mux.Lock()
	log.SpanLog(ctx, log.DebugLevelNotify, "updateInternal AlertPolicy", "key", key, "modRev", modRev)
	s.Keys[*key] = AlertPolicySendContext{
		ctx:         ctx,
		modRev:      modRev,
		forceDelete: forceDelete,
	}
	s.Mux.Unlock()
	s.sendrecv.wakeup()
}

func (s *AlertPolicySend) SendForCloudlet(ctx context.Context, action edgeproto.NoticeAction, cloudlet *edgeproto.Cloudlet) {
}

func (s *AlertPolicySend) Send(stream StreamNotify, notice *edgeproto.Notice, peer string) error {
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
			fmt.Sprintf("%s send AlertPolicy", s.sendrecv.cliserv),
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

func (s *AlertPolicySend) PrepData() bool {
	s.Mux.Lock()
	defer s.Mux.Unlock()
	if len(s.Keys) > 0 {
		s.keysToSend = s.Keys
		s.Keys = make(map[edgeproto.AlertPolicyKey]AlertPolicySendContext)
		return true
	}
	return false
}

// Server accepts multiple clients so needs to track multiple
// peers to send to.
type AlertPolicySendMany struct {
	handler SendAlertPolicyHandler
	Mux     sync.Mutex
	sends   map[string]*AlertPolicySend
}

func NewAlertPolicySendMany(handler SendAlertPolicyHandler) *AlertPolicySendMany {
	s := &AlertPolicySendMany{}
	s.handler = handler
	s.sends = make(map[string]*AlertPolicySend)
	return s
}

func (s *AlertPolicySendMany) NewSend(peerAddr string, notifyId int64) NotifySend {
	send := NewAlertPolicySend(s.handler)
	send.notifyId = notifyId
	s.Mux.Lock()
	s.sends[peerAddr] = send
	s.Mux.Unlock()
	return send
}

func (s *AlertPolicySendMany) DoneSend(peerAddr string, send NotifySend) {
	asend, ok := send.(*AlertPolicySend)
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
func (s *AlertPolicySendMany) Update(ctx context.Context, key *edgeproto.AlertPolicyKey, old *edgeproto.AlertPolicy, modRev int64) {
	s.Mux.Lock()
	defer s.Mux.Unlock()
	for _, send := range s.sends {
		send.Update(ctx, key, old, modRev)
	}
}

func (s *AlertPolicySendMany) GetTypeString() string {
	return "AlertPolicy"
}

type AlertPolicyRecv struct {
	Name        string
	MessageName string
	handler     RecvAlertPolicyHandler
	sendAllKeys map[edgeproto.AlertPolicyKey]struct{}
	Mux         sync.Mutex
	buf         edgeproto.AlertPolicy
	RecvCount   uint64
	sendrecv    *SendRecv
}

func NewAlertPolicyRecv(handler RecvAlertPolicyHandler) *AlertPolicyRecv {
	recv := &AlertPolicyRecv{}
	recv.Name = "AlertPolicy"
	recv.MessageName = proto.MessageName((*edgeproto.AlertPolicy)(nil))
	recv.handler = handler
	return recv
}

func (s *AlertPolicyRecv) SetSendRecv(sendrecv *SendRecv) {
	s.sendrecv = sendrecv
}

func (s *AlertPolicyRecv) GetMessageName() string {
	return s.MessageName
}

func (s *AlertPolicyRecv) GetName() string {
	return s.Name
}

func (s *AlertPolicyRecv) GetRecvCount() uint64 {
	return s.RecvCount
}

func (s *AlertPolicyRecv) Recv(ctx context.Context, notice *edgeproto.Notice, notifyId int64, peerAddr string) {
	span := opentracing.SpanFromContext(ctx)
	if span != nil {
		span.SetTag("objtype", "AlertPolicy")
	}

	buf := &edgeproto.AlertPolicy{}
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
		fmt.Sprintf("%s recv AlertPolicy", s.sendrecv.cliserv),
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

func (s *AlertPolicyRecv) RecvAllStart() {
	s.Mux.Lock()
	defer s.Mux.Unlock()
	s.sendAllKeys = make(map[edgeproto.AlertPolicyKey]struct{})
}

func (s *AlertPolicyRecv) RecvAllEnd(ctx context.Context, cleanup Cleanup) {
	s.Mux.Lock()
	validKeys := s.sendAllKeys
	s.sendAllKeys = nil
	s.Mux.Unlock()
	if cleanup == CleanupPrune {
		s.handler.Prune(ctx, validKeys)
	}
}
func (s *AlertPolicyRecv) Flush(ctx context.Context, notifyId int64) {
	s.handler.Flush(ctx, notifyId)
}

type AlertPolicyRecvMany struct {
	handler RecvAlertPolicyHandler
}

func NewAlertPolicyRecvMany(handler RecvAlertPolicyHandler) *AlertPolicyRecvMany {
	s := &AlertPolicyRecvMany{}
	s.handler = handler
	return s
}

func (s *AlertPolicyRecvMany) NewRecv() NotifyRecv {
	recv := NewAlertPolicyRecv(s.handler)
	return recv
}

func (s *AlertPolicyRecvMany) Flush(ctx context.Context, notifyId int64) {
	s.handler.Flush(ctx, notifyId)
}
func (mgr *ServerMgr) RegisterSendAlertPolicyCache(cache AlertPolicyCacheHandler) {
	send := NewAlertPolicySendMany(cache)
	mgr.RegisterSend(send)
	cache.AddNotifyCb(send.Update)
}

func (mgr *ServerMgr) RegisterRecvAlertPolicyCache(cache AlertPolicyCacheHandler) {
	recv := NewAlertPolicyRecvMany(cache)
	mgr.RegisterRecv(recv)
}

func (s *Client) RegisterSendAlertPolicyCache(cache AlertPolicyCacheHandler) {
	send := NewAlertPolicySend(cache)
	s.RegisterSend(send)
	cache.AddNotifyCb(send.Update)
}

func (s *Client) RegisterRecvAlertPolicyCache(cache AlertPolicyCacheHandler) {
	recv := NewAlertPolicyRecv(cache)
	s.RegisterRecv(recv)
}
