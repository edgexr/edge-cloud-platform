// Code generated by protoc-gen-gogo. DO NOT EDIT.
// source: trustpolicy.proto

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

type SendTrustPolicyHandler interface {
	GetAllLocked(ctx context.Context, cb func(key *edgeproto.TrustPolicy, modRev int64))
	GetWithRev(key *edgeproto.PolicyKey, buf *edgeproto.TrustPolicy, modRev *int64) bool
}

type RecvTrustPolicyHandler interface {
	Update(ctx context.Context, in *edgeproto.TrustPolicy, rev int64)
	Delete(ctx context.Context, in *edgeproto.TrustPolicy, rev int64)
	Prune(ctx context.Context, keys map[edgeproto.PolicyKey]struct{})
	Flush(ctx context.Context, notifyId int64)
}

type TrustPolicyCacheHandler interface {
	SendTrustPolicyHandler
	RecvTrustPolicyHandler
	AddNotifyCb(fn func(ctx context.Context, obj *edgeproto.TrustPolicy, modRev int64))
}

type TrustPolicySend struct {
	Name        string
	MessageName string
	handler     SendTrustPolicyHandler
	Keys        map[edgeproto.PolicyKey]TrustPolicySendContext
	keysToSend  map[edgeproto.PolicyKey]TrustPolicySendContext
	notifyId    int64
	Mux         sync.Mutex
	buf         edgeproto.TrustPolicy
	SendCount   uint64
	sendrecv    *SendRecv
}

type TrustPolicySendContext struct {
	ctx         context.Context
	modRev      int64
	forceDelete bool
}

func NewTrustPolicySend(handler SendTrustPolicyHandler) *TrustPolicySend {
	send := &TrustPolicySend{}
	send.Name = "TrustPolicy"
	send.MessageName = proto.MessageName((*edgeproto.TrustPolicy)(nil))
	send.handler = handler
	send.Keys = make(map[edgeproto.PolicyKey]TrustPolicySendContext)
	return send
}

func (s *TrustPolicySend) SetSendRecv(sendrecv *SendRecv) {
	s.sendrecv = sendrecv
}

func (s *TrustPolicySend) GetMessageName() string {
	return s.MessageName
}

func (s *TrustPolicySend) GetName() string {
	return s.Name
}

func (s *TrustPolicySend) GetSendCount() uint64 {
	return s.SendCount
}

func (s *TrustPolicySend) GetNotifyId() int64 {
	return s.notifyId
}
func (s *TrustPolicySend) UpdateAll(ctx context.Context) {
	if !s.sendrecv.isRemoteWanted(s.MessageName) {
		return
	}
	s.Mux.Lock()
	s.handler.GetAllLocked(ctx, func(obj *edgeproto.TrustPolicy, modRev int64) {
		s.Keys[*obj.GetKey()] = TrustPolicySendContext{
			ctx:    ctx,
			modRev: modRev,
		}
	})
	s.Mux.Unlock()
}

func (s *TrustPolicySend) Update(ctx context.Context, obj *edgeproto.TrustPolicy, modRev int64) {
	if !s.sendrecv.isRemoteWanted(s.MessageName) {
		return
	}
	forceDelete := false
	s.updateInternal(ctx, obj.GetKey(), modRev, forceDelete)
}

func (s *TrustPolicySend) ForceDelete(ctx context.Context, key *edgeproto.PolicyKey, modRev int64) {
	forceDelete := true
	s.updateInternal(ctx, key, modRev, forceDelete)
}

func (s *TrustPolicySend) updateInternal(ctx context.Context, key *edgeproto.PolicyKey, modRev int64, forceDelete bool) {
	s.Mux.Lock()
	log.SpanLog(ctx, log.DebugLevelNotify, "updateInternal TrustPolicy", "key", key, "modRev", modRev)
	s.Keys[*key] = TrustPolicySendContext{
		ctx:         ctx,
		modRev:      modRev,
		forceDelete: forceDelete,
	}
	s.Mux.Unlock()
	s.sendrecv.wakeup()
}

func (s *TrustPolicySend) SendForCloudlet(ctx context.Context, action edgeproto.NoticeAction, cloudlet *edgeproto.Cloudlet) {
}

func (s *TrustPolicySend) Send(stream StreamNotify, notice *edgeproto.Notice, peer string) error {
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
			fmt.Sprintf("%s send TrustPolicy", s.sendrecv.cliserv),
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

func (s *TrustPolicySend) PrepData() bool {
	s.Mux.Lock()
	defer s.Mux.Unlock()
	if len(s.Keys) > 0 {
		s.keysToSend = s.Keys
		s.Keys = make(map[edgeproto.PolicyKey]TrustPolicySendContext)
		return true
	}
	return false
}

// Server accepts multiple clients so needs to track multiple
// peers to send to.
type TrustPolicySendMany struct {
	handler SendTrustPolicyHandler
	Mux     sync.Mutex
	sends   map[string]*TrustPolicySend
}

func NewTrustPolicySendMany(handler SendTrustPolicyHandler) *TrustPolicySendMany {
	s := &TrustPolicySendMany{}
	s.handler = handler
	s.sends = make(map[string]*TrustPolicySend)
	return s
}

func (s *TrustPolicySendMany) NewSend(peerAddr string, notifyId int64) NotifySend {
	send := NewTrustPolicySend(s.handler)
	send.notifyId = notifyId
	s.Mux.Lock()
	s.sends[peerAddr] = send
	s.Mux.Unlock()
	return send
}

func (s *TrustPolicySendMany) DoneSend(peerAddr string, send NotifySend) {
	asend, ok := send.(*TrustPolicySend)
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
func (s *TrustPolicySendMany) Update(ctx context.Context, obj *edgeproto.TrustPolicy, modRev int64) {
	s.Mux.Lock()
	defer s.Mux.Unlock()
	for _, send := range s.sends {
		send.Update(ctx, obj, modRev)
	}
}

func (s *TrustPolicySendMany) GetTypeString() string {
	return "TrustPolicy"
}

type TrustPolicyRecv struct {
	Name        string
	MessageName string
	handler     RecvTrustPolicyHandler
	sendAllKeys map[edgeproto.PolicyKey]struct{}
	Mux         sync.Mutex
	buf         edgeproto.TrustPolicy
	RecvCount   uint64
	sendrecv    *SendRecv
}

func NewTrustPolicyRecv(handler RecvTrustPolicyHandler) *TrustPolicyRecv {
	recv := &TrustPolicyRecv{}
	recv.Name = "TrustPolicy"
	recv.MessageName = proto.MessageName((*edgeproto.TrustPolicy)(nil))
	recv.handler = handler
	return recv
}

func (s *TrustPolicyRecv) SetSendRecv(sendrecv *SendRecv) {
	s.sendrecv = sendrecv
}

func (s *TrustPolicyRecv) GetMessageName() string {
	return s.MessageName
}

func (s *TrustPolicyRecv) GetName() string {
	return s.Name
}

func (s *TrustPolicyRecv) GetRecvCount() uint64 {
	return s.RecvCount
}

func (s *TrustPolicyRecv) Recv(ctx context.Context, notice *edgeproto.Notice, notifyId int64, peerAddr string) {
	span := opentracing.SpanFromContext(ctx)
	if span != nil {
		span.SetTag("objtype", "TrustPolicy")
	}

	buf := &edgeproto.TrustPolicy{}
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
		fmt.Sprintf("%s recv TrustPolicy", s.sendrecv.cliserv),
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

func (s *TrustPolicyRecv) RecvAllStart() {
	s.Mux.Lock()
	defer s.Mux.Unlock()
	s.sendAllKeys = make(map[edgeproto.PolicyKey]struct{})
}

func (s *TrustPolicyRecv) RecvAllEnd(ctx context.Context, cleanup Cleanup) {
	s.Mux.Lock()
	validKeys := s.sendAllKeys
	s.sendAllKeys = nil
	s.Mux.Unlock()
	if cleanup == CleanupPrune {
		s.handler.Prune(ctx, validKeys)
	}
}
func (s *TrustPolicyRecv) Flush(ctx context.Context, notifyId int64) {
	s.handler.Flush(ctx, notifyId)
}

type TrustPolicyRecvMany struct {
	handler RecvTrustPolicyHandler
}

func NewTrustPolicyRecvMany(handler RecvTrustPolicyHandler) *TrustPolicyRecvMany {
	s := &TrustPolicyRecvMany{}
	s.handler = handler
	return s
}

func (s *TrustPolicyRecvMany) NewRecv() NotifyRecv {
	recv := NewTrustPolicyRecv(s.handler)
	return recv
}

func (s *TrustPolicyRecvMany) Flush(ctx context.Context, notifyId int64) {
	s.handler.Flush(ctx, notifyId)
}
func (mgr *ServerMgr) RegisterSendTrustPolicyCache(cache TrustPolicyCacheHandler) {
	send := NewTrustPolicySendMany(cache)
	mgr.RegisterSend(send)
	cache.AddNotifyCb(send.Update)
}

func (mgr *ServerMgr) RegisterRecvTrustPolicyCache(cache TrustPolicyCacheHandler) {
	recv := NewTrustPolicyRecvMany(cache)
	mgr.RegisterRecv(recv)
}

func (s *Client) RegisterSendTrustPolicyCache(cache TrustPolicyCacheHandler) {
	send := NewTrustPolicySend(cache)
	s.RegisterSend(send)
	cache.AddNotifyCb(send.Update)
}

func (s *Client) RegisterRecvTrustPolicyCache(cache TrustPolicyCacheHandler) {
	recv := NewTrustPolicyRecv(cache)
	s.RegisterRecv(recv)
}
