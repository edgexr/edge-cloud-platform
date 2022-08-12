// Code generated by protoc-gen-gogo. DO NOT EDIT.
// source: trustpolicyexception.proto

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

type SendTrustPolicyExceptionHandler interface {
	GetAllKeys(ctx context.Context, cb func(key *edgeproto.TrustPolicyExceptionKey, modRev int64))
	GetWithRev(key *edgeproto.TrustPolicyExceptionKey, buf *edgeproto.TrustPolicyException, modRev *int64) bool
	GetForCloudlet(cloudlet *edgeproto.Cloudlet, cb func(key *edgeproto.TrustPolicyExceptionKey, modRev int64))
}

type RecvTrustPolicyExceptionHandler interface {
	Update(ctx context.Context, in *edgeproto.TrustPolicyException, rev int64)
	Delete(ctx context.Context, in *edgeproto.TrustPolicyException, rev int64)
	Prune(ctx context.Context, keys map[edgeproto.TrustPolicyExceptionKey]struct{})
	Flush(ctx context.Context, notifyId int64)
}

type TrustPolicyExceptionCacheHandler interface {
	SendTrustPolicyExceptionHandler
	RecvTrustPolicyExceptionHandler
	AddNotifyCb(fn func(ctx context.Context, obj *edgeproto.TrustPolicyExceptionKey, old *edgeproto.TrustPolicyException, modRev int64))
}

type TrustPolicyExceptionSend struct {
	Name        string
	MessageName string
	handler     SendTrustPolicyExceptionHandler
	Keys        map[edgeproto.TrustPolicyExceptionKey]TrustPolicyExceptionSendContext
	keysToSend  map[edgeproto.TrustPolicyExceptionKey]TrustPolicyExceptionSendContext
	notifyId    int64
	Mux         sync.Mutex
	buf         edgeproto.TrustPolicyException
	SendCount   uint64
	sendrecv    *SendRecv
}

type TrustPolicyExceptionSendContext struct {
	ctx         context.Context
	modRev      int64
	forceDelete bool
}

func NewTrustPolicyExceptionSend(handler SendTrustPolicyExceptionHandler) *TrustPolicyExceptionSend {
	send := &TrustPolicyExceptionSend{}
	send.Name = "TrustPolicyException"
	send.MessageName = proto.MessageName((*edgeproto.TrustPolicyException)(nil))
	send.handler = handler
	send.Keys = make(map[edgeproto.TrustPolicyExceptionKey]TrustPolicyExceptionSendContext)
	return send
}

func (s *TrustPolicyExceptionSend) SetSendRecv(sendrecv *SendRecv) {
	s.sendrecv = sendrecv
}

func (s *TrustPolicyExceptionSend) GetMessageName() string {
	return s.MessageName
}

func (s *TrustPolicyExceptionSend) GetName() string {
	return s.Name
}

func (s *TrustPolicyExceptionSend) GetSendCount() uint64 {
	return s.SendCount
}

func (s *TrustPolicyExceptionSend) GetNotifyId() int64 {
	return s.notifyId
}
func (s *TrustPolicyExceptionSend) UpdateAll(ctx context.Context) {
	if !s.sendrecv.isRemoteWanted(s.MessageName) {
		return
	}
	if !s.UpdateAllOk() { // to be implemented by hand
		return
	}
	s.Mux.Lock()
	s.handler.GetAllKeys(ctx, func(key *edgeproto.TrustPolicyExceptionKey, modRev int64) {
		s.Keys[*key] = TrustPolicyExceptionSendContext{
			ctx:    ctx,
			modRev: modRev,
		}
	})
	s.Mux.Unlock()
}

func (s *TrustPolicyExceptionSend) Update(ctx context.Context, key *edgeproto.TrustPolicyExceptionKey, old *edgeproto.TrustPolicyException, modRev int64) {
	if !s.sendrecv.isRemoteWanted(s.MessageName) {
		return
	}
	if !s.UpdateOk(ctx, key) { // to be implemented by hand
		return
	}
	forceDelete := false
	s.updateInternal(ctx, key, modRev, forceDelete)
}

func (s *TrustPolicyExceptionSend) ForceDelete(ctx context.Context, key *edgeproto.TrustPolicyExceptionKey, modRev int64) {
	forceDelete := true
	s.updateInternal(ctx, key, modRev, forceDelete)
}

func (s *TrustPolicyExceptionSend) updateInternal(ctx context.Context, key *edgeproto.TrustPolicyExceptionKey, modRev int64, forceDelete bool) {
	s.Mux.Lock()
	log.SpanLog(ctx, log.DebugLevelNotify, "updateInternal TrustPolicyException", "key", key, "modRev", modRev)
	s.Keys[*key] = TrustPolicyExceptionSendContext{
		ctx:         ctx,
		modRev:      modRev,
		forceDelete: forceDelete,
	}
	s.Mux.Unlock()
	s.sendrecv.wakeup()
}

func (s *TrustPolicyExceptionSend) SendForCloudlet(ctx context.Context, action edgeproto.NoticeAction, cloudlet *edgeproto.Cloudlet) {
	keys := make(map[edgeproto.TrustPolicyExceptionKey]int64)
	s.handler.GetForCloudlet(cloudlet, func(objKey *edgeproto.TrustPolicyExceptionKey, modRev int64) {
		keys[*objKey] = modRev
	})
	for k, modRev := range keys {
		if action == edgeproto.NoticeAction_UPDATE {
			s.Update(ctx, &k, nil, modRev)
		} else if action == edgeproto.NoticeAction_DELETE {
			s.ForceDelete(ctx, &k, modRev)
		}
	}
}

func (s *TrustPolicyExceptionSend) Send(stream StreamNotify, notice *edgeproto.Notice, peer string) error {
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
			fmt.Sprintf("%s send TrustPolicyException", s.sendrecv.cliserv),
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

func (s *TrustPolicyExceptionSend) PrepData() bool {
	s.Mux.Lock()
	defer s.Mux.Unlock()
	if len(s.Keys) > 0 {
		s.keysToSend = s.Keys
		s.Keys = make(map[edgeproto.TrustPolicyExceptionKey]TrustPolicyExceptionSendContext)
		return true
	}
	return false
}

// Server accepts multiple clients so needs to track multiple
// peers to send to.
type TrustPolicyExceptionSendMany struct {
	handler SendTrustPolicyExceptionHandler
	Mux     sync.Mutex
	sends   map[string]*TrustPolicyExceptionSend
}

func NewTrustPolicyExceptionSendMany(handler SendTrustPolicyExceptionHandler) *TrustPolicyExceptionSendMany {
	s := &TrustPolicyExceptionSendMany{}
	s.handler = handler
	s.sends = make(map[string]*TrustPolicyExceptionSend)
	return s
}

func (s *TrustPolicyExceptionSendMany) NewSend(peerAddr string, notifyId int64) NotifySend {
	send := NewTrustPolicyExceptionSend(s.handler)
	send.notifyId = notifyId
	s.Mux.Lock()
	s.sends[peerAddr] = send
	s.Mux.Unlock()
	return send
}

func (s *TrustPolicyExceptionSendMany) DoneSend(peerAddr string, send NotifySend) {
	asend, ok := send.(*TrustPolicyExceptionSend)
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
func (s *TrustPolicyExceptionSendMany) Update(ctx context.Context, key *edgeproto.TrustPolicyExceptionKey, old *edgeproto.TrustPolicyException, modRev int64) {
	s.Mux.Lock()
	defer s.Mux.Unlock()
	for _, send := range s.sends {
		send.Update(ctx, key, old, modRev)
	}
}

func (s *TrustPolicyExceptionSendMany) GetTypeString() string {
	return "TrustPolicyException"
}

type TrustPolicyExceptionRecv struct {
	Name        string
	MessageName string
	handler     RecvTrustPolicyExceptionHandler
	sendAllKeys map[edgeproto.TrustPolicyExceptionKey]struct{}
	Mux         sync.Mutex
	buf         edgeproto.TrustPolicyException
	RecvCount   uint64
	sendrecv    *SendRecv
}

func NewTrustPolicyExceptionRecv(handler RecvTrustPolicyExceptionHandler) *TrustPolicyExceptionRecv {
	recv := &TrustPolicyExceptionRecv{}
	recv.Name = "TrustPolicyException"
	recv.MessageName = proto.MessageName((*edgeproto.TrustPolicyException)(nil))
	recv.handler = handler
	return recv
}

func (s *TrustPolicyExceptionRecv) SetSendRecv(sendrecv *SendRecv) {
	s.sendrecv = sendrecv
}

func (s *TrustPolicyExceptionRecv) GetMessageName() string {
	return s.MessageName
}

func (s *TrustPolicyExceptionRecv) GetName() string {
	return s.Name
}

func (s *TrustPolicyExceptionRecv) GetRecvCount() uint64 {
	return s.RecvCount
}

func (s *TrustPolicyExceptionRecv) Recv(ctx context.Context, notice *edgeproto.Notice, notifyId int64, peerAddr string) {
	span := opentracing.SpanFromContext(ctx)
	if span != nil {
		span.SetTag("objtype", "TrustPolicyException")
	}

	buf := &edgeproto.TrustPolicyException{}
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
		fmt.Sprintf("%s recv TrustPolicyException", s.sendrecv.cliserv),
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

func (s *TrustPolicyExceptionRecv) RecvAllStart() {
	s.Mux.Lock()
	defer s.Mux.Unlock()
	s.sendAllKeys = make(map[edgeproto.TrustPolicyExceptionKey]struct{})
}

func (s *TrustPolicyExceptionRecv) RecvAllEnd(ctx context.Context, cleanup Cleanup) {
	s.Mux.Lock()
	validKeys := s.sendAllKeys
	s.sendAllKeys = nil
	s.Mux.Unlock()
	if cleanup == CleanupPrune {
		s.handler.Prune(ctx, validKeys)
	}
}
func (s *TrustPolicyExceptionRecv) Flush(ctx context.Context, notifyId int64) {
	s.handler.Flush(ctx, notifyId)
}

type TrustPolicyExceptionRecvMany struct {
	handler RecvTrustPolicyExceptionHandler
}

func NewTrustPolicyExceptionRecvMany(handler RecvTrustPolicyExceptionHandler) *TrustPolicyExceptionRecvMany {
	s := &TrustPolicyExceptionRecvMany{}
	s.handler = handler
	return s
}

func (s *TrustPolicyExceptionRecvMany) NewRecv() NotifyRecv {
	recv := NewTrustPolicyExceptionRecv(s.handler)
	return recv
}

func (s *TrustPolicyExceptionRecvMany) Flush(ctx context.Context, notifyId int64) {
	s.handler.Flush(ctx, notifyId)
}
func (mgr *ServerMgr) RegisterSendTrustPolicyExceptionCache(cache TrustPolicyExceptionCacheHandler) {
	send := NewTrustPolicyExceptionSendMany(cache)
	mgr.RegisterSend(send)
	cache.AddNotifyCb(send.Update)
}

func (mgr *ServerMgr) RegisterRecvTrustPolicyExceptionCache(cache TrustPolicyExceptionCacheHandler) {
	recv := NewTrustPolicyExceptionRecvMany(cache)
	mgr.RegisterRecv(recv)
}

func (s *Client) RegisterSendTrustPolicyExceptionCache(cache TrustPolicyExceptionCacheHandler) {
	send := NewTrustPolicyExceptionSend(cache)
	s.RegisterSend(send)
	cache.AddNotifyCb(send.Update)
}

func (s *Client) RegisterRecvTrustPolicyExceptionCache(cache TrustPolicyExceptionCacheHandler) {
	recv := NewTrustPolicyExceptionRecv(cache)
	s.RegisterRecv(recv)
}
