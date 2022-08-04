// Code generated by protoc-gen-gogo. DO NOT EDIT.
// source: network.proto

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

type SendNetworkHandler interface {
	GetAllKeys(ctx context.Context, cb func(key *edgeproto.NetworkKey, modRev int64))
	GetWithRev(key *edgeproto.NetworkKey, buf *edgeproto.Network, modRev *int64) bool
}

type RecvNetworkHandler interface {
	Update(ctx context.Context, in *edgeproto.Network, rev int64)
	Delete(ctx context.Context, in *edgeproto.Network, rev int64)
	Prune(ctx context.Context, keys map[edgeproto.NetworkKey]struct{})
	Flush(ctx context.Context, notifyId int64)
}

type NetworkCacheHandler interface {
	SendNetworkHandler
	RecvNetworkHandler
	AddNotifyCb(fn func(ctx context.Context, obj *edgeproto.NetworkKey, old *edgeproto.Network, modRev int64))
}

type NetworkSend struct {
	Name        string
	MessageName string
	handler     SendNetworkHandler
	Keys        map[edgeproto.NetworkKey]NetworkSendContext
	keysToSend  map[edgeproto.NetworkKey]NetworkSendContext
	notifyId    int64
	Mux         sync.Mutex
	buf         edgeproto.Network
	SendCount   uint64
	sendrecv    *SendRecv
}

type NetworkSendContext struct {
	ctx    context.Context
	modRev int64
}

func NewNetworkSend(handler SendNetworkHandler) *NetworkSend {
	send := &NetworkSend{}
	send.Name = "Network"
	send.MessageName = proto.MessageName((*edgeproto.Network)(nil))
	send.handler = handler
	send.Keys = make(map[edgeproto.NetworkKey]NetworkSendContext)
	return send
}

func (s *NetworkSend) SetSendRecv(sendrecv *SendRecv) {
	s.sendrecv = sendrecv
}

func (s *NetworkSend) GetMessageName() string {
	return s.MessageName
}

func (s *NetworkSend) GetName() string {
	return s.Name
}

func (s *NetworkSend) GetSendCount() uint64 {
	return s.SendCount
}

func (s *NetworkSend) GetNotifyId() int64 {
	return s.notifyId
}
func (s *NetworkSend) UpdateAll(ctx context.Context) {
	if !s.sendrecv.isRemoteWanted(s.MessageName) {
		return
	}
	s.Mux.Lock()
	s.handler.GetAllKeys(ctx, func(key *edgeproto.NetworkKey, modRev int64) {
		s.Keys[*key] = NetworkSendContext{
			ctx:    ctx,
			modRev: modRev,
		}
	})
	s.Mux.Unlock()
}

func (s *NetworkSend) Update(ctx context.Context, key *edgeproto.NetworkKey, old *edgeproto.Network, modRev int64) {
	if !s.sendrecv.isRemoteWanted(s.MessageName) {
		return
	}
	s.updateInternal(ctx, key, modRev)
}

func (s *NetworkSend) updateInternal(ctx context.Context, key *edgeproto.NetworkKey, modRev int64) {
	s.Mux.Lock()
	log.SpanLog(ctx, log.DebugLevelNotify, "updateInternal Network", "key", key, "modRev", modRev)
	s.Keys[*key] = NetworkSendContext{
		ctx:    ctx,
		modRev: modRev,
	}
	s.Mux.Unlock()
	s.sendrecv.wakeup()
}

func (s *NetworkSend) Send(stream StreamNotify, notice *edgeproto.Notice, peer string) error {
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
			fmt.Sprintf("%s send Network", s.sendrecv.cliserv),
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

func (s *NetworkSend) PrepData() bool {
	s.Mux.Lock()
	defer s.Mux.Unlock()
	if len(s.Keys) > 0 {
		s.keysToSend = s.Keys
		s.Keys = make(map[edgeproto.NetworkKey]NetworkSendContext)
		return true
	}
	return false
}

// Server accepts multiple clients so needs to track multiple
// peers to send to.
type NetworkSendMany struct {
	handler SendNetworkHandler
	Mux     sync.Mutex
	sends   map[string]*NetworkSend
}

func NewNetworkSendMany(handler SendNetworkHandler) *NetworkSendMany {
	s := &NetworkSendMany{}
	s.handler = handler
	s.sends = make(map[string]*NetworkSend)
	return s
}

func (s *NetworkSendMany) NewSend(peerAddr string, notifyId int64) NotifySend {
	send := NewNetworkSend(s.handler)
	send.notifyId = notifyId
	s.Mux.Lock()
	s.sends[peerAddr] = send
	s.Mux.Unlock()
	return send
}

func (s *NetworkSendMany) DoneSend(peerAddr string, send NotifySend) {
	asend, ok := send.(*NetworkSend)
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
func (s *NetworkSendMany) Update(ctx context.Context, key *edgeproto.NetworkKey, old *edgeproto.Network, modRev int64) {
	s.Mux.Lock()
	defer s.Mux.Unlock()
	for _, send := range s.sends {
		send.Update(ctx, key, old, modRev)
	}
}

func (s *NetworkSendMany) GetTypeString() string {
	return "Network"
}

type NetworkRecv struct {
	Name        string
	MessageName string
	handler     RecvNetworkHandler
	sendAllKeys map[edgeproto.NetworkKey]struct{}
	Mux         sync.Mutex
	buf         edgeproto.Network
	RecvCount   uint64
	sendrecv    *SendRecv
}

func NewNetworkRecv(handler RecvNetworkHandler) *NetworkRecv {
	recv := &NetworkRecv{}
	recv.Name = "Network"
	recv.MessageName = proto.MessageName((*edgeproto.Network)(nil))
	recv.handler = handler
	return recv
}

func (s *NetworkRecv) SetSendRecv(sendrecv *SendRecv) {
	s.sendrecv = sendrecv
}

func (s *NetworkRecv) GetMessageName() string {
	return s.MessageName
}

func (s *NetworkRecv) GetName() string {
	return s.Name
}

func (s *NetworkRecv) GetRecvCount() uint64 {
	return s.RecvCount
}

func (s *NetworkRecv) Recv(ctx context.Context, notice *edgeproto.Notice, notifyId int64, peerAddr string) {
	span := opentracing.SpanFromContext(ctx)
	if span != nil {
		span.SetTag("objtype", "Network")
	}

	buf := &edgeproto.Network{}
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
		fmt.Sprintf("%s recv Network", s.sendrecv.cliserv),
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

func (s *NetworkRecv) RecvAllStart() {
	s.Mux.Lock()
	defer s.Mux.Unlock()
	s.sendAllKeys = make(map[edgeproto.NetworkKey]struct{})
}

func (s *NetworkRecv) RecvAllEnd(ctx context.Context, cleanup Cleanup) {
	s.Mux.Lock()
	validKeys := s.sendAllKeys
	s.sendAllKeys = nil
	s.Mux.Unlock()
	if cleanup == CleanupPrune {
		s.handler.Prune(ctx, validKeys)
	}
}
func (s *NetworkRecv) Flush(ctx context.Context, notifyId int64) {
	s.handler.Flush(ctx, notifyId)
}

type NetworkRecvMany struct {
	handler RecvNetworkHandler
}

func NewNetworkRecvMany(handler RecvNetworkHandler) *NetworkRecvMany {
	s := &NetworkRecvMany{}
	s.handler = handler
	return s
}

func (s *NetworkRecvMany) NewRecv() NotifyRecv {
	recv := NewNetworkRecv(s.handler)
	return recv
}

func (s *NetworkRecvMany) Flush(ctx context.Context, notifyId int64) {
	s.handler.Flush(ctx, notifyId)
}
func (mgr *ServerMgr) RegisterSendNetworkCache(cache NetworkCacheHandler) {
	send := NewNetworkSendMany(cache)
	mgr.RegisterSend(send)
	cache.AddNotifyCb(send.Update)
}

func (mgr *ServerMgr) RegisterRecvNetworkCache(cache NetworkCacheHandler) {
	recv := NewNetworkRecvMany(cache)
	mgr.RegisterRecv(recv)
}

func (s *Client) RegisterSendNetworkCache(cache NetworkCacheHandler) {
	send := NewNetworkSend(cache)
	s.RegisterSend(send)
	cache.AddNotifyCb(send.Update)
}

func (s *Client) RegisterRecvNetworkCache(cache NetworkCacheHandler) {
	recv := NewNetworkRecv(cache)
	s.RegisterRecv(recv)
}