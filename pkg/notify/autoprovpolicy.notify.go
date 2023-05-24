// Code generated by protoc-gen-gogo. DO NOT EDIT.
// source: autoprovpolicy.proto

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
	_ "github.com/gogo/protobuf/types"
	opentracing "github.com/opentracing/opentracing-go"
	math "math"
	"sync"
)

// Reference imports to suppress errors if they are not otherwise used.
var _ = proto.Marshal
var _ = fmt.Errorf
var _ = math.Inf

// Auto-generated code: DO NOT EDIT

type SendAutoProvPolicyHandler interface {
	GetAllLocked(ctx context.Context, cb func(key *edgeproto.AutoProvPolicy, modRev int64))
	GetWithRev(key *edgeproto.PolicyKey, buf *edgeproto.AutoProvPolicy, modRev *int64) bool
}

type RecvAutoProvPolicyHandler interface {
	Update(ctx context.Context, in *edgeproto.AutoProvPolicy, rev int64)
	Delete(ctx context.Context, in *edgeproto.AutoProvPolicy, rev int64)
	Prune(ctx context.Context, keys map[edgeproto.PolicyKey]struct{})
	Flush(ctx context.Context, notifyId int64)
}

type AutoProvPolicyCacheHandler interface {
	SendAutoProvPolicyHandler
	RecvAutoProvPolicyHandler
	AddNotifyCb(fn func(ctx context.Context, obj *edgeproto.AutoProvPolicy, modRev int64))
}

type AutoProvPolicySend struct {
	Name        string
	MessageName string
	handler     SendAutoProvPolicyHandler
	Keys        map[edgeproto.PolicyKey]AutoProvPolicySendContext
	keysToSend  map[edgeproto.PolicyKey]AutoProvPolicySendContext
	notifyId    int64
	Mux         sync.Mutex
	buf         edgeproto.AutoProvPolicy
	SendCount   uint64
	sendrecv    *SendRecv
}

type AutoProvPolicySendContext struct {
	ctx         context.Context
	modRev      int64
	forceDelete bool
}

func NewAutoProvPolicySend(handler SendAutoProvPolicyHandler) *AutoProvPolicySend {
	send := &AutoProvPolicySend{}
	send.Name = "AutoProvPolicy"
	send.MessageName = proto.MessageName((*edgeproto.AutoProvPolicy)(nil))
	send.handler = handler
	send.Keys = make(map[edgeproto.PolicyKey]AutoProvPolicySendContext)
	return send
}

func (s *AutoProvPolicySend) SetSendRecv(sendrecv *SendRecv) {
	s.sendrecv = sendrecv
}

func (s *AutoProvPolicySend) GetMessageName() string {
	return s.MessageName
}

func (s *AutoProvPolicySend) GetName() string {
	return s.Name
}

func (s *AutoProvPolicySend) GetSendCount() uint64 {
	return s.SendCount
}

func (s *AutoProvPolicySend) GetNotifyId() int64 {
	return s.notifyId
}
func (s *AutoProvPolicySend) UpdateAll(ctx context.Context) {
	if !s.sendrecv.isRemoteWanted(s.MessageName) {
		return
	}
	s.Mux.Lock()
	s.handler.GetAllLocked(ctx, func(obj *edgeproto.AutoProvPolicy, modRev int64) {
		s.Keys[*obj.GetKey()] = AutoProvPolicySendContext{
			ctx:    ctx,
			modRev: modRev,
		}
	})
	s.Mux.Unlock()
}

func (s *AutoProvPolicySend) Update(ctx context.Context, obj *edgeproto.AutoProvPolicy, modRev int64) {
	if !s.sendrecv.isRemoteWanted(s.MessageName) {
		return
	}
	forceDelete := false
	s.updateInternal(ctx, obj.GetKey(), modRev, forceDelete)
}

func (s *AutoProvPolicySend) ForceDelete(ctx context.Context, key *edgeproto.PolicyKey, modRev int64) {
	forceDelete := true
	s.updateInternal(ctx, key, modRev, forceDelete)
}

func (s *AutoProvPolicySend) updateInternal(ctx context.Context, key *edgeproto.PolicyKey, modRev int64, forceDelete bool) {
	s.Mux.Lock()
	log.SpanLog(ctx, log.DebugLevelNotify, "updateInternal AutoProvPolicy", "key", key, "modRev", modRev)
	s.Keys[*key] = AutoProvPolicySendContext{
		ctx:         ctx,
		modRev:      modRev,
		forceDelete: forceDelete,
	}
	s.Mux.Unlock()
	s.sendrecv.wakeup()
}

func (s *AutoProvPolicySend) SendForCloudlet(ctx context.Context, action edgeproto.NoticeAction, cloudlet *edgeproto.Cloudlet) {
}

func (s *AutoProvPolicySend) Send(stream StreamNotify, notice *edgeproto.Notice, peer string) error {
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
			fmt.Sprintf("%s send AutoProvPolicy", s.sendrecv.cliserv),
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

func (s *AutoProvPolicySend) PrepData() bool {
	s.Mux.Lock()
	defer s.Mux.Unlock()
	if len(s.Keys) > 0 {
		s.keysToSend = s.Keys
		s.Keys = make(map[edgeproto.PolicyKey]AutoProvPolicySendContext)
		return true
	}
	return false
}

// Server accepts multiple clients so needs to track multiple
// peers to send to.
type AutoProvPolicySendMany struct {
	handler SendAutoProvPolicyHandler
	Mux     sync.Mutex
	sends   map[string]*AutoProvPolicySend
}

func NewAutoProvPolicySendMany(handler SendAutoProvPolicyHandler) *AutoProvPolicySendMany {
	s := &AutoProvPolicySendMany{}
	s.handler = handler
	s.sends = make(map[string]*AutoProvPolicySend)
	return s
}

func (s *AutoProvPolicySendMany) NewSend(peerAddr string, notifyId int64) NotifySend {
	send := NewAutoProvPolicySend(s.handler)
	send.notifyId = notifyId
	s.Mux.Lock()
	s.sends[peerAddr] = send
	s.Mux.Unlock()
	return send
}

func (s *AutoProvPolicySendMany) DoneSend(peerAddr string, send NotifySend) {
	asend, ok := send.(*AutoProvPolicySend)
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
func (s *AutoProvPolicySendMany) Update(ctx context.Context, obj *edgeproto.AutoProvPolicy, modRev int64) {
	s.Mux.Lock()
	defer s.Mux.Unlock()
	for _, send := range s.sends {
		send.Update(ctx, obj, modRev)
	}
}

func (s *AutoProvPolicySendMany) GetTypeString() string {
	return "AutoProvPolicy"
}

type AutoProvPolicyRecv struct {
	Name        string
	MessageName string
	handler     RecvAutoProvPolicyHandler
	sendAllKeys map[edgeproto.PolicyKey]struct{}
	Mux         sync.Mutex
	buf         edgeproto.AutoProvPolicy
	RecvCount   uint64
	sendrecv    *SendRecv
}

func NewAutoProvPolicyRecv(handler RecvAutoProvPolicyHandler) *AutoProvPolicyRecv {
	recv := &AutoProvPolicyRecv{}
	recv.Name = "AutoProvPolicy"
	recv.MessageName = proto.MessageName((*edgeproto.AutoProvPolicy)(nil))
	recv.handler = handler
	return recv
}

func (s *AutoProvPolicyRecv) SetSendRecv(sendrecv *SendRecv) {
	s.sendrecv = sendrecv
}

func (s *AutoProvPolicyRecv) GetMessageName() string {
	return s.MessageName
}

func (s *AutoProvPolicyRecv) GetName() string {
	return s.Name
}

func (s *AutoProvPolicyRecv) GetRecvCount() uint64 {
	return s.RecvCount
}

func (s *AutoProvPolicyRecv) Recv(ctx context.Context, notice *edgeproto.Notice, notifyId int64, peerAddr string) {
	span := opentracing.SpanFromContext(ctx)
	if span != nil {
		span.SetTag("objtype", "AutoProvPolicy")
	}

	buf := &edgeproto.AutoProvPolicy{}
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
		fmt.Sprintf("%s recv AutoProvPolicy", s.sendrecv.cliserv),
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

func (s *AutoProvPolicyRecv) RecvAllStart() {
	s.Mux.Lock()
	defer s.Mux.Unlock()
	s.sendAllKeys = make(map[edgeproto.PolicyKey]struct{})
}

func (s *AutoProvPolicyRecv) RecvAllEnd(ctx context.Context, cleanup Cleanup) {
	s.Mux.Lock()
	validKeys := s.sendAllKeys
	s.sendAllKeys = nil
	s.Mux.Unlock()
	if cleanup == CleanupPrune {
		s.handler.Prune(ctx, validKeys)
	}
}
func (s *AutoProvPolicyRecv) Flush(ctx context.Context, notifyId int64) {
	s.handler.Flush(ctx, notifyId)
}

type AutoProvPolicyRecvMany struct {
	handler RecvAutoProvPolicyHandler
}

func NewAutoProvPolicyRecvMany(handler RecvAutoProvPolicyHandler) *AutoProvPolicyRecvMany {
	s := &AutoProvPolicyRecvMany{}
	s.handler = handler
	return s
}

func (s *AutoProvPolicyRecvMany) NewRecv() NotifyRecv {
	recv := NewAutoProvPolicyRecv(s.handler)
	return recv
}

func (s *AutoProvPolicyRecvMany) Flush(ctx context.Context, notifyId int64) {
	s.handler.Flush(ctx, notifyId)
}
func (mgr *ServerMgr) RegisterSendAutoProvPolicyCache(cache AutoProvPolicyCacheHandler) {
	send := NewAutoProvPolicySendMany(cache)
	mgr.RegisterSend(send)
	cache.AddNotifyCb(send.Update)
}

func (mgr *ServerMgr) RegisterRecvAutoProvPolicyCache(cache AutoProvPolicyCacheHandler) {
	recv := NewAutoProvPolicyRecvMany(cache)
	mgr.RegisterRecv(recv)
}

func (s *Client) RegisterSendAutoProvPolicyCache(cache AutoProvPolicyCacheHandler) {
	send := NewAutoProvPolicySend(cache)
	s.RegisterSend(send)
	cache.AddNotifyCb(send.Update)
}

func (s *Client) RegisterRecvAutoProvPolicyCache(cache AutoProvPolicyCacheHandler) {
	recv := NewAutoProvPolicyRecv(cache)
	s.RegisterRecv(recv)
}

type RecvAutoProvCountsHandler interface {
	RecvAutoProvCounts(ctx context.Context, msg *edgeproto.AutoProvCounts)
}

type AutoProvCountsSend struct {
	Name        string
	MessageName string
	Data        []*edgeproto.AutoProvCounts
	dataToSend  []*edgeproto.AutoProvCounts
	Ctxs        []context.Context
	ctxsToSend  []context.Context
	notifyId    int64
	Mux         sync.Mutex
	buf         edgeproto.AutoProvCounts
	SendCount   uint64
	sendrecv    *SendRecv
}

type AutoProvCountsSendContext struct {
	ctx         context.Context
	modRev      int64
	forceDelete bool
}

func NewAutoProvCountsSend() *AutoProvCountsSend {
	send := &AutoProvCountsSend{}
	send.Name = "AutoProvCounts"
	send.MessageName = proto.MessageName((*edgeproto.AutoProvCounts)(nil))
	send.Data = make([]*edgeproto.AutoProvCounts, 0)
	return send
}

func (s *AutoProvCountsSend) SetSendRecv(sendrecv *SendRecv) {
	s.sendrecv = sendrecv
}

func (s *AutoProvCountsSend) GetMessageName() string {
	return s.MessageName
}

func (s *AutoProvCountsSend) GetName() string {
	return s.Name
}

func (s *AutoProvCountsSend) GetSendCount() uint64 {
	return s.SendCount
}

func (s *AutoProvCountsSend) GetNotifyId() int64 {
	return s.notifyId
}
func (s *AutoProvCountsSend) UpdateAll(ctx context.Context) {}

func (s *AutoProvCountsSend) Update(ctx context.Context, msg *edgeproto.AutoProvCounts) bool {
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

func (s *AutoProvCountsSend) SendForCloudlet(ctx context.Context, action edgeproto.NoticeAction, cloudlet *edgeproto.Cloudlet) {
}

func (s *AutoProvCountsSend) Send(stream StreamNotify, notice *edgeproto.Notice, peer string) error {
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

func (s *AutoProvCountsSend) PrepData() bool {
	s.Mux.Lock()
	defer s.Mux.Unlock()
	if len(s.Data) > 0 {
		s.dataToSend = s.Data
		s.Data = make([]*edgeproto.AutoProvCounts, 0)
		s.ctxsToSend = s.Ctxs
		s.Ctxs = make([]context.Context, 0)
		return true
	}
	return false
}

// Server accepts multiple clients so needs to track multiple
// peers to send to.
type AutoProvCountsSendMany struct {
	Mux   sync.Mutex
	sends map[string]*AutoProvCountsSend
}

func NewAutoProvCountsSendMany() *AutoProvCountsSendMany {
	s := &AutoProvCountsSendMany{}
	s.sends = make(map[string]*AutoProvCountsSend)
	return s
}

func (s *AutoProvCountsSendMany) NewSend(peerAddr string, notifyId int64) NotifySend {
	send := NewAutoProvCountsSend()
	send.notifyId = notifyId
	s.Mux.Lock()
	s.sends[peerAddr] = send
	s.Mux.Unlock()
	return send
}

func (s *AutoProvCountsSendMany) DoneSend(peerAddr string, send NotifySend) {
	asend, ok := send.(*AutoProvCountsSend)
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
func (s *AutoProvCountsSendMany) Update(ctx context.Context, msg *edgeproto.AutoProvCounts) int {
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

func (s *AutoProvCountsSendMany) UpdateFiltered(ctx context.Context, msg *edgeproto.AutoProvCounts, sendOk func(ctx context.Context, send *AutoProvCountsSend, msg *edgeproto.AutoProvCounts) bool) int {
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

func (s *AutoProvCountsSendMany) GetTypeString() string {
	return "AutoProvCounts"
}

type AutoProvCountsRecv struct {
	Name        string
	MessageName string
	handler     RecvAutoProvCountsHandler
	Mux         sync.Mutex
	buf         edgeproto.AutoProvCounts
	RecvCount   uint64
	sendrecv    *SendRecv
}

func NewAutoProvCountsRecv(handler RecvAutoProvCountsHandler) *AutoProvCountsRecv {
	recv := &AutoProvCountsRecv{}
	recv.Name = "AutoProvCounts"
	recv.MessageName = proto.MessageName((*edgeproto.AutoProvCounts)(nil))
	recv.handler = handler
	return recv
}

func (s *AutoProvCountsRecv) SetSendRecv(sendrecv *SendRecv) {
	s.sendrecv = sendrecv
}

func (s *AutoProvCountsRecv) GetMessageName() string {
	return s.MessageName
}

func (s *AutoProvCountsRecv) GetName() string {
	return s.Name
}

func (s *AutoProvCountsRecv) GetRecvCount() uint64 {
	return s.RecvCount
}

func (s *AutoProvCountsRecv) Recv(ctx context.Context, notice *edgeproto.Notice, notifyId int64, peerAddr string) {

	buf := &edgeproto.AutoProvCounts{}
	err := types.UnmarshalAny(&notice.Any, buf)
	if err != nil {
		s.sendrecv.stats.UnmarshalErrors++
		return
	}
	s.handler.RecvAutoProvCounts(ctx, buf)
	s.sendrecv.stats.Recv++
	// object specific counter
	s.RecvCount++
}

func (s *AutoProvCountsRecv) RecvAllStart() {
}

func (s *AutoProvCountsRecv) RecvAllEnd(ctx context.Context, cleanup Cleanup) {
}

type AutoProvCountsRecvMany struct {
	handler RecvAutoProvCountsHandler
}

func NewAutoProvCountsRecvMany(handler RecvAutoProvCountsHandler) *AutoProvCountsRecvMany {
	s := &AutoProvCountsRecvMany{}
	s.handler = handler
	return s
}

func (s *AutoProvCountsRecvMany) NewRecv() NotifyRecv {
	recv := NewAutoProvCountsRecv(s.handler)
	return recv
}

func (s *AutoProvCountsRecvMany) Flush(ctx context.Context, notifyId int64) {
}

type SendAutoProvInfoHandler interface {
	GetAllLocked(ctx context.Context, cb func(key *edgeproto.AutoProvInfo, modRev int64))
	GetWithRev(key *edgeproto.CloudletKey, buf *edgeproto.AutoProvInfo, modRev *int64) bool
}

type RecvAutoProvInfoHandler interface {
	Update(ctx context.Context, in *edgeproto.AutoProvInfo, rev int64)
	Delete(ctx context.Context, in *edgeproto.AutoProvInfo, rev int64)
	Prune(ctx context.Context, keys map[edgeproto.CloudletKey]struct{})
	Flush(ctx context.Context, notifyId int64)
}

type AutoProvInfoCacheHandler interface {
	SendAutoProvInfoHandler
	RecvAutoProvInfoHandler
	AddNotifyCb(fn func(ctx context.Context, obj *edgeproto.AutoProvInfo, modRev int64))
}

type AutoProvInfoSend struct {
	Name        string
	MessageName string
	handler     SendAutoProvInfoHandler
	Keys        map[edgeproto.CloudletKey]AutoProvInfoSendContext
	keysToSend  map[edgeproto.CloudletKey]AutoProvInfoSendContext
	notifyId    int64
	Mux         sync.Mutex
	buf         edgeproto.AutoProvInfo
	SendCount   uint64
	sendrecv    *SendRecv
}

type AutoProvInfoSendContext struct {
	ctx         context.Context
	modRev      int64
	forceDelete bool
}

func NewAutoProvInfoSend(handler SendAutoProvInfoHandler) *AutoProvInfoSend {
	send := &AutoProvInfoSend{}
	send.Name = "AutoProvInfo"
	send.MessageName = proto.MessageName((*edgeproto.AutoProvInfo)(nil))
	send.handler = handler
	send.Keys = make(map[edgeproto.CloudletKey]AutoProvInfoSendContext)
	return send
}

func (s *AutoProvInfoSend) SetSendRecv(sendrecv *SendRecv) {
	s.sendrecv = sendrecv
}

func (s *AutoProvInfoSend) GetMessageName() string {
	return s.MessageName
}

func (s *AutoProvInfoSend) GetName() string {
	return s.Name
}

func (s *AutoProvInfoSend) GetSendCount() uint64 {
	return s.SendCount
}

func (s *AutoProvInfoSend) GetNotifyId() int64 {
	return s.notifyId
}
func (s *AutoProvInfoSend) UpdateAll(ctx context.Context) {
	if !s.sendrecv.isRemoteWanted(s.MessageName) {
		return
	}
	s.Mux.Lock()
	s.handler.GetAllLocked(ctx, func(obj *edgeproto.AutoProvInfo, modRev int64) {
		s.Keys[*obj.GetKey()] = AutoProvInfoSendContext{
			ctx:    ctx,
			modRev: modRev,
		}
	})
	s.Mux.Unlock()
}

func (s *AutoProvInfoSend) Update(ctx context.Context, obj *edgeproto.AutoProvInfo, modRev int64) {
	if !s.sendrecv.isRemoteWanted(s.MessageName) {
		return
	}
	forceDelete := false
	s.updateInternal(ctx, obj.GetKey(), modRev, forceDelete)
}

func (s *AutoProvInfoSend) ForceDelete(ctx context.Context, key *edgeproto.CloudletKey, modRev int64) {
	forceDelete := true
	s.updateInternal(ctx, key, modRev, forceDelete)
}

func (s *AutoProvInfoSend) updateInternal(ctx context.Context, key *edgeproto.CloudletKey, modRev int64, forceDelete bool) {
	s.Mux.Lock()
	log.SpanLog(ctx, log.DebugLevelNotify, "updateInternal AutoProvInfo", "key", key, "modRev", modRev)
	s.Keys[*key] = AutoProvInfoSendContext{
		ctx:         ctx,
		modRev:      modRev,
		forceDelete: forceDelete,
	}
	s.Mux.Unlock()
	s.sendrecv.wakeup()
}

func (s *AutoProvInfoSend) SendForCloudlet(ctx context.Context, action edgeproto.NoticeAction, cloudlet *edgeproto.Cloudlet) {
}

func (s *AutoProvInfoSend) Send(stream StreamNotify, notice *edgeproto.Notice, peer string) error {
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
			fmt.Sprintf("%s send AutoProvInfo", s.sendrecv.cliserv),
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

func (s *AutoProvInfoSend) PrepData() bool {
	s.Mux.Lock()
	defer s.Mux.Unlock()
	if len(s.Keys) > 0 {
		s.keysToSend = s.Keys
		s.Keys = make(map[edgeproto.CloudletKey]AutoProvInfoSendContext)
		return true
	}
	return false
}

// Server accepts multiple clients so needs to track multiple
// peers to send to.
type AutoProvInfoSendMany struct {
	handler SendAutoProvInfoHandler
	Mux     sync.Mutex
	sends   map[string]*AutoProvInfoSend
}

func NewAutoProvInfoSendMany(handler SendAutoProvInfoHandler) *AutoProvInfoSendMany {
	s := &AutoProvInfoSendMany{}
	s.handler = handler
	s.sends = make(map[string]*AutoProvInfoSend)
	return s
}

func (s *AutoProvInfoSendMany) NewSend(peerAddr string, notifyId int64) NotifySend {
	send := NewAutoProvInfoSend(s.handler)
	send.notifyId = notifyId
	s.Mux.Lock()
	s.sends[peerAddr] = send
	s.Mux.Unlock()
	return send
}

func (s *AutoProvInfoSendMany) DoneSend(peerAddr string, send NotifySend) {
	asend, ok := send.(*AutoProvInfoSend)
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
func (s *AutoProvInfoSendMany) Update(ctx context.Context, obj *edgeproto.AutoProvInfo, modRev int64) {
	s.Mux.Lock()
	defer s.Mux.Unlock()
	for _, send := range s.sends {
		send.Update(ctx, obj, modRev)
	}
}

func (s *AutoProvInfoSendMany) GetTypeString() string {
	return "AutoProvInfo"
}

type AutoProvInfoRecv struct {
	Name        string
	MessageName string
	handler     RecvAutoProvInfoHandler
	sendAllKeys map[edgeproto.CloudletKey]struct{}
	Mux         sync.Mutex
	buf         edgeproto.AutoProvInfo
	RecvCount   uint64
	sendrecv    *SendRecv
}

func NewAutoProvInfoRecv(handler RecvAutoProvInfoHandler) *AutoProvInfoRecv {
	recv := &AutoProvInfoRecv{}
	recv.Name = "AutoProvInfo"
	recv.MessageName = proto.MessageName((*edgeproto.AutoProvInfo)(nil))
	recv.handler = handler
	return recv
}

func (s *AutoProvInfoRecv) SetSendRecv(sendrecv *SendRecv) {
	s.sendrecv = sendrecv
}

func (s *AutoProvInfoRecv) GetMessageName() string {
	return s.MessageName
}

func (s *AutoProvInfoRecv) GetName() string {
	return s.Name
}

func (s *AutoProvInfoRecv) GetRecvCount() uint64 {
	return s.RecvCount
}

func (s *AutoProvInfoRecv) Recv(ctx context.Context, notice *edgeproto.Notice, notifyId int64, peerAddr string) {
	span := opentracing.SpanFromContext(ctx)
	if span != nil {
		span.SetTag("objtype", "AutoProvInfo")
	}

	buf := &edgeproto.AutoProvInfo{}
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
		fmt.Sprintf("%s recv AutoProvInfo", s.sendrecv.cliserv),
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

func (s *AutoProvInfoRecv) RecvAllStart() {
	s.Mux.Lock()
	defer s.Mux.Unlock()
	s.sendAllKeys = make(map[edgeproto.CloudletKey]struct{})
}

func (s *AutoProvInfoRecv) RecvAllEnd(ctx context.Context, cleanup Cleanup) {
	s.Mux.Lock()
	validKeys := s.sendAllKeys
	s.sendAllKeys = nil
	s.Mux.Unlock()
	if cleanup == CleanupPrune {
		s.handler.Prune(ctx, validKeys)
	}
}
func (s *AutoProvInfoRecv) Flush(ctx context.Context, notifyId int64) {
	s.handler.Flush(ctx, notifyId)
}

type AutoProvInfoRecvMany struct {
	handler RecvAutoProvInfoHandler
}

func NewAutoProvInfoRecvMany(handler RecvAutoProvInfoHandler) *AutoProvInfoRecvMany {
	s := &AutoProvInfoRecvMany{}
	s.handler = handler
	return s
}

func (s *AutoProvInfoRecvMany) NewRecv() NotifyRecv {
	recv := NewAutoProvInfoRecv(s.handler)
	return recv
}

func (s *AutoProvInfoRecvMany) Flush(ctx context.Context, notifyId int64) {
	s.handler.Flush(ctx, notifyId)
}
func (mgr *ServerMgr) RegisterSendAutoProvInfoCache(cache AutoProvInfoCacheHandler) {
	send := NewAutoProvInfoSendMany(cache)
	mgr.RegisterSend(send)
	cache.AddNotifyCb(send.Update)
}

func (mgr *ServerMgr) RegisterRecvAutoProvInfoCache(cache AutoProvInfoCacheHandler) {
	recv := NewAutoProvInfoRecvMany(cache)
	mgr.RegisterRecv(recv)
}

func (s *Client) RegisterSendAutoProvInfoCache(cache AutoProvInfoCacheHandler) {
	send := NewAutoProvInfoSend(cache)
	s.RegisterSend(send)
	cache.AddNotifyCb(send.Update)
}

func (s *Client) RegisterRecvAutoProvInfoCache(cache AutoProvInfoCacheHandler) {
	recv := NewAutoProvInfoRecv(cache)
	s.RegisterRecv(recv)
}
