// Code generated by protoc-gen-gogo. DO NOT EDIT.
// source: settings.proto

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

type SendSettingsHandler interface {
	GetAllKeys(ctx context.Context, cb func(key *edgeproto.SettingsKey, modRev int64))
	GetWithRev(key *edgeproto.SettingsKey, buf *edgeproto.Settings, modRev *int64) bool
}

type RecvSettingsHandler interface {
	Update(ctx context.Context, in *edgeproto.Settings, rev int64)
	Delete(ctx context.Context, in *edgeproto.Settings, rev int64)
	Prune(ctx context.Context, keys map[edgeproto.SettingsKey]struct{})
	Flush(ctx context.Context, notifyId int64)
}

type SettingsCacheHandler interface {
	SendSettingsHandler
	RecvSettingsHandler
	AddNotifyCb(fn func(ctx context.Context, obj *edgeproto.SettingsKey, old *edgeproto.Settings, modRev int64))
}

type SettingsSend struct {
	Name        string
	MessageName string
	handler     SendSettingsHandler
	Keys        map[edgeproto.SettingsKey]SettingsSendContext
	keysToSend  map[edgeproto.SettingsKey]SettingsSendContext
	notifyId    int64
	Mux         sync.Mutex
	buf         edgeproto.Settings
	SendCount   uint64
	sendrecv    *SendRecv
}

type SettingsSendContext struct {
	ctx         context.Context
	modRev      int64
	forceDelete bool
}

func NewSettingsSend(handler SendSettingsHandler) *SettingsSend {
	send := &SettingsSend{}
	send.Name = "Settings"
	send.MessageName = proto.MessageName((*edgeproto.Settings)(nil))
	send.handler = handler
	send.Keys = make(map[edgeproto.SettingsKey]SettingsSendContext)
	return send
}

func (s *SettingsSend) SetSendRecv(sendrecv *SendRecv) {
	s.sendrecv = sendrecv
}

func (s *SettingsSend) GetMessageName() string {
	return s.MessageName
}

func (s *SettingsSend) GetName() string {
	return s.Name
}

func (s *SettingsSend) GetSendCount() uint64 {
	return s.SendCount
}

func (s *SettingsSend) GetNotifyId() int64 {
	return s.notifyId
}
func (s *SettingsSend) UpdateAll(ctx context.Context) {
	if !s.sendrecv.isRemoteWanted(s.MessageName) {
		return
	}
	s.Mux.Lock()
	s.handler.GetAllKeys(ctx, func(key *edgeproto.SettingsKey, modRev int64) {
		s.Keys[*key] = SettingsSendContext{
			ctx:    ctx,
			modRev: modRev,
		}
	})
	s.Mux.Unlock()
}

func (s *SettingsSend) Update(ctx context.Context, key *edgeproto.SettingsKey, old *edgeproto.Settings, modRev int64) {
	if !s.sendrecv.isRemoteWanted(s.MessageName) {
		return
	}
	forceDelete := false
	s.updateInternal(ctx, key, modRev, forceDelete)
}

func (s *SettingsSend) ForceDelete(ctx context.Context, key *edgeproto.SettingsKey, modRev int64) {
	forceDelete := true
	s.updateInternal(ctx, key, modRev, forceDelete)
}

func (s *SettingsSend) updateInternal(ctx context.Context, key *edgeproto.SettingsKey, modRev int64, forceDelete bool) {
	s.Mux.Lock()
	log.SpanLog(ctx, log.DebugLevelNotify, "updateInternal Settings", "key", key, "modRev", modRev)
	s.Keys[*key] = SettingsSendContext{
		ctx:         ctx,
		modRev:      modRev,
		forceDelete: forceDelete,
	}
	s.Mux.Unlock()
	s.sendrecv.wakeup()
}

func (s *SettingsSend) SendForCloudlet(ctx context.Context, action edgeproto.NoticeAction, cloudlet *edgeproto.Cloudlet) {
}

func (s *SettingsSend) Send(stream StreamNotify, notice *edgeproto.Notice, peer string) error {
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
			fmt.Sprintf("%s send Settings", s.sendrecv.cliserv),
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

func (s *SettingsSend) PrepData() bool {
	s.Mux.Lock()
	defer s.Mux.Unlock()
	if len(s.Keys) > 0 {
		s.keysToSend = s.Keys
		s.Keys = make(map[edgeproto.SettingsKey]SettingsSendContext)
		return true
	}
	return false
}

// Server accepts multiple clients so needs to track multiple
// peers to send to.
type SettingsSendMany struct {
	handler SendSettingsHandler
	Mux     sync.Mutex
	sends   map[string]*SettingsSend
}

func NewSettingsSendMany(handler SendSettingsHandler) *SettingsSendMany {
	s := &SettingsSendMany{}
	s.handler = handler
	s.sends = make(map[string]*SettingsSend)
	return s
}

func (s *SettingsSendMany) NewSend(peerAddr string, notifyId int64) NotifySend {
	send := NewSettingsSend(s.handler)
	send.notifyId = notifyId
	s.Mux.Lock()
	s.sends[peerAddr] = send
	s.Mux.Unlock()
	return send
}

func (s *SettingsSendMany) DoneSend(peerAddr string, send NotifySend) {
	asend, ok := send.(*SettingsSend)
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
func (s *SettingsSendMany) Update(ctx context.Context, key *edgeproto.SettingsKey, old *edgeproto.Settings, modRev int64) {
	s.Mux.Lock()
	defer s.Mux.Unlock()
	for _, send := range s.sends {
		send.Update(ctx, key, old, modRev)
	}
}

func (s *SettingsSendMany) GetTypeString() string {
	return "Settings"
}

type SettingsRecv struct {
	Name        string
	MessageName string
	handler     RecvSettingsHandler
	sendAllKeys map[edgeproto.SettingsKey]struct{}
	Mux         sync.Mutex
	buf         edgeproto.Settings
	RecvCount   uint64
	sendrecv    *SendRecv
}

func NewSettingsRecv(handler RecvSettingsHandler) *SettingsRecv {
	recv := &SettingsRecv{}
	recv.Name = "Settings"
	recv.MessageName = proto.MessageName((*edgeproto.Settings)(nil))
	recv.handler = handler
	return recv
}

func (s *SettingsRecv) SetSendRecv(sendrecv *SendRecv) {
	s.sendrecv = sendrecv
}

func (s *SettingsRecv) GetMessageName() string {
	return s.MessageName
}

func (s *SettingsRecv) GetName() string {
	return s.Name
}

func (s *SettingsRecv) GetRecvCount() uint64 {
	return s.RecvCount
}

func (s *SettingsRecv) Recv(ctx context.Context, notice *edgeproto.Notice, notifyId int64, peerAddr string) {
	span := opentracing.SpanFromContext(ctx)
	if span != nil {
		span.SetTag("objtype", "Settings")
	}

	buf := &edgeproto.Settings{}
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
		fmt.Sprintf("%s recv Settings", s.sendrecv.cliserv),
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

func (s *SettingsRecv) RecvAllStart() {
	s.Mux.Lock()
	defer s.Mux.Unlock()
	s.sendAllKeys = make(map[edgeproto.SettingsKey]struct{})
}

func (s *SettingsRecv) RecvAllEnd(ctx context.Context, cleanup Cleanup) {
	s.Mux.Lock()
	validKeys := s.sendAllKeys
	s.sendAllKeys = nil
	s.Mux.Unlock()
	if cleanup == CleanupPrune {
		s.handler.Prune(ctx, validKeys)
	}
}
func (s *SettingsRecv) Flush(ctx context.Context, notifyId int64) {
	s.handler.Flush(ctx, notifyId)
}

type SettingsRecvMany struct {
	handler RecvSettingsHandler
}

func NewSettingsRecvMany(handler RecvSettingsHandler) *SettingsRecvMany {
	s := &SettingsRecvMany{}
	s.handler = handler
	return s
}

func (s *SettingsRecvMany) NewRecv() NotifyRecv {
	recv := NewSettingsRecv(s.handler)
	return recv
}

func (s *SettingsRecvMany) Flush(ctx context.Context, notifyId int64) {
	s.handler.Flush(ctx, notifyId)
}
func (mgr *ServerMgr) RegisterSendSettingsCache(cache SettingsCacheHandler) {
	send := NewSettingsSendMany(cache)
	mgr.RegisterSend(send)
	cache.AddNotifyCb(send.Update)
}

func (mgr *ServerMgr) RegisterRecvSettingsCache(cache SettingsCacheHandler) {
	recv := NewSettingsRecvMany(cache)
	mgr.RegisterRecv(recv)
}

func (s *Client) RegisterSendSettingsCache(cache SettingsCacheHandler) {
	send := NewSettingsSend(cache)
	s.RegisterSend(send)
	cache.AddNotifyCb(send.Update)
}

func (s *Client) RegisterRecvSettingsCache(cache SettingsCacheHandler) {
	recv := NewSettingsRecv(cache)
	s.RegisterRecv(recv)
}
