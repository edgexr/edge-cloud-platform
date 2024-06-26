// Code generated by protoc-gen-gogo. DO NOT EDIT.
// source: debug.proto

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

type RecvDebugRequestHandler interface {
	RecvDebugRequest(ctx context.Context, msg *edgeproto.DebugRequest)
}

type DebugRequestSend struct {
	Name        string
	MessageName string
	Data        []*edgeproto.DebugRequest
	dataToSend  []*edgeproto.DebugRequest
	Ctxs        []context.Context
	ctxsToSend  []context.Context
	notifyId    int64
	Mux         sync.Mutex
	buf         edgeproto.DebugRequest
	SendCount   uint64
	sendrecv    *SendRecv
}

type DebugRequestSendContext struct {
	ctx         context.Context
	modRev      int64
	forceDelete bool
}

func NewDebugRequestSend() *DebugRequestSend {
	send := &DebugRequestSend{}
	send.Name = "DebugRequest"
	send.MessageName = proto.MessageName((*edgeproto.DebugRequest)(nil))
	send.Data = make([]*edgeproto.DebugRequest, 0)
	return send
}

func (s *DebugRequestSend) SetSendRecv(sendrecv *SendRecv) {
	s.sendrecv = sendrecv
}

func (s *DebugRequestSend) GetMessageName() string {
	return s.MessageName
}

func (s *DebugRequestSend) GetName() string {
	return s.Name
}

func (s *DebugRequestSend) GetSendCount() uint64 {
	return s.SendCount
}

func (s *DebugRequestSend) GetNotifyId() int64 {
	return s.notifyId
}
func (s *DebugRequestSend) UpdateAll(ctx context.Context) {}

func (s *DebugRequestSend) Update(ctx context.Context, msg *edgeproto.DebugRequest) bool {
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

func (s *DebugRequestSend) SendForCloudlet(ctx context.Context, action edgeproto.NoticeAction, cloudlet *edgeproto.Cloudlet) {
}

func (s *DebugRequestSend) Send(stream StreamNotify, notice *edgeproto.Notice, peer string) error {
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
		log.SpanLog(ctx, log.DebugLevelNotify,
			fmt.Sprintf("%s send DebugRequest", s.sendrecv.cliserv),
			"peerAddr", peer,
			"peer", s.sendrecv.peer,
			"local", s.sendrecv.name,
			"message", msg)
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

func (s *DebugRequestSend) PrepData() bool {
	s.Mux.Lock()
	defer s.Mux.Unlock()
	if len(s.Data) > 0 {
		s.dataToSend = s.Data
		s.Data = make([]*edgeproto.DebugRequest, 0)
		s.ctxsToSend = s.Ctxs
		s.Ctxs = make([]context.Context, 0)
		return true
	}
	return false
}

// Server accepts multiple clients so needs to track multiple
// peers to send to.
type DebugRequestSendMany struct {
	Mux   sync.Mutex
	sends map[string]*DebugRequestSend
}

func NewDebugRequestSendMany() *DebugRequestSendMany {
	s := &DebugRequestSendMany{}
	s.sends = make(map[string]*DebugRequestSend)
	return s
}

func (s *DebugRequestSendMany) NewSend(peerAddr string, notifyId int64) NotifySend {
	send := NewDebugRequestSend()
	send.notifyId = notifyId
	s.Mux.Lock()
	s.sends[peerAddr] = send
	s.Mux.Unlock()
	return send
}

func (s *DebugRequestSendMany) DoneSend(peerAddr string, send NotifySend) {
	asend, ok := send.(*DebugRequestSend)
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
func (s *DebugRequestSendMany) Update(ctx context.Context, msg *edgeproto.DebugRequest) int {
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

func (s *DebugRequestSendMany) UpdateFiltered(ctx context.Context, msg *edgeproto.DebugRequest, sendOk func(ctx context.Context, send *DebugRequestSend, msg *edgeproto.DebugRequest) bool) int {
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

func (s *DebugRequestSendMany) GetTypeString() string {
	return "DebugRequest"
}

type DebugRequestRecv struct {
	Name        string
	MessageName string
	handler     RecvDebugRequestHandler
	Mux         sync.Mutex
	buf         edgeproto.DebugRequest
	RecvCount   uint64
	sendrecv    *SendRecv
}

func NewDebugRequestRecv(handler RecvDebugRequestHandler) *DebugRequestRecv {
	recv := &DebugRequestRecv{}
	recv.Name = "DebugRequest"
	recv.MessageName = proto.MessageName((*edgeproto.DebugRequest)(nil))
	recv.handler = handler
	return recv
}

func (s *DebugRequestRecv) SetSendRecv(sendrecv *SendRecv) {
	s.sendrecv = sendrecv
}

func (s *DebugRequestRecv) GetMessageName() string {
	return s.MessageName
}

func (s *DebugRequestRecv) GetName() string {
	return s.Name
}

func (s *DebugRequestRecv) GetRecvCount() uint64 {
	return s.RecvCount
}

func (s *DebugRequestRecv) Recv(ctx context.Context, notice *edgeproto.Notice, notifyId int64, peerAddr string) {
	span := opentracing.SpanFromContext(ctx)
	if span != nil {
		span.SetTag("objtype", "DebugRequest")
	}

	buf := &edgeproto.DebugRequest{}
	err := types.UnmarshalAny(&notice.Any, buf)
	if err != nil {
		s.sendrecv.stats.UnmarshalErrors++
		log.SpanLog(ctx, log.DebugLevelNotify, "Unmarshal Error", "err", err)
		return
	}
	if span != nil {
		span.SetTag("msg", buf)
	}
	log.SpanLog(ctx, log.DebugLevelNotify,
		fmt.Sprintf("%s recv DebugRequest", s.sendrecv.cliserv),
		"peerAddr", peerAddr,
		"peer", s.sendrecv.peer,
		"local", s.sendrecv.name,
		"message", buf)
	s.handler.RecvDebugRequest(ctx, buf)
	s.sendrecv.stats.Recv++
	// object specific counter
	s.RecvCount++
}

func (s *DebugRequestRecv) RecvAllStart() {
}

func (s *DebugRequestRecv) RecvAllEnd(ctx context.Context, cleanup Cleanup) {
}

type DebugRequestRecvMany struct {
	handler RecvDebugRequestHandler
}

func NewDebugRequestRecvMany(handler RecvDebugRequestHandler) *DebugRequestRecvMany {
	s := &DebugRequestRecvMany{}
	s.handler = handler
	return s
}

func (s *DebugRequestRecvMany) NewRecv() NotifyRecv {
	recv := NewDebugRequestRecv(s.handler)
	return recv
}

func (s *DebugRequestRecvMany) Flush(ctx context.Context, notifyId int64) {
}

type RecvDebugReplyHandler interface {
	RecvDebugReply(ctx context.Context, msg *edgeproto.DebugReply)
}

type DebugReplySend struct {
	Name        string
	MessageName string
	Data        []*edgeproto.DebugReply
	dataToSend  []*edgeproto.DebugReply
	Ctxs        []context.Context
	ctxsToSend  []context.Context
	notifyId    int64
	Mux         sync.Mutex
	buf         edgeproto.DebugReply
	SendCount   uint64
	sendrecv    *SendRecv
}

type DebugReplySendContext struct {
	ctx         context.Context
	modRev      int64
	forceDelete bool
}

func NewDebugReplySend() *DebugReplySend {
	send := &DebugReplySend{}
	send.Name = "DebugReply"
	send.MessageName = proto.MessageName((*edgeproto.DebugReply)(nil))
	send.Data = make([]*edgeproto.DebugReply, 0)
	return send
}

func (s *DebugReplySend) SetSendRecv(sendrecv *SendRecv) {
	s.sendrecv = sendrecv
}

func (s *DebugReplySend) GetMessageName() string {
	return s.MessageName
}

func (s *DebugReplySend) GetName() string {
	return s.Name
}

func (s *DebugReplySend) GetSendCount() uint64 {
	return s.SendCount
}

func (s *DebugReplySend) GetNotifyId() int64 {
	return s.notifyId
}
func (s *DebugReplySend) UpdateAll(ctx context.Context) {}

func (s *DebugReplySend) Update(ctx context.Context, msg *edgeproto.DebugReply) bool {
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

func (s *DebugReplySend) SendForCloudlet(ctx context.Context, action edgeproto.NoticeAction, cloudlet *edgeproto.Cloudlet) {
}

func (s *DebugReplySend) Send(stream StreamNotify, notice *edgeproto.Notice, peer string) error {
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

func (s *DebugReplySend) PrepData() bool {
	s.Mux.Lock()
	defer s.Mux.Unlock()
	if len(s.Data) > 0 {
		s.dataToSend = s.Data
		s.Data = make([]*edgeproto.DebugReply, 0)
		s.ctxsToSend = s.Ctxs
		s.Ctxs = make([]context.Context, 0)
		return true
	}
	return false
}

// Server accepts multiple clients so needs to track multiple
// peers to send to.
type DebugReplySendMany struct {
	Mux   sync.Mutex
	sends map[string]*DebugReplySend
}

func NewDebugReplySendMany() *DebugReplySendMany {
	s := &DebugReplySendMany{}
	s.sends = make(map[string]*DebugReplySend)
	return s
}

func (s *DebugReplySendMany) NewSend(peerAddr string, notifyId int64) NotifySend {
	send := NewDebugReplySend()
	send.notifyId = notifyId
	s.Mux.Lock()
	s.sends[peerAddr] = send
	s.Mux.Unlock()
	return send
}

func (s *DebugReplySendMany) DoneSend(peerAddr string, send NotifySend) {
	asend, ok := send.(*DebugReplySend)
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
func (s *DebugReplySendMany) Update(ctx context.Context, msg *edgeproto.DebugReply) int {
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

func (s *DebugReplySendMany) UpdateFiltered(ctx context.Context, msg *edgeproto.DebugReply, sendOk func(ctx context.Context, send *DebugReplySend, msg *edgeproto.DebugReply) bool) int {
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

func (s *DebugReplySendMany) GetTypeString() string {
	return "DebugReply"
}

type DebugReplyRecv struct {
	Name        string
	MessageName string
	handler     RecvDebugReplyHandler
	Mux         sync.Mutex
	buf         edgeproto.DebugReply
	RecvCount   uint64
	sendrecv    *SendRecv
}

func NewDebugReplyRecv(handler RecvDebugReplyHandler) *DebugReplyRecv {
	recv := &DebugReplyRecv{}
	recv.Name = "DebugReply"
	recv.MessageName = proto.MessageName((*edgeproto.DebugReply)(nil))
	recv.handler = handler
	return recv
}

func (s *DebugReplyRecv) SetSendRecv(sendrecv *SendRecv) {
	s.sendrecv = sendrecv
}

func (s *DebugReplyRecv) GetMessageName() string {
	return s.MessageName
}

func (s *DebugReplyRecv) GetName() string {
	return s.Name
}

func (s *DebugReplyRecv) GetRecvCount() uint64 {
	return s.RecvCount
}

func (s *DebugReplyRecv) Recv(ctx context.Context, notice *edgeproto.Notice, notifyId int64, peerAddr string) {

	buf := &edgeproto.DebugReply{}
	err := types.UnmarshalAny(&notice.Any, buf)
	if err != nil {
		s.sendrecv.stats.UnmarshalErrors++
		return
	}
	s.handler.RecvDebugReply(ctx, buf)
	s.sendrecv.stats.Recv++
	// object specific counter
	s.RecvCount++
}

func (s *DebugReplyRecv) RecvAllStart() {
}

func (s *DebugReplyRecv) RecvAllEnd(ctx context.Context, cleanup Cleanup) {
}

type DebugReplyRecvMany struct {
	handler RecvDebugReplyHandler
}

func NewDebugReplyRecvMany(handler RecvDebugReplyHandler) *DebugReplyRecvMany {
	s := &DebugReplyRecvMany{}
	s.handler = handler
	return s
}

func (s *DebugReplyRecvMany) NewRecv() NotifyRecv {
	recv := NewDebugReplyRecv(s.handler)
	return recv
}

func (s *DebugReplyRecvMany) Flush(ctx context.Context, notifyId int64) {
}
