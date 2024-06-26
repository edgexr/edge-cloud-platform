// Code generated by protoc-gen-gogo. DO NOT EDIT.
// source: metric.proto

package notify

import (
	"context"
	fmt "fmt"
	edgeproto "github.com/edgexr/edge-cloud-platform/api/edgeproto"
	"github.com/edgexr/edge-cloud-platform/pkg/log"
	_ "github.com/edgexr/edge-cloud-platform/tools/protogen"
	_ "github.com/gogo/protobuf/gogoproto"
	proto "github.com/gogo/protobuf/proto"
	"github.com/gogo/protobuf/types"
	_ "github.com/gogo/protobuf/types"
	math "math"
	"sync"
)

// Reference imports to suppress errors if they are not otherwise used.
var _ = proto.Marshal
var _ = fmt.Errorf
var _ = math.Inf

// Auto-generated code: DO NOT EDIT

type RecvMetricHandler interface {
	RecvMetric(ctx context.Context, msg *edgeproto.Metric)
}

type MetricSend struct {
	Name        string
	MessageName string
	Data        []*edgeproto.Metric
	dataToSend  []*edgeproto.Metric
	Ctxs        []context.Context
	ctxsToSend  []context.Context
	notifyId    int64
	Mux         sync.Mutex
	buf         edgeproto.Metric
	SendCount   uint64
	sendrecv    *SendRecv
}

type MetricSendContext struct {
	ctx         context.Context
	modRev      int64
	forceDelete bool
}

func NewMetricSend() *MetricSend {
	send := &MetricSend{}
	send.Name = "Metric"
	send.MessageName = proto.MessageName((*edgeproto.Metric)(nil))
	send.Data = make([]*edgeproto.Metric, 0)
	return send
}

func (s *MetricSend) SetSendRecv(sendrecv *SendRecv) {
	s.sendrecv = sendrecv
}

func (s *MetricSend) GetMessageName() string {
	return s.MessageName
}

func (s *MetricSend) GetName() string {
	return s.Name
}

func (s *MetricSend) GetSendCount() uint64 {
	return s.SendCount
}

func (s *MetricSend) GetNotifyId() int64 {
	return s.notifyId
}
func (s *MetricSend) UpdateAll(ctx context.Context) {}

func (s *MetricSend) Update(ctx context.Context, msg *edgeproto.Metric) bool {
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

func (s *MetricSend) SendForCloudlet(ctx context.Context, action edgeproto.NoticeAction, cloudlet *edgeproto.Cloudlet) {
}

func (s *MetricSend) Send(stream StreamNotify, notice *edgeproto.Notice, peer string) error {
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

func (s *MetricSend) PrepData() bool {
	s.Mux.Lock()
	defer s.Mux.Unlock()
	if len(s.Data) > 0 {
		s.dataToSend = s.Data
		s.Data = make([]*edgeproto.Metric, 0)
		s.ctxsToSend = s.Ctxs
		s.Ctxs = make([]context.Context, 0)
		return true
	}
	return false
}

// Server accepts multiple clients so needs to track multiple
// peers to send to.
type MetricSendMany struct {
	Mux   sync.Mutex
	sends map[string]*MetricSend
}

func NewMetricSendMany() *MetricSendMany {
	s := &MetricSendMany{}
	s.sends = make(map[string]*MetricSend)
	return s
}

func (s *MetricSendMany) NewSend(peerAddr string, notifyId int64) NotifySend {
	send := NewMetricSend()
	send.notifyId = notifyId
	s.Mux.Lock()
	s.sends[peerAddr] = send
	s.Mux.Unlock()
	return send
}

func (s *MetricSendMany) DoneSend(peerAddr string, send NotifySend) {
	asend, ok := send.(*MetricSend)
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
func (s *MetricSendMany) Update(ctx context.Context, msg *edgeproto.Metric) int {
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

func (s *MetricSendMany) UpdateFiltered(ctx context.Context, msg *edgeproto.Metric, sendOk func(ctx context.Context, send *MetricSend, msg *edgeproto.Metric) bool) int {
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

func (s *MetricSendMany) GetTypeString() string {
	return "Metric"
}

type MetricRecv struct {
	Name        string
	MessageName string
	handler     RecvMetricHandler
	Mux         sync.Mutex
	buf         edgeproto.Metric
	RecvCount   uint64
	sendrecv    *SendRecv
}

func NewMetricRecv(handler RecvMetricHandler) *MetricRecv {
	recv := &MetricRecv{}
	recv.Name = "Metric"
	recv.MessageName = proto.MessageName((*edgeproto.Metric)(nil))
	recv.handler = handler
	return recv
}

func (s *MetricRecv) SetSendRecv(sendrecv *SendRecv) {
	s.sendrecv = sendrecv
}

func (s *MetricRecv) GetMessageName() string {
	return s.MessageName
}

func (s *MetricRecv) GetName() string {
	return s.Name
}

func (s *MetricRecv) GetRecvCount() uint64 {
	return s.RecvCount
}

func (s *MetricRecv) Recv(ctx context.Context, notice *edgeproto.Notice, notifyId int64, peerAddr string) {

	buf := &edgeproto.Metric{}
	err := types.UnmarshalAny(&notice.Any, buf)
	if err != nil {
		s.sendrecv.stats.UnmarshalErrors++
		return
	}
	s.handler.RecvMetric(ctx, buf)
	s.sendrecv.stats.Recv++
	// object specific counter
	s.RecvCount++
}

func (s *MetricRecv) RecvAllStart() {
}

func (s *MetricRecv) RecvAllEnd(ctx context.Context, cleanup Cleanup) {
}

type MetricRecvMany struct {
	handler RecvMetricHandler
}

func NewMetricRecvMany(handler RecvMetricHandler) *MetricRecvMany {
	s := &MetricRecvMany{}
	s.handler = handler
	return s
}

func (s *MetricRecvMany) NewRecv() NotifyRecv {
	recv := NewMetricRecv(s.handler)
	return recv
}

func (s *MetricRecvMany) Flush(ctx context.Context, notifyId int64) {
}
