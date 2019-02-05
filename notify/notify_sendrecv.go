package notify

// Sendrecv handles sending and receiving data streams.
// While the initial connection and negotiation between client and server
// is asymmetric, after that send and recv streams behave the
// same regardless if the node is a client or server.
// Sendrecv code handles this common send/recv logic.

import (
	fmt "fmt"
	"sync"

	"github.com/gogo/protobuf/types"
	"github.com/mobiledgex/edge-cloud/edgeproto"
	"github.com/mobiledgex/edge-cloud/log"
	"google.golang.org/grpc"
)

// NotifySend is implemented by auto-generated code. That code
// is specific to the given object, but the interface is generic.
// The sendrecv code uses the generic interface to treat all
// objects equally.
type NotifySend interface {
	// Set the SendRecv owner
	SetSendRecv(s *SendRecv)
	// Get the proto message name
	GetMessageName() string
	// Get the object name (no package name)
	GetName() string
	// Get send count for object
	GetSendCount() uint64
	// Send the data
	Send(stream StreamNotify, buf *edgeproto.Notice, peerAddr string) error
	// Return true if there are keys to send
	HasData() bool
	// Queue all cached data for send
	UpdateAll()
}

// NotifyRecv is implemented by auto-generated code. The same
// comment as for NotifySend applies here as well.
type NotifyRecv interface {
	// Set the SendRecv owner
	SetSendRecv(s *SendRecv)
	// Get the proto message name
	GetMessageName() string
	// Get the object name (no package name)
	GetName() string
	// Get recv count for object
	GetRecvCount() uint64
	// Recieve the data
	Recv(notice *edgeproto.Notice, notifyId int64, peerAddr string)
	// Start receiving a send all
	RecvAllStart()
	// End receiving a send all
	RecvAllEnd()
}

type StreamNotify interface {
	Send(*edgeproto.Notice) error
	Recv() (*edgeproto.Notice, error)
	grpc.Stream
}

type Stats struct {
	Tries           uint64
	Connects        uint64
	NegotiateErrors uint64
	SendAll         uint64
	Send            uint64
	Recv            uint64
	RecvErrors      uint64
	SendErrors      uint64
	MarshalErrors   uint64
	UnmarshalErrors uint64
	ObjSend         map[string]uint64
	ObjRecv         map[string]uint64
}

type SendRecv struct {
	cliserv            string // client or server
	peerAddr           string
	sendlist           []NotifySend
	recvmap            map[string]NotifyRecv
	started            bool
	done               bool
	localWanted        []string
	remoteWanted       map[string]struct{}
	filterCloudletKeys bool
	cloudletKeys       map[edgeproto.CloudletKey]struct{}
	appSend            *AppSend
	cloudletSend       *CloudletSend
	clusterInstSend    *ClusterInstSend
	appInstSend        *AppInstSend
	sendRunning        chan struct{}
	recvRunning        chan struct{}
	signal             chan bool
	stats              Stats
	mux                sync.Mutex
}

func (s *SendRecv) init(cliserv string) {
	s.cliserv = cliserv
	s.sendlist = make([]NotifySend, 0)
	s.recvmap = make(map[string]NotifyRecv)
	s.localWanted = []string{}
	s.remoteWanted = make(map[string]struct{})
	s.cloudletKeys = make(map[edgeproto.CloudletKey]struct{})
	s.signal = make(chan bool, 1)
}

func (s *SendRecv) registerSend(send NotifySend) {
	s.mux.Lock()
	defer s.mux.Unlock()
	if s.started {
		log.FatalLog("Must register before starting")
	}
	s.sendlist = append(s.sendlist, send)
	send.SetSendRecv(s)
	// track some specific sends for cloudlet key filtering
	switch v := send.(type) {
	case *AppSend:
		s.appSend = v
	case *CloudletSend:
		s.cloudletSend = v
	case *ClusterInstSend:
		s.clusterInstSend = v
	case *AppInstSend:
		s.appInstSend = v
	}
}

func (s *SendRecv) registerRecv(recv NotifyRecv) {
	s.mux.Lock()
	defer s.mux.Unlock()
	if s.started {
		log.FatalLog("Must register before starting")
	}
	s.recvmap[recv.GetMessageName()] = recv
	s.localWanted = append(s.localWanted, recv.GetMessageName())
	recv.SetSendRecv(s)
}

func (s *SendRecv) setRemoteWanted(names []string) {
	s.mux.Lock()
	defer s.mux.Unlock()
	for _, name := range names {
		s.remoteWanted[name] = struct{}{}
	}
}

func (s *SendRecv) isRemoteWanted(name string) bool {
	s.mux.Lock()
	defer s.mux.Unlock()
	_, found := s.remoteWanted[name]
	return found
}

func (s *SendRecv) send(stream StreamNotify) {
	var err error
	var notice edgeproto.Notice

	sendAll := true
	// trigger initial sendAll
	s.wakeup()
	streamDone := false

	for !s.done && err == nil {
		// Select with channels is used here rather than a condition
		// variable to be able to detect when the underlying connection
		// is done/cancelled, as the only way to detect that is via a
		// channel, and you can't mix waiting on condition variables
		// and channels.
		select {
		case <-s.signal:
		case <-stream.Context().Done():
			err = stream.Context().Err()
			streamDone = true
		}
		if streamDone {
			break
		}
		s.mux.Lock()
		hasData := false
		for _, send := range s.sendlist {
			if send.HasData() {
				hasData = true
				break
			}
		}
		if !hasData && !s.done && !sendAll {
			s.mux.Unlock()
			continue
		}
		s.mux.Unlock()
		if s.done {
			break
		}
		if sendAll {
			log.DebugLog(log.DebugLevelNotify,
				fmt.Sprintf("%s send all", s.cliserv),
				"peer", s.peerAddr)
			s.stats.SendAll++
		}
		// Note that order is important here, as some objects
		// may have dependencies on other objects. It's up to the
		// caller to make sure CacheSend objects are registered
		// in the desired send order.
		for _, send := range s.sendlist {
			if sendAll {
				send.UpdateAll()
			}
			err = send.Send(stream, &notice, s.peerAddr)
			if err != nil {
				break
			}
		}
		if err != nil {
			break
		}
		if sendAll {
			notice.Action = edgeproto.NoticeAction_SENDALL_END
			notice.Any = types.Any{}
			err = stream.Send(&notice)
			if err != nil {
				log.DebugLog(log.DebugLevelNotify,
					fmt.Sprintf("%s send all end", s.cliserv),
					"peer", s.peerAddr,
					"err", err)
				break
			}
			sendAll = false
		}
		if err != nil {
			break
		}
	}
	close(s.sendRunning)
}

func (s *SendRecv) recv(stream StreamNotify, notifyId int64) {
	recvAll := true
	for _, recv := range s.recvmap {
		recv.RecvAllStart()
	}
	for !s.done {
		notice, err := stream.Recv()
		if s.done {
			break
		}
		if err != nil {
			log.DebugLog(log.DebugLevelNotify,
				fmt.Sprintf("%s receive", s.cliserv), "err", err)
			break
		}
		name, err := types.AnyMessageName(&notice.Any)
		if err != nil && notice.Action != edgeproto.NoticeAction_SENDALL_END {
			log.DebugLog(log.DebugLevelNotify,
				fmt.Sprintf("%s receive", s.cliserv),
				"peer", s.peerAddr,
				"notice", notice, "err", err)
			continue
		}
		if recvAll && notice.Action == edgeproto.NoticeAction_SENDALL_END {
			for _, recv := range s.recvmap {
				recv.RecvAllEnd()
			}
			recvAll = false
			continue
		}
		recv := s.recvmap[name]
		if recv != nil {
			recv.Recv(notice, notifyId, s.peerAddr)
		} else {
			log.DebugLog(log.DebugLevelNotify,
				fmt.Sprintf("%s recv unhandled", s.cliserv),
				"peer", s.peerAddr,
				"action", notice.Action,
				"name", name)
		}
	}
	close(s.recvRunning)
}

func (s *SendRecv) wakeup() {
	// This puts true in the channel unless it is full,
	// then the default (noop) case is performed.
	// The signal channel is used to tell the thread to run.
	// It is a replacement for a condition variable, which
	// we cannot use (see comments in Server send())
	select {
	case s.signal <- true:
	default:
	}
}

func (s *SendRecv) hasCloudletKey(key *edgeproto.CloudletKey) bool {
	s.mux.Lock()
	defer s.mux.Unlock()
	_, found := s.cloudletKeys[*key]
	return found
}

func (s *SendRecv) setObjStats(stats *Stats) {
	stats.ObjSend = make(map[string]uint64)
	stats.ObjRecv = make(map[string]uint64)
	for _, send := range s.sendlist {
		stats.ObjSend[send.GetName()] = send.GetSendCount()
	}
	for _, recv := range s.recvmap {
		stats.ObjRecv[recv.GetName()] = recv.GetRecvCount()
	}
}