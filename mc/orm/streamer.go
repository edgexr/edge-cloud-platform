package orm

import (
	"sync"
)

type Streamer struct {
	buffer []interface{}
	mux    sync.Mutex
	subs   map[chan interface{}]struct{}
}

type Streams map[interface{}]*Streamer

type StreamObj struct {
	streamMap Streams
	mux       sync.Mutex
}

func (sm *StreamObj) Get(in interface{}) *Streamer {
	sm.mux.Lock()
	defer sm.mux.Unlock()
	streamer, found := sm.streamMap[in]
	if found {
		return streamer
	}
	return nil
}

func (sm *StreamObj) Add(in interface{}, streamer *Streamer) {
	sm.mux.Lock()
	defer sm.mux.Unlock()
	if sm.streamMap == nil {
		sm.streamMap = Streams{in: streamer}
	} else {
		sm.streamMap[in] = streamer
	}
}

func (sm *StreamObj) Remove(in interface{}, streamer *Streamer) {
	sm.mux.Lock()
	defer sm.mux.Unlock()
	if streamerObj, ok := sm.streamMap[in]; ok {
		if streamerObj == streamer {
			delete(sm.streamMap, in)
		}
	}
}

func NewStreamer() *Streamer {
	return &Streamer{
		subs: make(map[chan interface{}]struct{}),
	}
}

func (s *Streamer) Stop() {
	s.mux.Lock()
	defer s.mux.Unlock()
	for msgCh := range s.subs {
		close(msgCh)
		delete(s.subs, msgCh)
	}
}

func (s *Streamer) Subscribe() chan interface{} {
	msgCh := make(chan interface{}, 20)

	s.mux.Lock()
	defer s.mux.Unlock()
	s.subs[msgCh] = struct{}{}
	// Send already streamed msgs to new subscriber
	for _, msg := range s.buffer {
		select {
		case msgCh <- msg:
		default:
		}
	}
	return msgCh
}

func (s *Streamer) Unsubscribe(msgCh chan interface{}) {
	s.mux.Lock()
	defer s.mux.Unlock()
	if _, ok := s.subs[msgCh]; ok {
		delete(s.subs, msgCh)
		close(msgCh)
	}
}

func (s *Streamer) Publish(msg interface{}) {
	// Buffer all the streamed messages till now,
	// so that a newly joined subscriber can get
	// complete list of messages
	s.mux.Lock()
	defer s.mux.Unlock()
	s.buffer = append(s.buffer, msg)
	for msgCh := range s.subs {
		select {
		case msgCh <- msg:
		default:
		}
	}
}
