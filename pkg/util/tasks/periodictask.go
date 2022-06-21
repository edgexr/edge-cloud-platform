package tasks

import (
	"context"
	"sync"
	"time"

	"github.com/edgexr/edge-cloud-platform/pkg/log"
	"github.com/opentracing/opentracing-go"
)

// PeriodicTask is a task that continuously runs at a set time
// interval. This is a controller for a persistent go routine
// that runs a task periodically or on demand.
type PeriodicTaskable interface {
	// Task function to run
	Run(ctx context.Context)
	// Interval between runs (changes do not apply until the next iteration)
	GetInterval() time.Duration
	// Starts a span for the task
	StartSpan() opentracing.Span
}

// Cancels the periodic task after it's been started
//type CancelPeriodicTask func()

// Allows to wakeup the task and run it immediately
//type WakeupPeriodicTask func()

type PeriodicTask struct {
	task    PeriodicTaskable
	running bool
	stop    chan bool
	wakeup  chan bool
	mux     sync.Mutex
	wait    sync.WaitGroup
}

func NewPeriodicTask(task PeriodicTaskable) *PeriodicTask {
	p := PeriodicTask{}
	p.stop = make(chan bool, 1)
	p.wakeup = make(chan bool, 1)
	p.task = task
	return &p
}

func (s *PeriodicTask) Start() {
	s.mux.Lock()
	defer s.mux.Unlock()
	if s.running {
		return
	}
	s.running = true
	s.wait.Add(1)
	go func() {
		defer s.wait.Done()
		for {
			interval := s.task.GetInterval()
			select {
			case <-s.wakeup:
			case <-time.After(interval):
			case <-s.stop:
				return
			}
			span := s.task.StartSpan()
			ctx := log.ContextWithSpan(context.Background(), span)
			s.task.Run(ctx)
			span.Finish()
		}
	}()
}

func (s *PeriodicTask) Stop() {
	s.mux.Lock()
	defer s.mux.Unlock()
	if !s.running {
		return
	}
	s.stop <- true
	s.wait.Wait()
	s.running = false
}

func (s *PeriodicTask) Wakeup() {
	select {
	case s.wakeup <- true:
	default:
	}
}

/*
func RunPeriodicTask(p PeriodicTask) (CancelPeriodicTask, WakeupPeriodicTask) {
	stop := make(chan struct{})
	trigger := make(chan bool, 1)
	wait := sync.WaitGroup{}
	cancel := func() {
		close(stop)
		wait.Wait()
	}
	wakeup := func() {
		select {
		case trigger <- true:
		default:
		}
	}
	wait.Add(1)
	go func() {
		defer wait.Done()
		for {
			interval := p.GetInterval()
			select {
			case <-trigger:
			case <-time.After(interval):
			case <-stop:
				return
			}
			span := p.StartSpan()
			ctx := log.ContextWithSpan(context.Background(), span)
			p.Run(ctx)
			span.Finish()
		}
	}()
	return cancel, wakeup
}
*/
