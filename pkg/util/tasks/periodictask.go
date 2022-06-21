package tasks

import (
	"context"
	"sync"
	"time"

	"github.com/edgexr/edge-cloud-platform/pkg/log"
	"github.com/opentracing/opentracing-go"
)

// PeriodicTask is a task manager that controls a go routine
// which periodically runs some task function. The task can be
// run on demand, or the manager can be stopped and restarted.
type PeriodicTask struct {
	task    PeriodicTaskable
	running bool
	stop    chan bool
	wakeup  chan bool
	mux     sync.Mutex
	wait    sync.WaitGroup
}

// PeriodicTaskable is a task that continuously runs at a set time
// interval. This informs the PeriodicTask when to run again, and
// what the span context should be for each run.
type PeriodicTaskable interface {
	// Task function to run
	Run(ctx context.Context)
	// Interval between runs (changes do not apply until the next iteration)
	GetInterval() time.Duration
	// Starts a span for the task
	StartSpan() opentracing.Span
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

// Wakeup causes the task to be run immediately
func (s *PeriodicTask) Wakeup() {
	select {
	case s.wakeup <- true:
	default:
	}
}
