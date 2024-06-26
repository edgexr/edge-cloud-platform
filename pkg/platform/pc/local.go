// Copyright 2022 MobiledgeX, Inc
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package pc

import (
	"fmt"
	"io"
	"os/exec"
	"sync"
	"time"

	"github.com/creack/pty"
	ssh "github.com/edgexr/golang-ssh"
)

// Implements nanobox-io's ssh.Client interface, but runs commands locally.
// This is used for kubernetes DIND or other local testing.
type LocalClient struct {
	cmd        *exec.Cmd
	WorkingDir string
}

// Output returns the output of the command run on the remote host.
func (s *LocalClient) Output(command string) (string, error) {
	cmd := exec.Command("bash", "-c", command)
	cmd.Dir = s.WorkingDir
	out, err := cmd.CombinedOutput()
	return string(out), err
}

// Shell requests a shell from the remote. If an arg is passed, it tries to
// exec them on the server.
func (s *LocalClient) Shell(sin io.Reader, sout, serr io.Writer, args ...string) error {
	args = append([]string{"-c"}, args...)
	cmd := exec.Command("/bin/sh", args...)
	cmd.Dir = s.WorkingDir
	tty, err := pty.Start(cmd)
	if err != nil {
		return err
	}
	defer tty.Close()

	// wait until all data has been written to avoid
	// race conditions between write back and caller closing
	// the connection.
	wg := sync.WaitGroup{}
	wg.Add(1)
	go func() {
		io.Copy(sout, tty)
		wg.Done()
	}()
	go func() {
		io.Copy(tty, sin)
	}()
	cmd.Wait()
	wg.Wait()
	return nil
}

// Start starts the specified command without waiting for it to finish. You
// have to call the Wait function for that.
//
// The first two io.ReadCloser are the standard output and the standard
// error of the executing command respectively. The returned error follows
// the same logic as in the exec.Cmd.Start function.
func (s *LocalClient) Start(command string) (io.ReadCloser, io.ReadCloser, io.WriteCloser, error) {
	cmd := exec.Command("sh", "-c", command)
	cmd.Dir = s.WorkingDir
	sout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, nil, nil, err
	}
	serr, err := cmd.StderrPipe()
	if err != nil {
		return nil, nil, nil, err
	}
	sin, err := cmd.StdinPipe()
	if err != nil {
		return nil, nil, nil, err
	}

	err = cmd.Start()
	if err != nil {
		return nil, nil, nil, err
	}
	s.cmd = cmd
	return sout, serr, sin, nil
}

// Wait waits for the command started by the Start function to exit. The
// returned error follows the same logic as in the exec.Cmd.Wait function.
func (s *LocalClient) Wait() error {
	if s.cmd == nil {
		return fmt.Errorf("no command started")
	}
	err := s.cmd.Wait()
	s.cmd = nil
	return err
}

// AddHop for LocalClient returns an unmodified LocalClient
func (s *LocalClient) AddHop(host string, port int) (ssh.Client, error) {
	return s, nil
}

// For local, timeout is irrelevant
func (s *LocalClient) OutputWithTimeout(command string, timeout time.Duration) (string, error) {
	return s.Output(command)
}

// No-op for local client
func (nc *LocalClient) StartPersistentConn(timeout time.Duration) error {
	return nil
}

// No-op for local client
func (nc *LocalClient) StopPersistentConn() {
}
