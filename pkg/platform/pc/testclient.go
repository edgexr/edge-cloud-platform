// Copyright 2024 EdgeXR, Inc
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package pc

import (
	"io"
	"time"

	ssh "github.com/edgexr/golang-ssh"
)

// TestClient is designed for unit tests to accumulate and
// check what commands were issues, and optionally provide
// responses to certain commands.
type TestClient struct {
	Cmds            []string
	OutputResponder func(cmd string) (string, error)
}

func (s *TestClient) Output(command string) (string, error) {
	s.Cmds = append(s.Cmds, command)
	if s.OutputResponder != nil {
		return s.OutputResponder(command)
	}
	return "", nil
}

func (s *TestClient) OutputWithTimeout(command string, Timeout time.Duration) (string, error) {
	return s.Output(command)
}

func (s *TestClient) Shell(sin io.Reader, sout, serr io.Writer, args ...string) error {
	return nil
}

func (s *TestClient) Start(command string) (io.ReadCloser, io.ReadCloser, io.WriteCloser, error) {
	s.Cmds = append(s.Cmds, command)
	return nil, nil, nil, nil
}

func (s *TestClient) Wait() error {
	return nil
}

func (s *TestClient) AddHop(host string, port int) (ssh.Client, error) {
	return s, nil
}

func (s *TestClient) StartPersistentConn(timeout time.Duration) error {
	return nil
}

func (s *TestClient) StopPersistentConn() {}
