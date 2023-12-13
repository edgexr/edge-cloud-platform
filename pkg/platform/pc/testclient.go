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
