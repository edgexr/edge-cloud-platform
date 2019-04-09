package pc

import (
	"fmt"
	"io"

	"github.com/mobiledgex/edge-cloud/log"
)

// PlatformClient provides a way to run commands on the
// underlying platform. It is currently implemented by
// nanobox-io's ssh.Client, and LocalClient.
type PlatformClient interface {
	// Output returns the output of the command.
	Output(command string) (string, error)
	// Shell requests a shell. If an arg is passed, it tries
	// to exec them on the remote shell.
	Shell(args ...string) error
	// Start stars the specified command without waiting for
	// it to finish. Wait should be called to wait for it to finish.
	// The first two io.ReadCloser are the standard output and the standard
	// error of the executing command respectively. The returned error
	// follows the same logic as in the exec.Cmd.Start function.
	Start(command string) (io.ReadCloser, io.ReadCloser, error)
	// Wait waits for the command started by the Start function.
	// The returned error follows the same logic as exec.Cmd.Wait.
	Wait() error
}

// Some utility functions

func WriteFile(client PlatformClient, file string, contents string, kind string) error {
	log.DebugLog(log.DebugLevelMexos, "write file", "kind", kind)

	cmd := fmt.Sprintf("cat <<'EOF'> %s \n%s\nEOF", file, contents)
	out, err := client.Output(cmd)
	if err != nil {
		return fmt.Errorf("error writing %s, %s, %s, %v", kind, cmd, out, err)
	}
	log.DebugLog(log.DebugLevelMexos, "wrote file", "kind", kind)
	return nil
}

func CopyFile(client PlatformClient, src, dst string) error {
	cmd := fmt.Sprintf("cp %s %s", src, dst)
	out, err := client.Output(cmd)
	if err != nil {
		log.DebugLog(log.DebugLevelMexos, "copy failed", "src", src, "dst", dst, "err", err, "out", out)
	}
	return err
}