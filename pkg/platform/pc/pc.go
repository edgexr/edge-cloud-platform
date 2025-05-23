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
	"bytes"
	"context"
	"encoding/base64"
	"fmt"
	"io"
	"os"
	"runtime"
	"strings"
	"time"

	"github.com/edgexr/edge-cloud-platform/pkg/cloudcommon"
	"github.com/edgexr/edge-cloud-platform/pkg/log"
	ssh "github.com/edgexr/golang-ssh"
	gonanoid "github.com/matoous/go-nanoid/v2"
)

// Sudo is a toggle for executing as superuser
type Sudo bool

// SudoOn means run in sudo mode
var SudoOn Sudo = true

// NoSudo means dont run in sudo mode
var NoSudo Sudo = false

// OverwriteDir is a toggle to indicate overwrite during dir creation
type OverwriteDir bool

var Overwrite OverwriteDir = true
var NoOverwrite OverwriteDir = false

type SSHOptions struct {
	Timeout  time.Duration
	User     string
	CachedIP bool
}

type WriteFileOptions struct {
	Perms *os.FileMode
}

type WriteFileOp func(opts *WriteFileOptions)

func WithFilePerms(perms os.FileMode) WriteFileOp {
	return func(opts *WriteFileOptions) { opts.Perms = &perms }
}

// Most of the systems have a limit of 128KB for arg size
// But since we encode our data to base64, leave some room for
// command name and other arguments, everything except data.
// Hence 8KB is left out: 128 - 8 = 120 KB
var minDataArgLimitBytes = (120 * 1024)

// Some utility functions

// WriteFile writes the file contents optionally in sudo mode
func WriteFile(client ssh.Client, file string, contents string, kind string, sudo Sudo, ops ...WriteFileOp) error {
	opts := &WriteFileOptions{}
	for _, op := range ops {
		op(opts)
	}

	log.DebugLog(log.DebugLevelInfra, "write file", "kind", kind, "sudo", sudo, "opts", opts)

	// encode to avoid issues with quotes, special characters, and shell
	// evaluation of $vars.
	dat := base64.StdEncoding.EncodeToString([]byte(contents))

	var b64File string
	var err error
	if len(dat) > minDataArgLimitBytes {
		// data is more than min sys supported arg limit
		// split the data and store it in file and then decode it

		// open new file
		b64File, err = client.Output(fmt.Sprintf("mktemp %s-XXXXXX", file))
		if err != nil {
			return fmt.Errorf("failed to create temp file: %s, %v", b64File, err)
		}
		defer func() {
			// cleanup temp file created, ignore err
			client.Output(fmt.Sprintf("rm %s", b64File))
		}()
		ii := 0
		for count := len(dat); count > 0; {
			var datSlice string
			if count > minDataArgLimitBytes {
				datSlice = dat[ii : ii+minDataArgLimitBytes]
				count -= minDataArgLimitBytes
				ii += minDataArgLimitBytes
			} else {
				datSlice = dat[ii : ii+count]
				count = 0
			}
			// write encoded data to temp file
			out, err := client.Output(fmt.Sprintf("echo -n '%s' >> %s", datSlice, b64File))
			if err != nil {
				return fmt.Errorf("failed to write '%s' to temp file: %s, %s, %v", datSlice, b64File, out, err)
			}
		}
	}

	// On a mac base64 command "-d" option is "-D"
	// If we are running on a mac and we are trying to run base64 decode replace "-d" with "-D"
	decodeCmd := "base64 -d"
	if runtime.GOOS == "darwin" {
		if _, isLocalClient := client.(*LocalClient); isLocalClient {
			decodeCmd = "base64 -D"
		}
	}
	cmd := ""
	if b64File != "" {
		cmd = fmt.Sprintf("cat %s | %s > %s", b64File, decodeCmd, file)
	} else {
		cmd = fmt.Sprintf("%s <<< %s > %s", decodeCmd, dat, file)
	}
	if sudo {
		cmd = fmt.Sprintf("sudo bash -c '%s'", cmd)
	}
	out, err := client.Output(cmd)
	if err != nil {
		return fmt.Errorf("error writing %s, %s, %s, %v", kind, cmd, out, err)
	}
	if opts.Perms != nil {
		cmd = fmt.Sprintf("chmod %#o %s", *opts.Perms, file)
		if sudo {
			cmd = fmt.Sprintf("sudo bash -c '%s'", cmd)
		}
		out, err := client.Output(cmd)
		if err != nil {
			return fmt.Errorf("error setting permissions on file %s, %s, %s, %v", file, cmd, out, err)
		}
	}
	log.DebugLog(log.DebugLevelInfra, "wrote file", "kind", kind)
	return nil
}

func ReadFile(ctx context.Context, client ssh.Client, filename string, sudo Sudo) (string, error) {
	su := ""
	if sudo {
		su = "sudo "
	}
	cmd := fmt.Sprintf("%scat %s", su, filename)
	out, err := client.Output(cmd)
	if err != nil && strings.Contains(out, "No such file or directory") {
		return "", os.ErrNotExist
	}
	if err != nil {
		return "", fmt.Errorf("failed to read file %s, %s", filename, err)
	}
	return out, nil
}

func CreateDir(ctx context.Context, client ssh.Client, dir string, ow OverwriteDir, sudo Sudo) error {
	mkdirCmd := fmt.Sprintf("mkdir %s", dir)
	if sudo {
		mkdirCmd = fmt.Sprintf("sudo mkdir %s", dir)
	}
	output, err := client.Output(mkdirCmd)
	if err == nil {
		return nil
	}
	if !strings.Contains(output, "File exists") {
		log.SpanLog(ctx, log.DebugLevelInfra, "mkdir err", "out", output, "err", err)
		return err
	}

	if !ow {
		return nil
	}

	// If overwrite, then try deleting the directory and recreate it
	err = DeleteDir(ctx, client, dir, sudo)
	if err != nil {
		delerr := fmt.Errorf("unable to delete already existing directory: %v", err)
		log.SpanLog(ctx, log.DebugLevelInfra, "rmdir err", "err", delerr)
		return err
	}
	output, err = client.Output(mkdirCmd)
	if err != nil {
		log.SpanLog(ctx, log.DebugLevelInfra, "mkdir err", "out", output, "err", err)
		return err
	}
	return nil
}

func DeleteDir(ctx context.Context, client ssh.Client, dir string, sudo Sudo) error {
	log.SpanLog(ctx, log.DebugLevelInfra, "deleting directory", "dir", dir)
	cmd := fmt.Sprintf("rm -rf %s", dir)
	if sudo == SudoOn {
		cmd = fmt.Sprintf("sudo rm -rf %s", dir)
	}
	out, err := client.Output(cmd)
	if err != nil {
		return fmt.Errorf("error deleting dir %s, %s, %v", cmd, out, err)
	}
	return nil
}

func DeleteFile(client ssh.Client, file string, sudo Sudo) error {
	log.DebugLog(log.DebugLevelInfra, "delete file")
	cmd := fmt.Sprintf("rm -f %s", file)
	if sudo == SudoOn {
		cmd = fmt.Sprintf("sudo rm -f %s", file)
	}
	out, err := client.Output(cmd)
	if err != nil {
		return fmt.Errorf("error deleting  %s, %s, %v", cmd, out, err)
	}
	log.DebugLog(log.DebugLevelInfra, "deleted file", "file", file)
	return nil
}

func CopyFile(client ssh.Client, src, dst string) error {
	cmd := fmt.Sprintf("cp %s %s", src, dst)
	out, err := client.Output(cmd)
	if err != nil {
		log.DebugLog(log.DebugLevelInfra, "copy failed", "src", src, "dst", dst, "err", err, "out", out)
	}
	return err
}

func Run(client ssh.Client, cmd string) error {
	out, err := client.Output(cmd)
	if err != nil {
		log.DebugLog(log.DebugLevelInfra, "cmd failed", "cmd", cmd, "err", err, "out", out)
		return fmt.Errorf("command \"%s\" failed, %v", cmd, err)
	}
	return nil
}

const runSafeScript = `import subprocess
import base64
import sys

args = [
%s]
p = subprocess.run(["%s"] + args)
sys.exit(p.returncode)
`

func writeSafeScript(client ssh.Client, cmd string, args []string) (string, error) {
	buf := bytes.Buffer{}
	for _, arg := range args {
		if strings.IndexByte(arg, '"') == -1 {
			// no quotes, safe to add as quoted string
			buf.WriteString("\"" + arg + "\",\n")
			continue
		}
		// Has quote(s). To be super safe, base64 encode.
		encArg := base64.StdEncoding.EncodeToString([]byte(arg))
		buf.WriteString("base64.b64decode(\"")
		buf.WriteString(encArg)
		buf.WriteString("\"), # ")
		buf.WriteString(arg)
		buf.WriteString("\n")
	}
	// Write python script to run command and args. Running from
	// python instead of shell avoids shell interpretation of
	// environment variables and special characters like semicolon,
	// pipe, and redirects that may be have been supplied by the user
	// in their args.
	id := gonanoid.MustGenerate(cloudcommon.IdAlphabet, 6)
	cmdFile := cmd + "-cmd-" + id
	cmdFileContents := fmt.Sprintf(runSafeScript, buf.String(), cmd)
	err := WriteFile(client, cmdFile, cmdFileContents, "python script", NoSudo)
	if err != nil {
		return "", err
	}
	return cmdFile, nil
}

// RunSafeShell behaves like client.Shell(), but assumes that args
// may come from user-input, and may intentionally be trying to
// compromise the security of the system. The ssh remote command
// always runs in the context of a shell, and therefore user
// args may try to take advantage of shell interpolation of
// injected commands, pipes, redirects, and evaluation of ssh shell
// environment variables. To avoid this, RunSafeShell writes the
// args to a file, and runs the cmd binary without shell
// interpretation of the arguments. It is assumed that cmd is
// not from user-supplied input, and is well-formed and trusted.
func RunSafeShell(client ssh.Client, sin io.Reader, sout, serr io.Writer, cmd string, args []string) error {
	if len(args) == 0 {
		// cmd is considered safe, so just run it directly
		return client.Shell(sin, sout, serr, cmd)
	}
	cmdFile, err := writeSafeScript(client, cmd, args)
	if err != nil {
		return err
	}
	defer DeleteFile(client, cmdFile, NoSudo)
	return client.Shell(sin, sout, serr, "python3 "+cmdFile)
}

// RunSafeOutput behaves like client.Output(), but assumes args may
// come from user-input and may be malicious. See RunSafeShell().
func RunSafeOutput(client ssh.Client, cmd string, args []string) (string, error) {
	if len(args) == 0 {
		// cmd is considered safe, so just run it directly
		return client.Output(cmd)
	}
	cmdFile, err := writeSafeScript(client, cmd, args)
	if err != nil {
		return "", err
	}
	//defer DeleteFile(client, cmdFile, NoSudo)
	return client.Output("python3 " + cmdFile)
}

type SSHClientOp func(sshp *SSHOptions)

func (o *SSHOptions) Apply(ops []SSHClientOp) {
	for _, op := range ops {
		op(o)
	}
}
func WithUser(user string) SSHClientOp {
	return func(op *SSHOptions) {
		op.User = user
	}
}
func WithTimeout(timeout time.Duration) SSHClientOp {
	return func(op *SSHOptions) {
		op.Timeout = timeout
	}
}
func WithCachedIp(cached bool) SSHClientOp {
	return func(op *SSHOptions) {
		op.CachedIP = cached
	}
}
