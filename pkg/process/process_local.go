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

package process

import (
	"bytes"
	"fmt"
	"io"
	"log"
	"os"
	"os/exec"
	"strings"
	"sync"

	ct "github.com/daviddengcn/go-colortext"
)

// Local processes all run in the same global namespace, using different
// tcp ports to communicate with each other.

func StartLocal(name, bin string, args, envs []string, logfile string) (*exec.Cmd, error) {
	log.Printf("StartLocal:\n%s %s\n", bin, strings.Join(args, " "))
	cmd := exec.Command(bin, args...)
	if len(envs) > 0 {
		log.Printf("%s env: %v\n", name, envs)
		// Append to the current process's env
		cmd.Env = os.Environ()
		cmd.Env = append(cmd.Env, envs...)
	}
	if logfile == "" {
		writer := NewColorWriter(name)
		cmd.Stdout = writer
		cmd.Stderr = writer
	} else {
		fmt.Printf("Creating logfile %v\n", logfile)
		// open the out file for writing
		outfile, err := os.OpenFile(logfile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0666)
		if err != nil {
			fmt.Printf("ERROR Creating logfile %v -- %v\n", logfile, err)
			panic(err)
		}
		cmd.Stdout = outfile
		cmd.Stderr = outfile
	}

	err := cmd.Start()
	if err != nil {
		return nil, err
	}
	return cmd, nil
}

func StopLocal(cmd *exec.Cmd) {
	if cmd != nil {
		cmd.Process.Kill()
		cmd.Process.Wait()
	}
}

type ColorWriter struct {
	Name  string
	Color ct.Color
}

func (c *ColorWriter) Write(p []byte) (int, error) {
	buf := bytes.NewBuffer(p)
	printed := 0
	for {
		line, err := buf.ReadBytes('\n')
		if len(line) > 0 {
			ct.ChangeColor(c.Color, false, ct.None, false)
			fmt.Printf("%s : %s", c.Name, string(line))
			ct.ResetColor()
			printed += len(line)
		}
		if err != nil {
			if err != io.EOF {
				return printed, err
			}
			break
		}
	}
	return printed, nil
}

var nextColorIdx = 0
var nextColorMux sync.Mutex

var colors = []ct.Color{
	ct.Green,
	ct.Cyan,
	ct.Magenta,
	ct.Blue,
	ct.Red,
	ct.Yellow,
}

func NewColorWriter(name string) *ColorWriter {
	nextColorMux.Lock()
	color := colors[nextColorIdx]
	nextColorIdx++
	if nextColorIdx >= len(colors) {
		nextColorIdx = 0
	}
	nextColorMux.Unlock()

	writer := ColorWriter{
		Name:  name,
		Color: color,
	}
	return &writer
}
