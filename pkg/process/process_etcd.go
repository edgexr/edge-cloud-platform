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
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
)

type Etcd struct {
	Common         `yaml:",inline"`
	DataDir        string
	PeerAddrs      string
	ClientAddrs    string
	InitialCluster string
	cmd            *exec.Cmd
}

var EtcdRamDiskSizeVar = "ETCD_RAMDISK_SIZEG"
var RamDisk = "ramdisk"
var MaxRamDiskSizeG = 3.0

func (p *Etcd) StartLocal(logfile string, opts ...StartOp) error {
	etcdRamDiskSizeG := os.Getenv(EtcdRamDiskSizeVar)
	if runtime.GOOS == "darwin" && etcdRamDiskSizeG != "" {
		// macos specific
		dir := "/Volumes/" + RamDisk
		_, err := os.Stat(dir)
		if os.IsNotExist(err) {
			// create ram disk
			size, err := strconv.ParseFloat(etcdRamDiskSizeG, 32)
			if err != nil {
				return fmt.Errorf("Failed to convert %s value %s to float: %v", EtcdRamDiskSizeVar, etcdRamDiskSizeG, err)
			}
			// prevent the user from killing their machine
			if size > MaxRamDiskSizeG {
				return fmt.Errorf("RAM disk sizes larger than %fG not allowed to avoid killing your machine", MaxRamDiskSizeG)
			}
			// create device
			args := []string{"hdiutil", "attach", "-nomount",
				fmt.Sprintf("ram://%d", uint(size*2097152))}
			log.Printf("Creating ramdisk: %s\n", strings.Join(args, " "))
			out, err := exec.Command(args[0], args[1:]...).CombinedOutput()
			if err != nil {
				return fmt.Errorf("Failed to create ramdisk: %s: %s, %v", strings.Join(args, " "), string(out), err)
			}
			diskID := string(out)
			eraseCmd := fmt.Sprintf("diskutil erasevolume HFS+ %s %s", RamDisk, diskID)
			log.Printf("Formatting ramdisk: %s\n", eraseCmd)
			out, err = exec.Command("bash", "-c", eraseCmd).CombinedOutput()
			if err != nil {
				return fmt.Errorf("Failed to clear ramdisk: %s: %s, %v", strings.Join(args, " "), string(out), err)
			}
		}
		base := filepath.Base(p.DataDir)
		p.DataDir = dir + "/" + base
		log.Printf("Using ramdisk for etcd %s storage: %s\n", p.Name, p.DataDir)
	}

	options := StartOptions{}
	options.ApplyStartOptions(opts...)
	if options.CleanStartup {
		if err := p.ResetData(); err != nil {
			return err
		}
	}

	args := []string{"--name", p.Name, "--data-dir", p.DataDir, "--listen-peer-urls", p.PeerAddrs, "--listen-client-urls", p.ClientAddrs, "--advertise-client-urls", p.ClientAddrs, "--initial-advertise-peer-urls", p.PeerAddrs, "--initial-cluster", p.InitialCluster}

	var err error
	p.cmd, err = StartLocal(p.Name, p.GetExeName(), args, p.GetEnv(), logfile)
	return err
}

func (p *Etcd) StopLocal() {
	StopLocal(p.cmd)
}

func (p *Etcd) GetExeName() string { return "etcd" }

func (p *Etcd) LookupArgs() string { return "--name " + p.Name }

func (p *Etcd) GetBindAddrs() []string {
	addrs := []string{}
	addrs = append(addrs, strings.Split(p.PeerAddrs, ",")...)
	addrs = append(addrs, strings.Split(p.ClientAddrs, ",")...)
	return addrs
}

func (p *Etcd) ResetData() error {
	return os.RemoveAll(p.DataDir)
}

// This should be called after etcd processes are stopped
func CleanupEtcdRamDisk() error {
	if runtime.GOOS == "darwin" {
		dir := "/Volumes/" + RamDisk
		_, err := os.Stat(dir)
		if os.IsNotExist(err) {
			return nil
		}
		log.Printf("Cleaning up RAM disk. Getting device ID...\n")
		args := []string{"bash", "-c", "diskutil list " + RamDisk}
		out, err := exec.Command(args[0], args[1:]...).CombinedOutput()
		if err != nil {
			return fmt.Errorf("Failed to get device ID for RAM disk: %s: %s, %v", strings.Join(args, " "), string(out), err)
		}
		outFields := strings.Fields(string(out))
		if len(outFields) < 1 {
			return fmt.Errorf("diskutil output device ID not found: %s", string(out))
		}
		diskID := outFields[0]
		log.Printf("Unmounting RAM disk %s\n", diskID)
		args = []string{"umount", "-f", diskID}
		out, err = exec.Command(args[0], args[1:]...).CombinedOutput()
		if err != nil {
			return fmt.Errorf("unmount etcd RAM disk failed: %s: %s, %v", strings.Join(args, " "), string(out), err)
		}
		log.Printf("Ejecting RAM disk %s\n", diskID)
		args = []string{"hdiutil", "detach", diskID}
		out, err = exec.Command(args[0], args[1:]...).CombinedOutput()
		if err != nil {
			return fmt.Errorf("delete etcd RAM disk failed: %s: %s, %v", strings.Join(args, " "), string(out), err)
		}
	}
	return nil
}
