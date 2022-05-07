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
	"io/ioutil"
	"log"
)

type Alertmanager struct {
	DockerGeneric `yaml:",inline"`
	ConfigFile    string
	TemplateFile  string
	Port          int
}

func (p *Alertmanager) StartLocal(logfile string, opts ...StartOp) error {
	configFile := "/tmp/alertmanager.yml"
	templateFile := "/tmp/alertmanager.tmpl"
	if p.ConfigFile != "" {
		// Copy file from data dir to /tmp since it's going to be written to
		in, err := ioutil.ReadFile(p.ConfigFile)
		if err != nil {
			log.Printf("Failed to open alertmanager configuration file - %s\n", err.Error())
			return err
		}
		err = ioutil.WriteFile(configFile, in, 0644)
		if err != nil {
			log.Printf("Failed to copy alertmanager configuration file - %s\n", err.Error())
			return err
		}
	}
	if p.TemplateFile != "" {
		templateFile = p.TemplateFile
	}
	args := p.GetRunArgs()
	args = append(args,
		"-p", fmt.Sprintf("%d:%d", p.Port, p.Port),
		"-v", configFile+":/etc/prometheus/alertmanager.yml",
		"-v", templateFile+":/etc/alertmanager/templates/alertmanager.tmpl",
		"prom/alertmanager:v0.21.0",
		"--web.listen-address", fmt.Sprintf(":%d", p.Port),
		"--log.level", "debug",
		"--config.file", "/etc/prometheus/alertmanager.yml",
	)

	log.Printf("Start Alertmanager: %v\n", args)
	cmd, err := StartLocal(p.Name, p.GetExeName(), args, p.GetEnv(), logfile)
	p.SetCmd(cmd)
	return err
}
