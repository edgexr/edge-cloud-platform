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

package main

import (
	"encoding/json"
	"encoding/xml"
	"flag"
	"fmt"
	"io/ioutil"
	"os"
	"strings"
)

func main() {
	// default read from /var/log but use -ovf foo.txt to override
	ovfile := flag.String("ovf", "/var/log/userdata.log", "default ovfenv file")
	flag.Parse()
	// combined metada params and network_params?
	// This appears to be the current extent of options that
	// might be encountered today xxx
	envars := map[string]string{
		"ROLE":           "",
		"SKIPK8S":        "",
		"K8SMASTER":      "",
		"HOSTNAME":       "",
		"UPDATE":         "",
		"SKIPINIT":       "",
		"INTERFACE":      "",
		"UPDATEHOSTNAME": "",
		"IPADDR":         "",
		"NETMASK":        "",
		"NETTYPE":        "",
	}
	type EnvProperty struct {
		Key   string `xml:"key,attr"`
		Value string `xml:"value,attr"`
	}
	type PropertySection struct {
		Properties []EnvProperty `xml:"Property"`
	}
	type Environment struct {
		Property *PropertySection `xml:"PropertySection"`
	}
	info := Environment{}

	ovf, err := os.OpenFile(*ovfile, os.O_RDWR, 0755)
	if err != nil {
		fmt.Printf("Error reading file %s: %s\n", *ovfile, err.Error())
		return
	}
	defer ovf.Close()

	data, err := ioutil.ReadFile(*ovfile)
	if err != nil {
		fmt.Printf("ReadFile failed: %s\n", err.Error())
		os.Exit(-1)
	}

	err = xml.Unmarshal(data, &info)
	if err != nil {
		fmt.Printf("Error unmarshal: %s\n", err.Error())
		os.Exit(-1)
	}
	vars := make(map[string]interface{})
	for _, p := range info.Property.Properties {
		_, ok := envars[strings.ToUpper(p.Key)]
		if ok {
			vars[p.Key] = p.Value
		}
	}
	metadata := map[string]interface{}{
		"meta": vars,
	}
	out, err := json.Marshal(metadata)
	if err != nil {
		fmt.Printf("Error marshalling meta data %s\n", err.Error())
		os.Exit(-1)
	}
	fmt.Printf("%s", string(out))
}
