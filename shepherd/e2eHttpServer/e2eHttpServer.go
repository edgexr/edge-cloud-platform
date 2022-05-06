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
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"strings"
	"text/template"

	e2esetup "github.com/edgexr/edge-cloud-infra/e2e-tests/e2e-setup"
	"gopkg.in/yaml.v2"
)

type ExporterStatsCollector struct {
	Prom Prometheus `yaml:"prometheus"`
}

type Prometheus struct {
	ClustCpu       int    `yaml:"clustCpu"`
	ClustCpuCores  int    `yaml:"clustCpuCores"`
	ClustMem       int    `yaml:"clustMem"`
	ClustMemTotal  int    `yaml:"clustMemTotal"`
	ClustDisk      int    `yaml:"clustDisk"`
	ClustDiskTotal int    `yaml:"clustDiskTotal"`
	TcpConn        int    `yaml:"tcpConn"`
	TcpRetrans     int    `yaml:"tcpRetrans"`
	UdpSent        int    `yaml:"udpSent"`
	UdpRecv        int    `yaml:"udpRecv"`
	UdpRecvErr     int    `yaml:"udpRecvErr"`
	AppCpu         int    `yaml:"appCpu"`
	AppMem         int    `yaml:"appMem"`
	AppDisk        int    `yaml:"appDisk"`
	NetSend        int    `yaml:"netSend"`
	NetRecv        int    `yaml:"netRecv"`
	AppName        string `yaml:"appName"`
	AppVersion     string `yaml:"appVersion"`
}

var promExportStr string
var promExportStrTemplate *template.Template
var promExportSetup = `# HELP node_netstat_Tcp_CurrEstab mimicking the TcpConns stat
# TYPE node_netstat_Tcp_CurrEstab untyped
node_netstat_Tcp_CurrEstab {{.TcpConn}}
# HELP node_netstat_Tcp_RetransSegs mimicking the TcpRetrans stat
# TYPE node_netstat_Tcp_RetransSegs untyped
node_netstat_Tcp_RetransSegs {{.TcpRetrans}}
# HELP node_netstat_Udp_InDatagrams mimicking the UdpRecv stat
# TYPE node_netstat_Udp_InDatagrams untyped
node_netstat_Udp_InDatagrams {{.UdpRecv}}
# HELP node_netstat_Udp_InErrors mimicking the UdpRecvErr stat
# TYPE node_netstat_Udp_InErrors untyped
node_netstat_Udp_InErrors {{.UdpRecvErr}}
# HELP node_netstat_Udp_OutDatagrams mimicking the UdpSent stat
# TYPE node_netstat_Udp_OutDatagrams untyped
node_netstat_Udp_OutDatagrams {{.UdpSent}}
# HELP container_cpu_usage_seconds_total Cumulative cpu time consumed in seconds. For mimicking the cpu metrics
# TYPE container_cpu_usage_seconds_total counter
container_cpu_usage_seconds_total{id="/",image="",pod=""} {{.ClustCpu}} 
container_cpu_usage_seconds_total{id="idNameThatsNotJustAForwardSlash",image="anythingButAnEmptyString",pod="{{.AppName}}"} {{.AppCpu}}
# HELP machine_cpu_cores Number of CPU cores on the machine. For mimicking cluster-cpu
# TYPE machine_cpu_cores gauge
machine_cpu_cores {{.ClustCpuCores}}
# HELP container_memory_working_set_bytes Current working set in bytes. For mimicking the mem metrics
# TYPE container_memory_working_set_bytes gauge
container_memory_working_set_bytes{id="/",image="",pod=""} {{.ClustMem}}
container_memory_working_set_bytes{id="idNameThatsNotJustAForwardSlash",image="anythingButAnEmptyString",pod="{{.AppName}}"} {{.AppMem}}
# HELP machine_memory_bytes Amount of memory installed on the machine. For mimicking cluster-mem
# TYPE machine_memory_bytes gauge
machine_memory_bytes {{.ClustMemTotal}}
# HELP container_fs_usage_bytes Number of bytes that are consumed by the container on this filesystem. For mimicking the disk metrics
# TYPE container_fs_usage_bytes gauge
container_fs_usage_bytes{device="/dev/sda1",id="/",image="",pod=""} {{.ClustDisk}}
container_fs_usage_bytes{device="",id="notAForwardSlash",image="notTheEmptyString",pod="{{.AppName}}"} {{.AppDisk}}
# HELP container_fs_limit_bytes Number of bytes that can be consumed by the container on this filesystem. For mimicking cluster-disk
# TYPE container_fs_limit_bytes gauge
container_fs_limit_bytes{device="/dev/sda1",id="/"} {{.ClustDiskTotal}}
# HELP container_network_transmit_bytes_total Cumulative count of bytes transmitted. For mimicking the network stats
# TYPE container_network_transmit_bytes_total counter
container_network_transmit_bytes_total{image="notTheEmptyString",pod="{{.AppName}}"} {{.NetSend}}
# HELP container_network_receive_bytes_total Cumulative count of bytes received. For mimicking the network stats
# TYPE container_network_receive_bytes_total counter
container_network_receive_bytes_total{image="notTheEmptyString",pod="{{.AppName}}"} {{.NetRecv}}
# HELP kube_pod_labels is what each pod has as a list of labels - used to cross-reference with container stats
# TYPE kube_pod_labels gauge
kube_pod_labels{pod="{{.AppName}}",label_mexAppName="{{.AppName}}",label_mexAppVersion="{{.AppVersion}}"} 1
`

var port = flag.Int("port", 9100, "Port to export metrics on")
var statsPath = flag.String("promStatsPath", "", "Path to stats to export")

var SlackMessages []e2esetup.TestSlackMsg
var PagerDutyEvents []e2esetup.TestPagerDutyEvent

func main() {
	flag.Parse()
	if *port < 0 || 65535 < *port {
		log.Fatalf("Invalid Port number %d, please specify a port between 0 and 65535", *port)
	}
	SlackMessages = make([]e2esetup.TestSlackMsg, 0)
	promExportStrTemplate = template.Must(template.New("exporter").Parse(promExportSetup))
	stats := ExporterStatsCollector{}
	GetValuesFromYaml(&stats, *statsPath)
	buf := bytes.Buffer{}
	if err := promExportStrTemplate.Execute(&buf, &stats.Prom); err != nil {
		log.Fatal("Failed to create exporter ", "error:", err)
	}
	promExportStr = buf.String()

	log.Println("Starting Generic Web Service...")
	http.HandleFunc("/metrics", promExporter)
	http.HandleFunc(e2esetup.SlackWebhookApi, slackWebhookHandler)
	http.HandleFunc(e2esetup.ListSlackMessagesApi, showSlackMessages)
	http.HandleFunc(e2esetup.DeleteAllSlackMessagesApi, deleteSlackMessages)
	http.HandleFunc(e2esetup.PagerDutyApi, slackWebhookHandler)
	http.HandleFunc(e2esetup.ListPagerDutyMessagesApi, showPagerDutyEvents)
	http.HandleFunc(e2esetup.DeleteAllPagerDutyEventsApi, deletePagerDutyEvents)

	http.ListenAndServe(fmt.Sprintf(":%d", *port), nil)
}

func GetValuesFromYaml(stats *ExporterStatsCollector, ymlPath string) {
	yamlFile, err := ioutil.ReadFile(ymlPath)
	if err != nil {
		log.Fatal("Failed to load exporter yml file ", "filename:", ymlPath, " error:", err)
	}
	err = yaml.Unmarshal(yamlFile, stats)
	if err != nil {
		log.Fatal("Failed to parse exporter yml file ", "filename:", ymlPath, " error:", err)
	}
}

func promExporter(w http.ResponseWriter, r *http.Request) {
	fmt.Fprintf(w, promExportStr)
}

func slackWebhookHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Unsupported method", http.StatusMethodNotAllowed)
		return
	}
	defer r.Body.Close()

	body, err := ioutil.ReadAll(r.Body)
	if err != nil {
		log.Printf("Failed to decode slack request")
		http.Error(w, "decoding failed", http.StatusInternalServerError)
		return
	}
	if strings.HasSuffix(r.URL.Path, e2esetup.SlackWebhookApi) {
		log.Printf("Got a request to send a slack message method: %s\n, body:%s", r.Method, string(body))
		slackMsg := e2esetup.TestSlackMsg{}
		err = json.Unmarshal(body, &slackMsg)
		if err != nil {
			log.Printf("slack message unmarshal error: %v body:<%s>\n", err, string(body))
		} else {
			SlackMessages = append(SlackMessages, slackMsg)
		}
	} else if strings.HasSuffix(r.URL.Path, e2esetup.PagerDutyApi) {
		log.Printf("Got a request to send a pager duty event: %s\n, body:%s", r.Method, string(body))
		event := e2esetup.TestPagerDutyEvent{}
		err = json.Unmarshal(body, &event)
		if err != nil {
			log.Printf("slack message unmarshal error: %v body:<%s>\n", err, string(body))
		} else {
			PagerDutyEvents = append(PagerDutyEvents, event)
		}

	}
}

func showSlackMessages(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Unsupported method", http.StatusMethodNotAllowed)
	}
	// marshal data and send it back
	w.Header().Set("Content-Type", "application/json; charset=UTF-8")
	w.WriteHeader(http.StatusOK)
	err := json.NewEncoder(w).Encode(SlackMessages)
	if err != nil {
		log.Printf("Failed to get marshal slack messages: %s, messages:<%v>\n",
			err.Error(), SlackMessages)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	return
}

func deleteSlackMessages(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodDelete {
		http.Error(w, "Unsupported method", http.StatusMethodNotAllowed)
	}
	SlackMessages = nil
}

func showPagerDutyEvents(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Unsupported method", http.StatusMethodNotAllowed)
	}
	// marshal data and send it back
	w.Header().Set("Content-Type", "application/json; charset=UTF-8")
	w.WriteHeader(http.StatusOK)
	err := json.NewEncoder(w).Encode(PagerDutyEvents)
	if err != nil {
		log.Printf("Failed to marshal pagerduty events: %s, events:<%v>\n",
			err.Error(), PagerDutyEvents)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	return
}

func deletePagerDutyEvents(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodDelete {
		http.Error(w, "Unsupported method", http.StatusMethodNotAllowed)
	}
	PagerDutyEvents = nil
}
