package main

import (
	"bytes"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"text/template"

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

var exportStr string
var exportStrTemplate *template.Template
var exportSetup = `# HELP node_netstat_Tcp_CurrEstab mimicking the TcpConns stat
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
var statsPath = flag.String("statsPath", "", "Path to stats to export")

func main() {
	flag.Parse()
	if *port < 0 || 65535 < *port {
		log.Fatalf("Invalid Port number %d, please specify a port between 0 and 65535", *port)
	}
	exportStrTemplate = template.Must(template.New("exporter").Parse(exportSetup))
	stats := ExporterStatsCollector{}
	GetValuesFromYaml(&stats, *statsPath)
	buf := bytes.Buffer{}
	if err := exportStrTemplate.Execute(&buf, &stats.Prom); err != nil {
		log.Fatal("Failed to create exporter ", "error:", err)
	}
	exportStr = buf.String()

	log.Println("Starting fake prometheus exporter...")
	http.HandleFunc("/metrics", exporter)
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

func exporter(w http.ResponseWriter, r *http.Request) {
	fmt.Fprintf(w, exportStr)
}
