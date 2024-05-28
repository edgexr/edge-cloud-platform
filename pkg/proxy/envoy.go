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

package proxy

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"text/template"

	"github.com/docker/docker/api/types"
	dme "github.com/edgexr/edge-cloud-platform/api/distributed_match_engine"
	"github.com/edgexr/edge-cloud-platform/api/edgeproto"
	"github.com/edgexr/edge-cloud-platform/pkg/cloudcommon"
	"github.com/edgexr/edge-cloud-platform/pkg/dockermgmt"
	"github.com/edgexr/edge-cloud-platform/pkg/log"
	"github.com/edgexr/edge-cloud-platform/pkg/platform/pc"
	ssh "github.com/edgexr/golang-ssh"
)

var envoyYamlT *template.Template
var sdsYamlT *template.Template

// this is the default value in envoy, for DOS protection
const defaultConcurrentConns uint64 = 1024

func init() {
	envoyYamlT = template.Must(template.New("yaml").Parse(envoyYaml))
	sdsYamlT = template.Must(template.New("yaml").Parse(sdsYaml))
}

func CreateEnvoyProxy(ctx context.Context, client ssh.Client, name, envoyImage string, config *ProxyConfig, appInst *edgeproto.AppInst, authAPI cloudcommon.RegistryAuthApi, ops ...Op) error {
	log.SpanLog(ctx, log.DebugLevelInfra, "create envoy", "name", name, "config", config, "appInst", appInst)
	opts := Options{}
	opts.Apply(ops)

	// if envoy image is not present, ensure pull credentials are present if needed
	present, err := dockermgmt.DockerImagePresent(ctx, client, envoyImage)
	if err != nil || !present {
		err = dockermgmt.SeedDockerSecret(ctx, client, envoyImage, authAPI)
		if err != nil {
			return err
		}
	}

	out, err := client.Output("pwd")
	if err != nil {
		return err
	}
	pwd := strings.TrimSpace(string(out))

	dir := pwd + "/envoy/" + name
	log.SpanLog(ctx, log.DebugLevelInfra, "envoy remote dir", "name", name, "dir", dir)
	err = pc.Run(client, "mkdir -p "+dir)
	if err != nil {
		return err
	}
	accesslogFile := dir + "/access.log"
	err = pc.Run(client, "sudo touch "+accesslogFile)
	if err != nil {
		log.SpanLog(ctx, log.DebugLevelInfra,
			"envoy %s can't create file %s", name, accesslogFile)
		return err
	}
	eyamlName := dir + "/envoy.yaml"
	syamlName := dir + "/sds.yaml"
	metricIP := cloudcommon.ProxyMetricsDefaultListenIP
	if opts.MetricIP != "" {
		metricIP = opts.MetricIP
	}
	configUpdated, isTLS, err := createEnvoyYaml(ctx, client, dir, name, config, metricIP, opts.MetricUDS, appInst)
	if err != nil {
		return fmt.Errorf("create envoy.yaml failed, %v", err)
	}
	log.SpanLog(ctx, log.DebugLevelInfra, "created envoy config", "configUpdated", configUpdated, "isTLS", isTLS)

	metricEndpoint := metricIP
	if opts.MetricUDS {
		metricEndpoint = cloudcommon.ProxyMetricsListenUDS
	}
	// container name is envoy+name for now to avoid conflicts with the nginx containers
	cmdArgs := []string{"run", "-d", "-l", "edge-cloud", "-l", cloudcommon.MexMetricEndpoint + "=" + metricEndpoint, "--restart=unless-stopped", "--name", "envoy" + name}
	if opts.DockerPublishPorts {
		cmdArgs = append(cmdArgs, dockermgmt.GetDockerPortString(appInst.MappedPorts, dockermgmt.UsePublicPortInContainer, dockermgmt.EnvoyProxy, config.ListenIP, config.ListenIPV6)...)
	}
	if opts.DockerNetwork != "" {
		// For dind, we use the network which the dind cluster is on.
		cmdArgs = append(cmdArgs, "--network", opts.DockerNetwork)
	}
	out, err = client.Output("pwd")
	if err != nil {
		return fmt.Errorf("Unable to get pwd: %v", err)
	}
	certsDir, _, _ := cloudcommon.GetCertsDirAndFiles(string(out))
	if isTLS {
		// use envoy SDS (secret discovery service) to refresh certs
		cmdArgs = append(cmdArgs, "-v", syamlName+":/etc/envoy/sds.yaml")
	}
	cmdArgs = append(cmdArgs, []string{
		"-v", certsDir + ":/etc/envoy/certs",
		"-v", accesslogFile + ":/tmp/access.log",
		"-v", eyamlName + ":/etc/envoy/envoy.yaml"}...)
	if opts.DockerUser != "" {
		cmdArgs = append(cmdArgs, []string{"-u", fmt.Sprintf("%s:%s", opts.DockerUser, opts.DockerUser)}...)
	}
	cmdArgs = append(cmdArgs, envoyImage)
	cmdArgs = append(cmdArgs, []string{"envoy", "-c", "/etc/envoy/envoy.yaml", "--use-dynamic-base-id"}...)

	data, err := client.Output("docker inspect envoy" + name)
	if err == nil {
		// container already running, determine if we can just restart it
		// or if we need to stop and start it.
		log.SpanLog(ctx, log.DebugLevelInfra, "existing envoy instance detected, checking if args match", "args", cmdArgs)
		os.WriteFile("docker-inspect.json", []byte(data), 0644)
		argsMatch := false
		inspectData := []types.ContainerJSON{}
		err := json.Unmarshal([]byte(data), &inspectData)
		if err != nil {
			log.SpanLog(ctx, log.DebugLevelInfra, "unmarshal docker inspect data failed", "data", inspectData, "err", err)
		} else if len(inspectData) > 0 {
			argsMatch = dockermgmt.ArgsMatchRunning(ctx, inspectData[0], cmdArgs)
			log.SpanLog(ctx, log.DebugLevelInfra, "existing envoy instance args check", "argsMatch", argsMatch)
		}
		if !configUpdated && argsMatch {
			return nil
		}
		if argsMatch {
			// restart container to pick up new config
			log.SpanLog(ctx, log.DebugLevelInfra, "restarting envoy")
			out, err := client.Output("docker restart envoy" + name)
			if err != nil {
				return fmt.Errorf("failed to restart envoy%s, %s, %s", name, out, err)
			}
			return nil
		}
		// stop so it can be started again
		log.SpanLog(ctx, log.DebugLevelInfra, "killing envoy so it can be re-run")
		out, err := client.Output("docker kill envoy" + name)
		if err != nil {
			// maybe it's dead already
			log.SpanLog(ctx, log.DebugLevelInfra, "failed to kill existing envoy", "out", out, "err", err)
		}
		out, err = client.Output("docker rm -f envoy" + name)
		if err != nil {
			log.SpanLog(ctx, log.DebugLevelInfra, "failed to remove existing envoy", "out", out, "err", err)
		}
	}

	cmd := "docker " + strings.Join(cmdArgs, " ")
	log.SpanLog(ctx, log.DebugLevelInfra, "envoy docker command", "name", "envoy"+name,
		"cmd", cmd)
	out, err = client.Output(cmd)
	if err != nil {
		return fmt.Errorf("can't create envoy container %s, %s, %v", "envoy"+name, out, err)
	}
	log.SpanLog(ctx, log.DebugLevelInfra, "created envoy container", "name", name)
	return nil
}

// Build a map of individual ports with key struct:
// <proto>:<portnum>
func buildPortsMapFromString(portsString string) (map[string]struct{}, error) {
	portMap := make(map[string]struct{})
	if portsString == "all" {
		return portMap, nil
	}
	ports, err := edgeproto.ParseAppPorts(portsString)
	if err != nil {
		return nil, err
	}
	for _, port := range ports {
		if port.EndPort == 0 {
			port.EndPort = port.InternalPort
		}
		for p := port.InternalPort; p <= port.EndPort; p++ {
			proto, err := edgeproto.LProtoStr(port.Proto)
			if err != nil {
				return nil, err
			}
			key := fmt.Sprintf("%s:%d", proto, p)
			portMap[key] = struct{}{}
		}
	}
	return portMap, nil
}

func getBackendIpToUse(ctx context.Context, appInst *edgeproto.AppInst, port *dme.AppPort, defaultBackendIP string) (string, error) {
	serviceBackendIP := defaultBackendIP
	if appInst.InternalPortToLbIp != nil {
		pstring, err := edgeproto.AppInternalPortToString(port)
		if err != nil {
			return "", err
		}
		lbip, ok := appInst.InternalPortToLbIp[pstring]
		if ok {
			serviceBackendIP = lbip
		}
	}
	if serviceBackendIP == "" {
		return "", fmt.Errorf("No load balancer IP and no default backend IP provided")
	}
	return serviceBackendIP, nil
}

func generateEnvoyYaml(ctx context.Context, name string, config *ProxyConfig, metricIP string, metricUDS bool, appInst *edgeproto.AppInst) (string, string, bool, error) {
	log.SpanLog(ctx, log.DebugLevelInfra, "generate envoy yaml", "name", name)

	var skipHcAll = false
	var skipHcPortsMap map[string]struct{}
	var err error

	spec := ProxySpec{
		Name:       name,
		MetricIP:   metricIP,
		MetricPort: cloudcommon.ProxyMetricsPort,
		MetricUDS:  metricUDS,
		CertName:   cloudcommon.CertName,
	}
	// check skip health check ports
	if config.SkipHCPorts == "all" {
		skipHcAll = true
	} else {
		skipHcPortsMap, err = buildPortsMapFromString(config.SkipHCPorts)
		if err != nil {
			return "", "", false, err
		}
	}

	isTLS := false
	proxyIPPairs := []struct {
		listenIP string
		destIP   string
		IPTag    string
	}{
		{config.ListenIP, config.DestIP, ""},
		{config.ListenIPV6, config.DestIPV6, "ipv6"},
	}
	for _, proxyIPPair := range proxyIPPairs {
		if proxyIPPair.listenIP == "" || proxyIPPair.destIP == "" {
			continue
		}
		for _, p := range appInst.MappedPorts {
			endPort := p.EndPort
			if endPort == 0 {
				endPort = p.PublicPort
			} else {
				// if we have a port range, the internal ports and external ports must match
				if p.InternalPort != p.PublicPort {
					return "", "", false, fmt.Errorf("public and internal ports must match when port range in use")
				}
			}
			// Currently there is no (known) way to put a port range within Envoy.
			// So we create one spec per port when there is a port range in use
			internalPort := p.InternalPort
			for pubPort := p.PublicPort; pubPort <= endPort; pubPort++ {
				serviceBackendIP, err := getBackendIpToUse(ctx, appInst, &p, proxyIPPair.destIP)
				if err != nil {
					return "", "", false, err
				}
				listenIP := proxyIPPair.listenIP
				// special case, yaml can't handle :: as a value, must be quoted
				if listenIP == "::" {
					listenIP = "\"::\""
				}

				switch p.Proto {
				// only support tcp for now
				case dme.LProto_L_PROTO_TCP:
					key := fmt.Sprintf("%s:%d", "tcp", internalPort)
					_, skipHealthCheck := skipHcPortsMap[key]
					tcpPort := TCPSpecDetail{
						ListenPort:  pubPort,
						ListenIP:    listenIP,
						BackendIP:   serviceBackendIP,
						BackendPort: internalPort,
						UseTLS:      p.Tls,
						HealthCheck: !skipHcAll && !skipHealthCheck,
						IPTag:       proxyIPPair.IPTag,
					}
					if p.Tls {
						isTLS = true
					}
					tcpconns, err := getTCPConcurrentConnections()
					if err != nil {
						return "", "", false, err
					}
					tcpPort.ConcurrentConns = tcpconns
					spec.TCPSpec = append(spec.TCPSpec, &tcpPort)
				case dme.LProto_L_PROTO_UDP:
					if p.Nginx { // defv specified nginx for this port (range)
						continue
					}
					udpPort := UDPSpecDetail{
						ListenPort:  pubPort,
						ListenIP:    listenIP,
						BackendIP:   serviceBackendIP,
						BackendPort: internalPort,
						MaxPktSize:  p.MaxPktSize,
						IPTag:       proxyIPPair.IPTag,
					}
					udpconns, err := getUDPConcurrentConnections()
					if err != nil {
						return "", "", false, err
					}
					udpPort.ConcurrentConns = udpconns
					spec.UDPSpec = append(spec.UDPSpec, &udpPort)
				}
				internalPort++
			}
		}
	}
	buf := bytes.Buffer{}
	err = envoyYamlT.Execute(&buf, &spec)
	if err != nil {
		return "", "", false, err
	}
	sdsbuf := bytes.Buffer{}
	if isTLS {
		log.SpanLog(ctx, log.DebugLevelInfra, "create sds yaml", "name", name)
		err = sdsYamlT.Execute(&sdsbuf, &spec)
		if err != nil {
			return "", "", false, err
		}
	}
	return buf.String(), sdsbuf.String(), isTLS, nil
}

func createEnvoyYaml(ctx context.Context, client ssh.Client, yamldir, name string, config *ProxyConfig, metricIP string, metricUDS bool, appInst *edgeproto.AppInst) (bool, bool, error) {
	log.SpanLog(ctx, log.DebugLevelInfra, "create envoy yaml", "name", name)
	envoyData, sdsData, isTLS, err := generateEnvoyYaml(ctx, name, config, metricIP, metricUDS, appInst)
	if err != nil {
		return false, false, err
	}

	updated := false
	curEnvoyData, err := client.Output("cat " + yamldir + "/envoy.yaml")
	if err == nil && strings.TrimSpace(curEnvoyData) == strings.TrimSpace(envoyData) {
		// no change
	} else {
		err = pc.WriteFile(client, yamldir+"/envoy.yaml", envoyData, "envoy.yaml", pc.NoSudo)
		if err != nil {
			log.SpanLog(ctx, log.DebugLevelInfra, "write envoy.yaml failed",
				"name", name, "err", err)
			return updated, isTLS, err
		}
		updated = true
	}
	if isTLS {
		curSdsData, err := client.Output("cat " + yamldir + "/sds.yaml")
		if err == nil && strings.TrimSpace(curSdsData) == strings.TrimSpace(sdsData) {
			// no change
		} else {
			err = pc.WriteFile(client, yamldir+"/sds.yaml", sdsData, "sds.yaml", pc.NoSudo)
			if err != nil {
				log.SpanLog(ctx, log.DebugLevelInfra, "write sds.yaml failed",
					"name", name, "err", err)
				return updated, isTLS, err
			}
		}
		updated = true
	}
	return updated, isTLS, nil
}

// TODO: Probably should eventually find a better way to uniquely name clusters other than just by the port theyre getting proxied from
var envoyYaml = `
node:
  id: {{.Name}}
  cluster: {{.Name}}
static_resources:
  listeners:
  {{- range .TCPSpec}}
  - address:
      socket_address:
        address: {{.ListenIP}}
        port_value: {{.ListenPort}}
    filter_chains:
    - filters:
      - name: envoy.filters.network.tcp_proxy
        typed_config:
          '@type': type.googleapis.com/envoy.extensions.filters.network.tcp_proxy.v3.TcpProxy
          stat_prefix: ingress_tcp
          cluster: backend{{.BackendPort}}{{.IPTag}}
          access_log:
            - name: envoy.access_loggers.file
              typed_config:
                '@type': type.googleapis.com/envoy.extensions.access_loggers.file.v3.FileAccessLog
                path: /tmp/access.log
                json_format: {
                  "start_time": "%START_TIME%",
                  "duration": "%DURATION%",
                  "bytes_sent": "%BYTES_SENT%",
                  "bytes_received": "%BYTES_RECEIVED%",
                  "client_address": "%DOWNSTREAM_REMOTE_ADDRESS%",
                  "upstream_cluster": "%UPSTREAM_CLUSTER%"
                }
      {{if .UseTLS -}}
      transport_socket:
        name: "envoy.transport_sockets.tls"
        typed_config:
          '@type': type.googleapis.com/envoy.extensions.transport_sockets.tls.v3.DownstreamTlsContext
          common_tls_context:
            tls_certificate_sds_secret_configs:
                name: envoy.transport_sockets.tls.context
                sds_config:
                    path: /etc/envoy/sds.yaml
      {{- end}}
  {{- end}}
  {{- range .UDPSpec}}
  - name: udp_listener_{{.ListenPort}}
    address:
      socket_address:
        protocol: UDP
        address: {{.ListenIP}}
        port_value: {{.ListenPort}}
    {{if ne .MaxPktSize 0 -}}
    udp_listener_config:
      downstream_socket_config:
        max_rx_datagram_size: {{.MaxPktSize}}
    {{- end}}
    listener_filters:
      name: envoy.filters.udp_listener.udp_proxy
      typed_config:
        '@type': type.googleapis.com/envoy.extensions.filters.udp.udp_proxy.v3.UdpProxyConfig
        stat_prefix: downstream{{.BackendPort}}{{.IPTag}}
        cluster: udp_backend{{.BackendPort}}{{.IPTag}}
        {{if ne .MaxPktSize 0 -}}
        upstream_socket_config:
          max_rx_datagram_size: {{.MaxPktSize}}
        {{- end}}
    reuse_port: true
  {{- end}}
  clusters:
  {{- range .TCPSpec}}
  - name: backend{{.BackendPort}}{{.IPTag}}
    connect_timeout: 0.25s
    type: strict_dns
    circuit_breakers:
        thresholds:
            max_connections: {{.ConcurrentConns}}
    lb_policy: round_robin
    load_assignment:
      cluster_name: backend{{.BackendPort}}{{.IPTag}}
      endpoints:
        lb_endpoints:
        - endpoint:
            address:
              socket_address:
                address: {{.BackendIP}}
                port_value: {{.BackendPort}}
    {{if .HealthCheck -}}
    health_checks:
      - timeout: 1s
        interval: 5s
        interval_jitter: 1s
        unhealthy_threshold: 3
        healthy_threshold: 3
        tcp_health_check: {}
        no_traffic_interval: 5s
    {{- end}}
{{- end}}
{{- range .UDPSpec}}
  - name: udp_backend{{.BackendPort}}{{.IPTag}}
    connect_timeout: 0.25s
    type: STRICT_DNS
    circuit_breakers:
      thresholds:
        max_connections: {{.ConcurrentConns}}
    lb_policy: ROUND_ROBIN
    load_assignment:
      cluster_name: udp_backend{{.BackendPort}}{{.IPTag}}
      endpoints:
      - lb_endpoints:
        - endpoint:
            address:
              socket_address:
                address: {{.BackendIP}}
                port_value: {{.BackendPort}}
{{- end}}
admin:
  access_log_path: "/tmp/admin.log"
  address:
  {{- if .MetricUDS}}
    pipe:
       path: "/var/tmp/metrics.sock"
  {{- else}}
    socket_address:
      address: {{.MetricIP}}
      port_value: {{.MetricPort}}
  {{- end}}
`

var sdsYaml = `
resources:
- '@type': type.googleapis.com/envoy.extensions.transport_sockets.tls.v3.Secret
  name: envoy.transport_sockets.tls.context
  tls_certificate:
    certificate_chain:
      filename: "/etc/envoy/certs/{{$.CertName}}.crt"
    private_key:
      filename: "/etc/envoy/certs/{{$.CertName}}.key"
`

func DeleteEnvoyProxy(ctx context.Context, client ssh.Client, name string) error {
	containerName := "envoy" + name

	log.SpanLog(ctx, log.DebugLevelInfra, "delete envoy", "name", containerName)
	out, err := client.Output("docker kill " + containerName)
	log.SpanLog(ctx, log.DebugLevelInfra, "kill envoy result", "out", out, "err", err)

	envoyDir := "envoy/" + name
	out, err = client.Output("rm -rf " + envoyDir)
	log.SpanLog(ctx, log.DebugLevelInfra, "delete envoy dir", "name", name, "dir", envoyDir, "out", out, "err", err)

	out, err = client.Output("docker rm -f " + "envoy" + name)
	log.SpanLog(ctx, log.DebugLevelInfra, "rm envoy result", "out", out, "err", err)
	if err != nil && !strings.Contains(string(out), "No such container") {
		// delete the envoy proxy anyway
		return fmt.Errorf("can't remove envoy container %s, %s, %v", name, out, err)
	}
	return nil
}

func GetEnvoyContainerName(name string) string {
	return "envoy" + name
}
