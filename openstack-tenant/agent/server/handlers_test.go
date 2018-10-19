package server

import (
	"fmt"
	"github.com/mobiledgex/edge-cloud-infra/openstack-tenant/agent/api"
	"testing"
)

var validOutput = `
user  nginx;
worker_processes  1;

error_log  /var/log/nginx/error.log warn;
pid        /var/run/nginx.pid;

events {
    worker_connections  1024;
}

http {
    include       /etc/nginx/mime.types;
    default_type  application/octet-stream;
    log_format  main  '$remote_addr - $remote_user [$time_local] "$request" '
                      '$status $body_bytes_sent "$http_referer" '
                      '"$http_user_agent" "$http_x_forwarded_for"';
    access_log  /var/log/nginx/access.log  main;
    keepalive_timeout  65;
    include /etc/nginx/conf.d/*.conf;
    server {
 	listen 9999 ssl;
	ssl_certificate        /etc/ssl/certs/server.crt;
	ssl_certificate_key    /etc/ssl/certs/server.key;
	location httptest1path {
		proxy_pass http://127.0.0.1:8888;
	}
    }
}

stream {
	server {
		listen 19999;
		proxy_pass 127.0.0.1:18888;
	}
	server {
		listen 29999 udp;
		proxy_pass 127.0.0.1:28888;
	}
}
`

func TestCreateNginxConf(t *testing.T) {
	ports := []*api.NginxPort{
		&api.NginxPort{
			Name:     "httptest1",
			Origin:   "127.0.0.1:8888",
			Path:     "httptest1path",
			External: "9999",
			Protocol: "TCP",
			Mexproto: "LProtoHTTP",
			Remoteip: "",
			Internal: "7777",
		},
		&api.NginxPort{
			Name:     "tcptest1",
			Origin:   "127.0.0.1:18888",
			Path:     "tcptest1path",
			External: "19999",
			Protocol: "TCP",
			Mexproto: "LProtoTCP",
			Remoteip: "",
			//Internal: "17777",
		},
		&api.NginxPort{
			Name:     "udptest1",
			Origin:   "127.0.0.1:28888",
			Path:     "udptest1path",
			External: "29999",
			Protocol: "UDP",
			Mexproto: "LProtoUDP",
			Remoteip: "",
			//Internal: "27777",
		},
	}

	conf, err := createNginxConf("testconf.conf", "test123", ports)
	if err != nil {
		t.Error(err)
		return
	}
	fmt.Printf("conf:\n%s\n", *conf)
	if validOutput != *conf {
		t.Errorf("output mismatch")
	}
}

var defaultConfOut = `
server {
    listen       7777;
    server_name  test123;
    ssl_certificate        /etc/ssl/certs/server.crt;
    ssl_certificate_key    /etc/ssl/certs/server.key;
    location / {
        root   /usr/share/nginx/html;
        index  index.html index.htm;
    }
}
`

func TestCreateDefaultNginxConf(t *testing.T) {
	ports := []*api.NginxPort{
		&api.NginxPort{
			Name:     "httptest1",
			Origin:   "127.0.0.1:8888",
			Path:     "httptest1path",
			External: "9999",
			Protocol: "TCP",
			Mexproto: "LProtoHTTP",
			Remoteip: "",
			Internal: "7777",
		},
		&api.NginxPort{
			Name:     "tcptest1",
			Origin:   "127.0.0.1:18888",
			Path:     "tcptest1path",
			External: "19999",
			Protocol: "TCP",
			Mexproto: "LProtoTCP",
			Remoteip: "",
			//Internal: "17777",
		},
		&api.NginxPort{
			Name:     "udptest1",
			Origin:   "127.0.0.1:28888",
			Path:     "udptest1path",
			External: "29999",
			Protocol: "UDP",
			Mexproto: "LProtoUDP",
			Remoteip: "",
			//Internal: "27777",
		},
	}

	conf, err := createNginxDefaultConf("defaultconf.conf", "test123", ports)
	if err != nil {
		t.Error(err)
		return
	}
	fmt.Printf("defaultconf:\n%s\n", *conf)
	if defaultConfOut != *conf {
		t.Errorf("output mismatch")
	}
}

func TestGetNginxDefaultPort(t *testing.T) {
	port := GetNginxDefaultPort()
	if port == "" {
		t.Errorf("can't get port")
	}
	fmt.Println("port", port)
}
