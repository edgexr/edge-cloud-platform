package main

import (
	"bufio"
	"flag"
	"fmt"
	baselog "log"
	"net"
	"net/http"
	"os"
	"strings"

	"github.com/mobiledgex/edge-cloud/log"
)

// Fake envoy exporter serves prometheus stats as if it were an Envoy
// load balancer.
// To query it, use
// curl --unix-socket <sockfile> http:/sock/stats/prometheus
// To set a measure, use
// curl --unix-socket <sockfile> --data-urlencode 'measure=envoy_cluster_upstream_cx_actve{envoy_cluster_name="myclust"}' --data-urlencode 'val=10' http:/sock/setval

var sockFile = flag.String("sockfile", "", "unix domain socket file to listen on")
var cluster = flag.String("cluster", "", "cluster name")

var stats []stat
var measures map[string]*measure

func main() {
	flag.Parse()
	ch := make(chan bool, 0)
	run(ch)
	<-ch
}

func run(ch chan bool) {
	if *sockFile == "" {
		baselog.Fatal("please specify sockfile to listen on")
	}
	if err := os.RemoveAll(*sockFile); err != nil {
		baselog.Fatal(err)
	}
	if *cluster == "" {
		baselog.Fatal("please specify cluster name")
	}

	measures = make(map[string]*measure)

	replaceTags := make(map[string]string)
	replaceTags["envoy_cluster_name"] = `"` + *cluster + `"`

	stats = parseSampleStats(sampleOutput, replaceTags)

	lis, err := net.Listen("unix", *sockFile)
	if err != nil {
		baselog.Fatal(err)
	}

	http.HandleFunc("/stats/prometheus", serveStatsProm)
	http.HandleFunc("/setval", setVal)

	log.DebugLog(log.DebugLevelInfo, "listening", "sockfile", *sockFile)
	go func() {
		err := http.Serve(lis, nil)
		if err != nil && err != http.ErrServerClosed {
			baselog.Fatal(err)
		}
		lis.Close()
		close(ch)
	}()
}

func serveStatsProm(w http.ResponseWriter, r *http.Request) {
	for _, s := range stats {
		fmt.Fprint(w, s.String()+"\n")
	}
}

func setVal(w http.ResponseWriter, r *http.Request) {
	measName := r.FormValue("measure")
	m, found := measures[measName]
	if !found {
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte(fmt.Sprintf("measure '%s' not found", measName)))
		return
	}
	val := r.FormValue("val")
	if val == "" {
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte("val not specified"))
		return
	}
	m.val = val
	w.Write([]byte("measure updated"))
	log.DebugLog(log.DebugLevelInfo, "updated measure", "measure", measName, "val", val)
}

type stat interface {
	// single line string to write to prometheus scraper
	String() string
}

func parseSampleStats(dat string, replaceTags map[string]string) []stat {
	stats := []stat{}

	scanner := bufio.NewScanner(strings.NewReader(dat))
	// read line by line
	lineno := 0
	for scanner.Scan() {
		lineno++
		line := scanner.Text()
		if len(line) == 0 {
			continue
		}
		if strings.HasPrefix(line, "# TYPE") {
			stats = append(stats, newHeader(line))
		} else {
			m, err := newMeasure(line, replaceTags)
			if err != nil {
				baselog.Fatalf("failed to parse: %s, at line %v", err, lineno)
			}
			stats = append(stats, m)
			measures[m.name] = m
		}
	}
	return stats
}

type header struct {
	val string
}

func newHeader(line string) *header {
	h := header{
		val: line,
	}
	return &h
}

func (s *header) String() string { return s.val }

type measure struct {
	name string
	val  string
}

func newMeasure(line string, replaceTags map[string]string) (*measure, error) {
	// in order to replace tags, we need to parse the line
	// line looks like name{key="val",...} val
	m := measure{}
	nameval := strings.Split(line, " ")
	if len(nameval) != 2 {
		return nil, fmt.Errorf("measure split by space expected 2 fields, but got %d: %s", len(nameval), line)
	}
	m.val = nameval[1]

	openbrace := strings.Index(nameval[0], "{")
	closebrace := strings.LastIndex(nameval[0], "}")
	name := line[:openbrace]

	// remove braces around tags
	tags := line[openbrace+1 : closebrace]
	newTags := []string{}
	if tags != "" {
		kvs := strings.Split(tags, ",")
		for _, kvstr := range kvs {
			kv := strings.Split(kvstr, "=")
			if len(kv) != 2 {
				return nil, fmt.Errorf("failed to split key value into 2, %s", kvstr)
			}
			if v, found := replaceTags[kv[0]]; found {
				kv[1] = v
			}
			newTags = append(newTags, kv[0]+"="+kv[1])
		}
	}
	m.name = name + "{" + strings.Join(newTags, ",") + "}"
	return &m, nil
}

func (s *measure) String() string {
	return s.name + " " + s.val
}
