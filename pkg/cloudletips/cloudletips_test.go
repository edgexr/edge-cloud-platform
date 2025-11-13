// Copyright 2025 EdgeXR, Inc
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package cloudletips

import (
	"context"
	"fmt"
	"slices"
	"strings"
	"testing"

	"github.com/edgexr/edge-cloud-platform/api/edgeproto"
	"github.com/edgexr/edge-cloud-platform/pkg/cloudcommon"
	"github.com/edgexr/edge-cloud-platform/pkg/log"
	"github.com/edgexr/edge-cloud-platform/pkg/regiondata"
	"github.com/stretchr/testify/require"
	"go.etcd.io/etcd/client/v3/concurrency"
)

func TestCloudletIPs(t *testing.T) {
	log.SetDebugLevel(log.DebugLevelApi | log.DebugLevelInfra)
	log.InitTracer(nil)
	defer log.FinishTracer()
	ctx := log.StartTestSpan(context.Background())

	dummy := regiondata.InMemoryStore{}
	dummy.Start()
	defer dummy.Stop()

	sync := regiondata.InitSync(&dummy)
	sync.Start()
	defer sync.Done()

	cloudletIPsCache := edgeproto.CloudletIPsCache{}
	cloudletIPsCache.InitCacheWithSync(sync)
	cloudletCache := edgeproto.CloudletCache{}
	cloudletCache.InitCacheWithSync(sync)
	clusterInstCache := edgeproto.ClusterInstCache{}
	clusterInstCache.InitCacheWithSync(sync)

	cloudletIPs := NewCloudletIPs(sync.GetKVStore(), cloudletIPsCache.Store, cloudletCache.Store, clusterInstCache.Store)

	ckey := func(name string) *edgeproto.CloudletKey {
		return &edgeproto.CloudletKey{
			Organization: "oper1",
			Name:         name,
		}
	}
	clkey := func(name string) *edgeproto.ClusterKey {
		return &edgeproto.ClusterKey{
			Organization: "dev1",
			Name:         name,
		}
	}
	lbkey := func(name string) *edgeproto.LoadBalancerKey {
		return &edgeproto.LoadBalancerKey{
			Namespace: "appinst",
			Name:      name,
		}
	}
	cluster := func(name string) *edgeproto.ClusterInst {
		return &edgeproto.ClusterInst{
			Key: *clkey(name),
		}
	}

	// create two test cloudlets
	const VIPS = "10.10.10.150-10.10.10.154"
	cloudlets := []edgeproto.Cloudlet{{
		Key: *ckey("c1"),
		EnvVar: map[string]string{
			cloudcommon.FloatingVIPs: VIPS,
		},
	}, {
		Key: *ckey("c2"),
		EnvVar: map[string]string{
			cloudcommon.FloatingVIPs: VIPS,
		},
	}}
	for _, cloudlet := range cloudlets {
		_, err := cloudletCache.Store.Put(ctx, &cloudlet, sync.SyncWait)
		require.Nil(t, err)
	}

	tests := []struct {
		desc           string
		start          []*edgeproto.CloudletIPs
		stmcloudletkey *edgeproto.CloudletKey
		stmaction      func(stm concurrency.STM, cloudlet *edgeproto.Cloudlet) error
		action         func() error
		err            string
		end            []*edgeproto.CloudletIPs
	}{{
		desc:           "cloudletIPs not present, reserve control IP",
		stmcloudletkey: ckey("c1"),
		stmaction: func(stm concurrency.STM, cloudlet *edgeproto.Cloudlet) error {
			return cloudletIPs.ReserveControlPlaneIP(stm, cloudlet, cluster("cl1"))
		},
		err: "",
		end: []*edgeproto.CloudletIPs{{
			Key: *ckey("c1"),
			ClusterIps: map[string]*edgeproto.ClusterIPs{
				clkey("cl1").GetKeyString(): {
					Key:              *clkey("cl1"),
					ControlPlaneIpv4: "10.10.10.150",
				},
			},
		}},
	}, {
		desc: "reserve control IP, orthogonal cloudlet ip pool",
		start: []*edgeproto.CloudletIPs{{
			Key: *ckey("c1"),
			ClusterIps: map[string]*edgeproto.ClusterIPs{
				clkey("cl1").GetKeyString(): {
					Key:              *clkey("cl1"),
					ControlPlaneIpv4: "10.10.10.150",
				},
			},
		}},
		stmcloudletkey: ckey("c2"),
		stmaction: func(stm concurrency.STM, cloudlet *edgeproto.Cloudlet) error {
			return cloudletIPs.ReserveControlPlaneIP(stm, cloudlet, cluster("cl2"))
		},
		err: "",
		end: []*edgeproto.CloudletIPs{{
			Key: *ckey("c1"),
			ClusterIps: map[string]*edgeproto.ClusterIPs{
				clkey("cl1").GetKeyString(): {
					Key:              *clkey("cl1"),
					ControlPlaneIpv4: "10.10.10.150",
				},
			},
		}, {
			Key: *ckey("c2"),
			ClusterIps: map[string]*edgeproto.ClusterIPs{
				clkey("cl2").GetKeyString(): {
					Key:              *clkey("cl2"),
					ControlPlaneIpv4: "10.10.10.150",
				},
			},
		}},
	}, {
		desc: "reserve control IP, additional cluster",
		start: []*edgeproto.CloudletIPs{{
			Key: *ckey("c1"),
			ClusterIps: map[string]*edgeproto.ClusterIPs{
				clkey("cl1").GetKeyString(): {
					Key:              *clkey("cl1"),
					ControlPlaneIpv4: "10.10.10.150",
				},
			},
		}},
		stmcloudletkey: ckey("c1"),
		stmaction: func(stm concurrency.STM, cloudlet *edgeproto.Cloudlet) error {
			return cloudletIPs.ReserveControlPlaneIP(stm, cloudlet, cluster("cl2"))
		},
		err: "",
		end: []*edgeproto.CloudletIPs{{
			Key: *ckey("c1"),
			ClusterIps: map[string]*edgeproto.ClusterIPs{
				clkey("cl1").GetKeyString(): {
					Key:              *clkey("cl1"),
					ControlPlaneIpv4: "10.10.10.150",
				},
				clkey("cl2").GetKeyString(): {
					Key:              *clkey("cl2"),
					ControlPlaneIpv4: "10.10.10.151",
				},
			},
		}},
	}, {
		desc: "reserve load balancer IP",
		start: []*edgeproto.CloudletIPs{{
			Key: *ckey("c1"),
			ClusterIps: map[string]*edgeproto.ClusterIPs{
				clkey("cl1").GetKeyString(): {
					Key:              *clkey("cl1"),
					ControlPlaneIpv4: "10.10.10.150",
				},
				clkey("cl2").GetKeyString(): {
					Key:              *clkey("cl2"),
					ControlPlaneIpv4: "10.10.10.151",
				},
			},
		}},
		action: func() error {
			_, err := cloudletIPs.ReserveLoadBalancerIP(ctx, *ckey("c1"), *clkey("cl1"), *lbkey("lb1"))
			return err
		},
		err: "",
		end: []*edgeproto.CloudletIPs{{
			Key: *ckey("c1"),
			ClusterIps: map[string]*edgeproto.ClusterIPs{
				clkey("cl1").GetKeyString(): {
					Key:              *clkey("cl1"),
					ControlPlaneIpv4: "10.10.10.150",
					LoadBalancers: map[string]*edgeproto.LoadBalancer{
						lbkey("lb1").GetKeyString(): {
							Key:  *lbkey("lb1"),
							Ipv4: "10.10.10.152",
						},
					},
				},
				clkey("cl2").GetKeyString(): {
					Key:              *clkey("cl2"),
					ControlPlaneIpv4: "10.10.10.151",
				},
			},
		}},
	}, {
		desc: "reserve load balancer IP 2",
		start: []*edgeproto.CloudletIPs{{
			Key: *ckey("c1"),
			ClusterIps: map[string]*edgeproto.ClusterIPs{
				clkey("cl1").GetKeyString(): {
					Key:              *clkey("cl1"),
					ControlPlaneIpv4: "10.10.10.150",
					LoadBalancers: map[string]*edgeproto.LoadBalancer{
						lbkey("lb1").GetKeyString(): {
							Key:  *lbkey("lb1"),
							Ipv4: "10.10.10.152",
						},
					},
				},
				clkey("cl2").GetKeyString(): {
					Key:              *clkey("cl2"),
					ControlPlaneIpv4: "10.10.10.153",
				},
			},
		}},
		action: func() error {
			_, err := cloudletIPs.ReserveLoadBalancerIP(ctx, *ckey("c1"), *clkey("cl2"), *lbkey("lb1"))
			return err
		},
		err: "",
		end: []*edgeproto.CloudletIPs{{
			Key: *ckey("c1"),
			ClusterIps: map[string]*edgeproto.ClusterIPs{
				clkey("cl1").GetKeyString(): {
					Key:              *clkey("cl1"),
					ControlPlaneIpv4: "10.10.10.150",
					LoadBalancers: map[string]*edgeproto.LoadBalancer{
						lbkey("lb1").GetKeyString(): {
							Key:  *lbkey("lb1"),
							Ipv4: "10.10.10.152",
						},
					},
				},
				clkey("cl2").GetKeyString(): {
					Key:              *clkey("cl2"),
					ControlPlaneIpv4: "10.10.10.153",
					LoadBalancers: map[string]*edgeproto.LoadBalancer{
						lbkey("lb1").GetKeyString(): {
							Key:  *lbkey("lb1"),
							Ipv4: "10.10.10.151",
						},
					},
				},
			},
		}},
	}, {
		desc: "reserve load balancer IP last IP",
		start: []*edgeproto.CloudletIPs{{
			Key: *ckey("c1"),
			ClusterIps: map[string]*edgeproto.ClusterIPs{
				clkey("cl1").GetKeyString(): {
					Key:              *clkey("cl1"),
					ControlPlaneIpv4: "10.10.10.150",
					LoadBalancers: map[string]*edgeproto.LoadBalancer{
						lbkey("lb1").GetKeyString(): {
							Key:  *lbkey("lb1"),
							Ipv4: "10.10.10.152",
						},
					},
				},
				clkey("cl2").GetKeyString(): {
					Key:              *clkey("cl2"),
					ControlPlaneIpv4: "10.10.10.153",
					LoadBalancers: map[string]*edgeproto.LoadBalancer{
						lbkey("lb1").GetKeyString(): {
							Key:  *lbkey("lb1"),
							Ipv4: "10.10.10.151",
						},
					},
				},
			},
		}},
		action: func() error {
			_, err := cloudletIPs.ReserveLoadBalancerIP(ctx, *ckey("c1"), *clkey("cl1"), *lbkey("lb2"))
			return err
		},
		err: "",
		end: []*edgeproto.CloudletIPs{{
			Key: *ckey("c1"),
			ClusterIps: map[string]*edgeproto.ClusterIPs{
				clkey("cl1").GetKeyString(): {
					Key:              *clkey("cl1"),
					ControlPlaneIpv4: "10.10.10.150",
					LoadBalancers: map[string]*edgeproto.LoadBalancer{
						lbkey("lb1").GetKeyString(): {
							Key:  *lbkey("lb1"),
							Ipv4: "10.10.10.152",
						},
						lbkey("lb2").GetKeyString(): {
							Key:  *lbkey("lb2"),
							Ipv4: "10.10.10.154",
						},
					},
				},
				clkey("cl2").GetKeyString(): {
					Key:              *clkey("cl2"),
					ControlPlaneIpv4: "10.10.10.153",
					LoadBalancers: map[string]*edgeproto.LoadBalancer{
						lbkey("lb1").GetKeyString(): {
							Key:  *lbkey("lb1"),
							Ipv4: "10.10.10.151",
						},
					},
				},
			},
		}},
	}, {
		desc: "free load balancer IP",
		start: []*edgeproto.CloudletIPs{{
			Key: *ckey("c1"),
			ClusterIps: map[string]*edgeproto.ClusterIPs{
				clkey("cl1").GetKeyString(): {
					Key:              *clkey("cl1"),
					ControlPlaneIpv4: "10.10.10.150",
					LoadBalancers: map[string]*edgeproto.LoadBalancer{
						lbkey("lb1").GetKeyString(): {
							Key:  *lbkey("lb1"),
							Ipv4: "10.10.10.152",
						},
						lbkey("lb2").GetKeyString(): {
							Key:  *lbkey("lb2"),
							Ipv4: "10.10.10.154",
						},
					},
				},
				clkey("cl2").GetKeyString(): {
					Key:              *clkey("cl2"),
					ControlPlaneIpv4: "10.10.10.153",
					LoadBalancers: map[string]*edgeproto.LoadBalancer{
						lbkey("lb1").GetKeyString(): {
							Key:  *lbkey("lb1"),
							Ipv4: "10.10.10.151",
						},
					},
				},
			},
		}},
		action: func() error {
			return cloudletIPs.FreeLoadBalancerIP(ctx, *ckey("c1"), *clkey("cl1"), *lbkey("lb1"))
		},
		err: "",
		end: []*edgeproto.CloudletIPs{{
			Key: *ckey("c1"),
			ClusterIps: map[string]*edgeproto.ClusterIPs{
				clkey("cl1").GetKeyString(): {
					Key:              *clkey("cl1"),
					ControlPlaneIpv4: "10.10.10.150",
					LoadBalancers: map[string]*edgeproto.LoadBalancer{
						lbkey("lb2").GetKeyString(): {
							Key:  *lbkey("lb2"),
							Ipv4: "10.10.10.154",
						},
					},
				},
				clkey("cl2").GetKeyString(): {
					Key:              *clkey("cl2"),
					ControlPlaneIpv4: "10.10.10.153",
					LoadBalancers: map[string]*edgeproto.LoadBalancer{
						lbkey("lb1").GetKeyString(): {
							Key:  *lbkey("lb1"),
							Ipv4: "10.10.10.151",
						},
					},
				},
			},
		}},
	}, {
		desc: "free load balancer IP 2",
		start: []*edgeproto.CloudletIPs{{
			Key: *ckey("c1"),
			ClusterIps: map[string]*edgeproto.ClusterIPs{
				clkey("cl1").GetKeyString(): {
					Key:              *clkey("cl1"),
					ControlPlaneIpv4: "10.10.10.150",
					LoadBalancers: map[string]*edgeproto.LoadBalancer{
						lbkey("lb1").GetKeyString(): {
							Key:  *lbkey("lb1"),
							Ipv4: "10.10.10.152",
						},
						lbkey("lb2").GetKeyString(): {
							Key:  *lbkey("lb2"),
							Ipv4: "10.10.10.154",
						},
					},
				},
				clkey("cl2").GetKeyString(): {
					Key:              *clkey("cl2"),
					ControlPlaneIpv4: "10.10.10.153",
					LoadBalancers: map[string]*edgeproto.LoadBalancer{
						lbkey("lb1").GetKeyString(): {
							Key:  *lbkey("lb1"),
							Ipv4: "10.10.10.151",
						},
					},
				},
			},
		}},
		action: func() error {
			return cloudletIPs.FreeLoadBalancerIP(ctx, *ckey("c1"), *clkey("cl2"), *lbkey("lb1"))
		},
		err: "",
		end: []*edgeproto.CloudletIPs{{
			Key: *ckey("c1"),
			ClusterIps: map[string]*edgeproto.ClusterIPs{
				clkey("cl1").GetKeyString(): {
					Key:              *clkey("cl1"),
					ControlPlaneIpv4: "10.10.10.150",
					LoadBalancers: map[string]*edgeproto.LoadBalancer{
						lbkey("lb1").GetKeyString(): {
							Key:  *lbkey("lb1"),
							Ipv4: "10.10.10.152",
						},
						lbkey("lb2").GetKeyString(): {
							Key:  *lbkey("lb2"),
							Ipv4: "10.10.10.154",
						},
					},
				},
				clkey("cl2").GetKeyString(): {
					Key:              *clkey("cl2"),
					ControlPlaneIpv4: "10.10.10.153",
				},
			},
		}},
	}, {
		desc: "free control plane IP",
		start: []*edgeproto.CloudletIPs{{
			Key: *ckey("c1"),
			ClusterIps: map[string]*edgeproto.ClusterIPs{
				clkey("cl1").GetKeyString(): {
					Key:              *clkey("cl1"),
					ControlPlaneIpv4: "10.10.10.150",
					LoadBalancers: map[string]*edgeproto.LoadBalancer{
						lbkey("lb1").GetKeyString(): {
							Key:  *lbkey("lb1"),
							Ipv4: "10.10.10.152",
						},
						lbkey("lb2").GetKeyString(): {
							Key:  *lbkey("lb2"),
							Ipv4: "10.10.10.154",
						},
					},
				},
				clkey("cl2").GetKeyString(): {
					Key:              *clkey("cl2"),
					ControlPlaneIpv4: "10.10.10.153",
				},
			},
		}},
		stmcloudletkey: ckey("c1"),
		stmaction: func(stm concurrency.STM, cloudlet *edgeproto.Cloudlet) error {
			cloudletIPs.FreeControlPlaneIP(stm, cloudlet.Key, *clkey("cl2"))
			return nil
		},
		err: "",
		end: []*edgeproto.CloudletIPs{{
			Key: *ckey("c1"),
			ClusterIps: map[string]*edgeproto.ClusterIPs{
				clkey("cl1").GetKeyString(): {
					Key:              *clkey("cl1"),
					ControlPlaneIpv4: "10.10.10.150",
					LoadBalancers: map[string]*edgeproto.LoadBalancer{
						lbkey("lb1").GetKeyString(): {
							Key:  *lbkey("lb1"),
							Ipv4: "10.10.10.152",
						},
						lbkey("lb2").GetKeyString(): {
							Key:  *lbkey("lb2"),
							Ipv4: "10.10.10.154",
						},
					},
				},
			},
		}},
	}, {
		desc: "no more free IPs, reserve control plane IP",
		start: []*edgeproto.CloudletIPs{{
			Key: *ckey("c1"),
			ClusterIps: map[string]*edgeproto.ClusterIPs{
				clkey("cl1").GetKeyString(): {
					Key:              *clkey("cl1"),
					ControlPlaneIpv4: "10.10.10.150",
					LoadBalancers: map[string]*edgeproto.LoadBalancer{
						lbkey("lb1").GetKeyString(): {
							Key:  *lbkey("lb1"),
							Ipv4: "10.10.10.152",
						},
						lbkey("lb2").GetKeyString(): {
							Key:  *lbkey("lb2"),
							Ipv4: "10.10.10.154",
						},
					},
				},
				clkey("cl2").GetKeyString(): {
					Key:              *clkey("cl2"),
					ControlPlaneIpv4: "10.10.10.153",
				},
				clkey("cl3").GetKeyString(): {
					Key:              *clkey("cl3"),
					ControlPlaneIpv4: "10.10.10.151",
				},
			},
		}},
		stmcloudletkey: ckey("c1"),
		stmaction: func(stm concurrency.STM, cloudlet *edgeproto.Cloudlet) error {
			return cloudletIPs.ReserveControlPlaneIP(stm, cloudlet, cluster("cl4"))
		},
		err: "no free IP available",
	}, {
		desc: "no more free IPs, reserve load balancer IP",
		start: []*edgeproto.CloudletIPs{{
			Key: *ckey("c1"),
			ClusterIps: map[string]*edgeproto.ClusterIPs{
				clkey("cl1").GetKeyString(): {
					Key:              *clkey("cl1"),
					ControlPlaneIpv4: "10.10.10.150",
					LoadBalancers: map[string]*edgeproto.LoadBalancer{
						lbkey("lb1").GetKeyString(): {
							Key:  *lbkey("lb1"),
							Ipv4: "10.10.10.152",
						},
						lbkey("lb2").GetKeyString(): {
							Key:  *lbkey("lb2"),
							Ipv4: "10.10.10.154",
						},
					},
				},
				clkey("cl2").GetKeyString(): {
					Key:              *clkey("cl2"),
					ControlPlaneIpv4: "10.10.10.153",
				},
				clkey("cl3").GetKeyString(): {
					Key:              *clkey("cl3"),
					ControlPlaneIpv4: "10.10.10.151",
				},
			},
		}},
		action: func() error {
			_, err := cloudletIPs.ReserveLoadBalancerIP(ctx, *ckey("c1"), *clkey("cl2"), *lbkey("lb1"))
			return err
		},
		err: "no free IP available",
	}}

	for _, test := range tests {
		log.SpanLog(ctx, log.DebugLevelInfra, test.desc+" ===============")
		// set initial state
		for _, cips := range test.start {
			_, err := cloudletIPsCache.Store.Put(ctx, cips, sync.SyncWait)
			require.Nil(t, err, test.desc)
		}
		var err error
		// do action
		if test.stmaction != nil {
			_, err = sync.GetKVStore().ApplySTM(ctx, func(stm concurrency.STM) error {
				cloudlet := &edgeproto.Cloudlet{}
				if !cloudletCache.Store.STMGet(stm, test.stmcloudletkey, cloudlet) {
					return fmt.Errorf("%s test.stmcloudletkey not found: %s", test.desc, test.stmcloudletkey.GetKeyString())
				}
				return test.stmaction(stm, cloudlet)
			})
		} else {
			err = test.action()
		}
		var expState []*edgeproto.CloudletIPs
		if test.err == "" {
			require.NoError(t, err, test.desc)
			expState = test.end
		} else {
			require.NotNil(t, err, test.desc)
			require.Contains(t, err.Error(), test.err, test.desc)
			expState = test.start
		}
		// check final state
		outState := []*edgeproto.CloudletIPs{}
		cloudletIPsCache.Show(nil, func(obj *edgeproto.CloudletIPs) error {
			outState = append(outState, obj)
			return nil
		})
		slices.SortFunc(outState, func(a, b *edgeproto.CloudletIPs) int {
			return strings.Compare(a.Key.GetKeyString(), b.Key.GetKeyString())
		})
		if test.end == nil {
			test.end = []*edgeproto.CloudletIPs{}
		}
		require.Equal(t, expState, outState, test.desc)
		// cleanup
		for _, cips := range expState {
			_, err := cloudletIPsCache.Store.Delete(ctx, cips, sync.SyncWait)
			require.Nil(t, err, test.desc)
		}
	}
}
