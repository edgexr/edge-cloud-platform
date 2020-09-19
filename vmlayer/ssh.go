package vmlayer

import (
	"context"
	"fmt"
	"time"

	"github.com/mobiledgex/edge-cloud-infra/infracommon"
	"github.com/mobiledgex/edge-cloud/cloud-resource-manager/platform"
	"github.com/mobiledgex/edge-cloud/cloud-resource-manager/platform/pc"
	"github.com/mobiledgex/edge-cloud/cloudcommon"
	"github.com/mobiledgex/edge-cloud/edgeproto"
	"github.com/mobiledgex/edge-cloud/log"
	"github.com/mobiledgex/edge-cloud/vault"
	ssh "github.com/mobiledgex/golang-ssh"
	"github.com/tmc/scp"
)

var CloudletSSHKeyRefreshInterval = 24 * time.Hour

type VMAccess struct {
	Name   string
	Client ssh.Client
	Role   VMRole
}

type SSHOptions struct {
	Timeout time.Duration
	User    string
}

type SSHClientOp func(sshp *SSHOptions) error

func WithUser(user string) SSHClientOp {
	return func(op *SSHOptions) error {
		op.User = user
		return nil
	}
}

func WithTimeout(timeout time.Duration) SSHClientOp {
	return func(op *SSHOptions) error {
		op.Timeout = timeout
		return nil
	}
}

func (o *SSHOptions) Apply(ops []SSHClientOp) {
	for _, op := range ops {
		op(o)
	}
}

func (v *VMPlatform) SetCloudletSignedSSHKey(ctx context.Context, vaultConfig *vault.Config) error {
	log.SpanLog(ctx, log.DebugLevelInfra, "Sign cloudlet public key from Vault")

	data := map[string]interface{}{
		"public_key": v.VMProperties.sshKey.PublicKey,
	}
	signedKey, err := infracommon.GetSignedKeyFromVault(vaultConfig, data)
	if err != nil {
		return err
	}

	v.VMProperties.sshKey.Mux.Lock()
	defer v.VMProperties.sshKey.Mux.Unlock()
	v.VMProperties.sshKey.SignedPublicKey = signedKey

	return nil
}

func (v *VMPlatform) triggerRefreshCloudletSSHKeys() {
	select {
	case v.VMProperties.sshKey.RefreshTrigger <- true:
	default:
	}
}

func (v *VMPlatform) RefreshCloudletSSHKeys(vaultConfig *vault.Config) {
	interval := CloudletSSHKeyRefreshInterval
	for {
		select {
		case <-time.After(interval):
		case <-v.VMProperties.sshKey.RefreshTrigger:
			span := log.StartSpan(log.DebugLevelInfra, "refresh Cloudlet SSH Key")
			ctx := log.ContextWithSpan(context.Background(), span)
			err := v.SetCloudletSignedSSHKey(ctx, vaultConfig)
			if err != nil {
				log.SpanLog(ctx, log.DebugLevelInfra, "refresh cloudlet ssh key failure", "err", err)
				// retry again soon
				interval = time.Hour
			} else {
				interval = CloudletSSHKeyRefreshInterval
			}
			span.Finish()
		}
	}
}

func (v *VMPlatform) InitCloudletSSHKeys(ctx context.Context, vaultConfig *vault.Config) error {
	// Generate Cloudlet SSH Keys
	cloudletPubKey, cloudletPrivKey, err := ssh.GenKeyPair()
	if err != nil {
		return fmt.Errorf("failed to generate cloudlet SSH key pair: %v", err)
	}
	v.VMProperties.sshKey.PublicKey = cloudletPubKey
	v.VMProperties.sshKey.PrivateKey = cloudletPrivKey
	err = v.SetCloudletSignedSSHKey(ctx, vaultConfig)
	if err != nil {
		return err
	}
	v.VMProperties.sshKey.RefreshTrigger = make(chan bool, 1)
	return nil
}

//GetSSHClientFromIPAddr returns ssh client handle for the given IP.
func (vp *VMProperties) GetSSHClientFromIPAddr(ctx context.Context, ipaddr string, ops ...SSHClientOp) (ssh.Client, error) {
	opts := SSHOptions{Timeout: infracommon.DefaultConnectTimeout, User: infracommon.SSHUser}
	opts.Apply(ops)
	var client ssh.Client
	var err error

	if vp.sshKey.PrivateKey == "" {
		return nil, fmt.Errorf("missing cloudlet private key")
	}
	if vp.sshKey.SignedPublicKey == "" {
		return nil, fmt.Errorf("missing cloudlet signed public Key")
	}

	vp.sshKey.Mux.Lock()
	auth := ssh.Auth{
		KeyPairs: []ssh.KeyPair{
			ssh.KeyPair{
				PublicRawKey:  []byte(vp.sshKey.SignedPublicKey),
				PrivateRawKey: []byte(vp.sshKey.PrivateKey),
			},
		},
	}
	vp.sshKey.Mux.Unlock()

	if vp.sshKey.UseMEXPrivateKey {
		auth = ssh.Auth{RawKeys: [][]byte{
			[]byte(vp.sshKey.MEXPrivateKey),
		}}
	}

	gwhost, gwport := vp.GetCloudletCRMGatewayIPAndPort()
	if gwhost != "" {
		// start the client to GW and add the addr as next hop
		client, err = ssh.NewNativeClient(opts.User, infracommon.ClientVersion, gwhost, gwport, &auth, opts.Timeout, nil)
		if err != nil {
			return nil, err
		}
		client, err = client.AddHop(ipaddr, 22)
		if err != nil {
			return nil, err
		}
	} else {
		var err error
		client, err = ssh.NewNativeClient(infracommon.SSHUser, infracommon.ClientVersion, ipaddr, 22, &auth, opts.Timeout, nil)
		if err != nil {
			return nil, fmt.Errorf("cannot get ssh client for addr %s, %v", ipaddr, err)
		}
	}
	log.SpanLog(ctx, log.DebugLevelInfra, "Created SSH Client", "ipaddr", ipaddr, "gwhost", gwhost, "timeout", opts.Timeout)
	return client, nil
}

func (v *VMPlatform) GetSSHClientForCluster(ctx context.Context, clusterInst *edgeproto.ClusterInst) (ssh.Client, error) {
	rootLBName := v.VMProperties.SharedRootLBName
	if clusterInst.IpAccess == edgeproto.IpAccess_IP_ACCESS_DEDICATED {
		rootLBName = cloudcommon.GetDedicatedLBFQDN(v.VMProperties.CommonPf.PlatformConfig.CloudletKey, &clusterInst.Key.ClusterKey, v.VMProperties.CommonPf.PlatformConfig.AppDNSRoot)
	}
	return v.GetSSHClientForServer(ctx, rootLBName, v.VMProperties.GetCloudletExternalNetwork())
}

//GetSSHClient returns ssh client handle for the server
func (v *VMPlatform) GetSSHClientForServer(ctx context.Context, serverName, networkName string, ops ...SSHClientOp) (ssh.Client, error) {
	// if this is a rootLB we may have the IP cached already
	var externalAddr string
	rootLB, err := GetRootLB(ctx, serverName)
	if err == nil && rootLB != nil {
		if rootLB.IP != nil {
			log.SpanLog(ctx, log.DebugLevelInfra, "using existing rootLB IP", "IP", rootLB.IP)
			externalAddr = rootLB.IP.ExternalAddr
		}
	}
	if externalAddr == "" {
		serverIp, err := v.GetIPFromServerName(ctx, networkName, "", serverName)
		if err != nil {
			return nil, err
		}
		externalAddr = serverIp.ExternalAddr
	}
	return v.VMProperties.GetSSHClientFromIPAddr(ctx, externalAddr, ops...)
}

func SCPFilePath(sshClient ssh.Client, srcPath, dstPath string) error {
	client, ok := sshClient.(*ssh.NativeClient)
	if !ok {
		return fmt.Errorf("unable to cast client to native client")
	}
	session, sessionInfo, err := client.Session(client.DefaultClientConfig.Timeout)
	if err != nil {
		return err
	}
	defer sessionInfo.CloseAll()
	err = scp.CopyPath(srcPath, dstPath, session)
	return err
}

func (v *VMPlatform) GetAllCloudletVMs(ctx context.Context, caches *platform.Caches) ([]VMAccess, error) {
	// Store in slice as to preserve order
	cloudletVMs := []VMAccess{}

	// Platform VM Name
	pfName := v.GetPlatformVMName(v.VMProperties.CommonPf.PlatformConfig.CloudletKey)
	client, err := v.GetSSHClientForServer(ctx, pfName, v.VMProperties.GetCloudletExternalNetwork())
	if err != nil {
		log.SpanLog(ctx, log.DebugLevelInfra, "error getting ssh client", "vm", pfName, "err", err)
	}
	cloudletVMs = append(cloudletVMs, VMAccess{
		Name:   pfName,
		Client: client,
		Role:   RoleVMPlatform,
	})

	// Shared RootLB
	sharedRootLBName := v.VMProperties.SharedRootLBName
	sharedlbclient, err := v.GetSSHClientForServer(ctx, sharedRootLBName, v.VMProperties.GetCloudletExternalNetwork())
	if err != nil {
		log.SpanLog(ctx, log.DebugLevelInfra, "error getting ssh client", "vm", sharedRootLBName, "err", err)
	}
	cloudletVMs = append(cloudletVMs, VMAccess{
		Name:   sharedRootLBName,
		Client: sharedlbclient,
		Role:   RoleAgent,
	})

	// Dedicated RootLB + Cluster VMs
	clusterInstKeys := make(map[edgeproto.ClusterInstKey]struct{})
	caches.ClusterInstCache.GetAllKeys(ctx, func(k *edgeproto.ClusterInstKey, modRev int64) {
		clusterInstKeys[*k] = struct{}{}
	})
	var clusterInst *edgeproto.ClusterInst
	for k := range clusterInstKeys {
		if !caches.ClusterInstCache.Get(&k, clusterInst) {
			var dedicatedlbclient ssh.Client
			if clusterInst.IpAccess == edgeproto.IpAccess_IP_ACCESS_DEDICATED {
				rootLBName := v.VMProperties.GetRootLBNameForCluster(ctx, clusterInst)
				dedicatedlbclient, err = v.GetSSHClientForServer(ctx, rootLBName, v.VMProperties.GetCloudletExternalNetwork())
				if err != nil {
					log.SpanLog(ctx, log.DebugLevelInfra, "error getting ssh client", "vm", rootLBName, "err", err)
				}
				cloudletVMs = append(cloudletVMs, VMAccess{
					Name:   rootLBName,
					Client: dedicatedlbclient,
					Role:   RoleAgent,
				})
			}
			var lbClient ssh.Client
			if dedicatedlbclient != nil {
				lbClient = dedicatedlbclient
			} else {
				lbClient = sharedlbclient
			}

			masterNode := GetClusterMasterName(ctx, clusterInst)
			masterIP, err := v.GetIPFromServerName(ctx, v.VMProperties.GetCloudletMexNetwork(), GetClusterSubnetName(ctx, clusterInst), masterNode)
			if err != nil {
				log.SpanLog(ctx, log.DebugLevelInfra, "error getting ssh client", "vm", masterNode, "err", err)
			}
			masterClient, err := lbClient.AddHop(masterIP.ExternalAddr, 22)
			cloudletVMs = append(cloudletVMs, VMAccess{
				Name:   masterNode,
				Client: masterClient,
				Role:   RoleMaster,
			})
			for nn := uint32(1); nn <= clusterInst.NumNodes; nn++ {
				clusterNode := GetClusterNodeName(ctx, clusterInst, nn)
				nodeIP, err := v.GetIPFromServerName(ctx, v.VMProperties.GetCloudletMexNetwork(), GetClusterSubnetName(ctx, clusterInst), clusterNode)
				if err != nil {
					log.SpanLog(ctx, log.DebugLevelInfra, "error getting ssh client", "vm", clusterNode, "err", err)
				}
				nodeClient, err := lbClient.AddHop(nodeIP.ExternalAddr, 22)
				cloudletVMs = append(cloudletVMs, VMAccess{
					Name:   clusterNode,
					Client: nodeClient,
					Role:   RoleNode,
				})
			}
		}
	}
	return cloudletVMs, nil
}

func GetVaultCAScript(vaultConfig *vault.Config) string {
	return fmt.Sprintf(`
#!/bin/bash

die() {
        echo "ERROR: $*" >&2
        exit 2
}

curl %s/v1/ssh/public_key | sudo tee /etc/ssh/trusted-user-ca-keys.pem
[[ $? -ne 0 ]] && die "failed to get CA cert from vault"
sudo grep "ssh-rsa" /etc/ssh/trusted-user-ca-keys.pem
[[ $? -ne 0 ]] && die "invalid CA cert from vault"

echo 'TrustedUserCAKeys /etc/ssh/trusted-user-ca-keys.pem' | sudo tee -a /etc/ssh/sshd_config
sudo systemctl reload ssh
[[ $? -ne 0 ]] && die "failed to reload ssh"

rm -f id_rsa_mex
echo "" > .ssh/authorized_keys

echo "Done setting up vault ssh"
`, vaultConfig.Addr)
}

func GetVaultCAScriptForMasterNode(vaultConfig *vault.Config) string {
	k8sJoinSvcScript := `
mkdir -p /var/tmp/k8s-join
cp /tmp/k8s-join-cmd.tmp /var/tmp/k8s-join/k8s-join-cmd
[[ $? -ne 0 ]] && die "failed to copy k8s-join-cmd.tmp file"
chown ubuntu:ubuntu /var/tmp/k8s-join/k8s-join-cmd

sudo tee /etc/systemd/system/k8s-join.service <<'EOT'
[Unit]
Description=Job that runs k8s join script server
[Service]
Type=simple
WorkingDirectory=/var/tmp/k8s-join
ExecStart=/usr/bin/python3 -m http.server 8000
Restart=always
[Install]
WantedBy=multi-user.target
EOT

sudo systemctl enable k8s-join
[[ $? -ne 0 ]] && die "failed to enable k8s-join service"
sudo systemctl start k8s-join
[[ $? -ne 0 ]] && die "failed to start k8s-join service"

echo "Done setting k8s-join service"
`
	vaultCAScript := GetVaultCAScript(vaultConfig)
	return vaultCAScript + k8sJoinSvcScript
}

func ExecuteUpgradeScript(ctx context.Context, vmName string, client ssh.Client, script string) error {
	log.SpanLog(ctx, log.DebugLevelInfra, "execute upgrade script", "vmName", vmName)
	err := pc.WriteFile(client, "upgradeCRMVault.sh", script, "upgrade script", pc.NoSudo)
	if err != nil {
		log.SpanLog(ctx, log.DebugLevelInfra, "failed to copy script", "err", err)
		return err
	}
	// Execute script
	out, err := client.Output("bash upgradeCRMVault.sh")
	if err != nil {
		log.SpanLog(ctx, log.DebugLevelInfra, "failed to fix vm", "out", out, "err", err)
		return err
	}
	return nil
}

func (v *VMPlatform) UpgradeFuncHandleSSHKeys(ctx context.Context, vaultConfig *vault.Config, caches *platform.Caches) (map[string]string, error) {
	log.SpanLog(ctx, log.DebugLevelInfra, "Upgrade Vms to use Vault SSH signed keys")
	// Set SSH client to use mex private key
	v.VMProperties.sshKey.UseMEXPrivateKey = true
	fixVMs, err := v.GetAllCloudletVMs(ctx, caches)
	if err != nil {
		return nil, err
	}

	for _, vm := range fixVMs {
		if vm.Client == nil {
			log.SpanLog(ctx, log.DebugLevelInfra, "missing ssh client", "vm", vm.Name)
			continue
		}
		script := ""
		if vm.Role == RoleMaster {
			// Start k8s-join webserver
			script = GetVaultCAScriptForMasterNode(vaultConfig)
		} else {
			script = GetVaultCAScript(vaultConfig)
		}
		err = ExecuteUpgradeScript(ctx, vm.Name, vm.Client, script)
		if err != nil {
			// continue fixing other VMs
			continue
		}
	}

	// Validate VMs with new vault SSH fix
	// Set SSH client to use vault signed Keys
	v.VMProperties.sshKey.UseMEXPrivateKey = false
	fixVMs, err = v.GetAllCloudletVMs(ctx, caches)
	if err != nil {
		return nil, err
	}
	results := make(map[string]string)
	for _, vm := range fixVMs {
		if vm.Client == nil {
			results[vm.Name] = "failed to get ssh client"
			continue
		}
		_, err = vm.Client.Output("hostname")
		if err != nil {
			results[vm.Name] = fmt.Sprintf("failed with error: %v", err)
			continue
		}
		results[vm.Name] = "fixed"
	}
	log.SpanLog(ctx, log.DebugLevelInfra, "Upgrade results", "results", results)
	return results, nil
}
