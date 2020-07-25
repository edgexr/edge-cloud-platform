package vmlayer

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/mobiledgex/edge-cloud-infra/infracommon"
	"github.com/mobiledgex/edge-cloud/cloudcommon"
	"github.com/mobiledgex/edge-cloud/edgeproto"

	sh "github.com/codeskyblue/go-sh"
	"github.com/mobiledgex/edge-cloud/log"
	ssh "github.com/mobiledgex/golang-ssh"
	"github.com/tmc/scp"
)

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

//CopySSHCredential copies over the ssh credential for mex to LB
func (v *VMPlatform) CopySSHCredential(ctx context.Context, serverName, networkName, userName string) error {
	//TODO multiple keys to be copied and added to authorized_keys if needed
	log.SpanLog(ctx, log.DebugLevelInfra, "copying ssh credentials", "server", serverName, "network", networkName, "user", userName)
	ip, err := v.GetIPFromServerName(ctx, networkName, "", serverName)
	if err != nil {
		return err
	}
	kf := infracommon.PrivateSSHKey()
	out, err := sh.Command("scp", "-o", infracommon.SSHOpts[0], "-o", infracommon.SSHOpts[1], "-i", kf, kf, userName+"@"+ip.ExternalAddr+":").Output()
	if err != nil {
		return fmt.Errorf("can't copy %s to %s, %s, %v", kf, ip.ExternalAddr, out, err)
	}
	return nil
}

//GetSSHClientFromIPAddr returns ssh client handle for the given IP.
func (vp *VMProperties) GetSSHClientFromIPAddr(ctx context.Context, ipaddr string, ops ...SSHClientOp) (ssh.Client, error) {
	opts := SSHOptions{Timeout: infracommon.DefaultConnectTimeout, User: infracommon.SSHUser}
	opts.Apply(ops)
	var client ssh.Client
	var err error
	auth := ssh.Auth{Keys: []string{infracommon.PrivateSSHKey()}}
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

func (v *VMPlatform) SetupSSHUser(ctx context.Context, rootLB *MEXRootLB, user string) (ssh.Client, error) {
	log.SpanLog(ctx, log.DebugLevelInfra, "setting up ssh user", "user", user)
	client, err := v.GetSSHClientForServer(ctx, rootLB.Name, v.VMProperties.GetCloudletExternalNetwork(), WithUser(user))
	if err != nil {
		return nil, err
	}
	// XXX cloud-init creates non root user but it does not populate all the needed files.
	//  packer will create images with correct things for root .ssh. It cannot provision
	//  them for the `ubuntu` user. It may not yet exist until cloud-init runs. So we fix it here.
	for _, cmd := range []string{
		fmt.Sprintf("sudo cp /root/.ssh/config /home/%s/.ssh/", user),
		fmt.Sprintf("sudo chown %s:%s /home/%s/.ssh/config", user, user, user),
		fmt.Sprintf("sudo chmod 600 /home/%s/.ssh/config", user),
		fmt.Sprintf("sudo cp /root/%s /home/%s/", infracommon.SSHPrivateKeyName, user),
		fmt.Sprintf("sudo chown %s:%s   /home/%s/%s", user, user, user, infracommon.SSHPrivateKeyName),
		fmt.Sprintf("sudo chmod 600   /home/%s/%s", user, infracommon.SSHPrivateKeyName),
	} {
		out, err := client.Output(cmd)
		if err != nil {
			log.SpanLog(ctx, log.DebugLevelInfra, "error setting up ssh user",
				"user", user, "error", err, "out", out)
			return nil, err
		}
	}
	return client, nil
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

// WaitServerSSHReachable waits up to the specified duration for the server to be reachable via
// SSH. The server passed here is just for logging it can be an ip or a name
func WaitServerSSHReachable(ctx context.Context, client ssh.Client, server string, timeout time.Duration) error {
	log.SpanLog(ctx, log.DebugLevelInfra, "WaitServerSSHReachable", "server", server)
	start := time.Now()
	for {
		out, err := client.Output(fmt.Sprintf("whoami"))
		if err == nil {
			break
		} else {
			log.SpanLog(ctx, log.DebugLevelInfra, "error waiting for server", "out", out, "error", err)
			if strings.Contains(err.Error(), "ssh client timeout") || strings.Contains(err.Error(), "ssh dial fail") {
				elapsed := time.Since(start)
				if elapsed > timeout {
					return fmt.Errorf("timed out connecting to VM %s", server)
				}
				log.SpanLog(ctx, log.DebugLevelInfra, "sleeping 10 seconds before retry", "elapsed", elapsed)
				time.Sleep(10 * time.Second)
			} else {
				return fmt.Errorf("WaitServerSSHReachable fail: server :%s is unreachable: %v, %s", server, err, out)
			}
		}
	}
	log.SpanLog(ctx, log.DebugLevelInfra, "WaitServerSSHReachable OK", "server", server)
	return nil
}
