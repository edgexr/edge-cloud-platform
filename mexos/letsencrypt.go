package mexos

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"strings"
	"time"

	sh "github.com/codeskyblue/go-sh"
	"github.com/mobiledgex/edge-cloud/log"
)

//TODO acme.sh seems to leave out _acme domains. We need to clean up periodically

func getPEMContent(fn string) ([]byte, error) {
	content, err := ioutil.ReadFile(fn)
	if err != nil {
		log.DebugLog(log.DebugLevelMexos, "can't read downloaded pem file", "name", fn, "error", err)
		return nil, fmt.Errorf("can't read downloaded pem file %s, %v", fn, err)
	}
	contstr := string(content)
	if strings.Contains(contstr, "404 Not Found") {
		log.DebugLog(log.DebugLevelMexos, "404 not found in pem file", "name", fn)
		return nil, fmt.Errorf("registry does not have the pem file %s", fn)
	}
	if !strings.HasPrefix(contstr, "-----BEGIN") {
		log.DebugLog(log.DebugLevelMexos, "does not look like pem file", "name", fn)
		return nil, fmt.Errorf("does not look like pem file %s", fn)
	}
	return content, nil
}

func checkPEMFile(fn string) error {
	_, err := getPEMContent(fn)
	return err
}

func checkPEMCert(fn, fqdn string) error {
	content, err := getPEMContent(fn)
	if err != nil {
		return err
	}
	block, _ := pem.Decode(content)
	if block == nil {
		log.DebugLog(log.DebugLevelMexos, "decode pem failed", "name", fn, "err", err)
		return fmt.Errorf("decode pem cert %s failed", fn)
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		log.DebugLog(log.DebugLevelMexos, "parse cert failed", "name", fn, "err", err)
		return fmt.Errorf("failed to parse certificate %s, %s", fn, err.Error())
	}
	// Validate cert. Unfortunately, cert.Verify() returns
	// "x509: certificate signed by unknown authority" for the
	// lets encrypt cert, so just check expiration date.
	now := time.Now()
	if now.Before(cert.NotBefore) || now.After(cert.NotAfter) {
		return fmt.Errorf("certificate expired for %s", fqdn)
	}
	log.DebugLog(log.DebugLevelMexos, "cert valid", "name", fn, "fqdn", fqdn)
	return nil
}

//AcquireCertificates obtains certficates from Letsencrypt over ACME. It should be used carefully. The API calls have quota.
func AcquireCertificates(fqdn string) error {
	log.DebugLog(log.DebugLevelMexos, "acquiring certificates for FQDN", "FQDN", fqdn)
	kf := PrivateSSHKey()
	srcfile := fmt.Sprintf("mobiledgex@%s:files-repo/certs/%s/fullchain.cer", GetCloudletRegistryFileServer(), fqdn)
	dkey := fmt.Sprintf("%s/%s.key", fqdn, fqdn)
	certfile := "cert.pem"
	keyfile := "key.pem"
	log.DebugLog(log.DebugLevelMexos, "trying to get cached cert files", "srcfile", srcfile)
	out, err := sh.Command("scp", "-o", sshOpts[0], "-o", sshOpts[1], "-i", kf, srcfile, certfile).CombinedOutput()
	if err != nil {
		log.DebugLog(log.DebugLevelMexos, "Failed to get cached cert file", "src", srcfile, "cert", certfile, "error", err, "out", string(out))
		if strings.Contains(string(out), "No such file or directory") {
			log.DebugLog(log.DebugLevelMexos, "Cert file not found, continuing")
		} else {
			// perhaps permission problem or other error.  Do not continue as this may be a problem
			// which will cause us to  exhaust our letsencrypt API limits
			log.InfoLog("Unexpected error attempting to get cached cert", "registry", GetCloudletRegistryFileServer(), "out", string(out))
			return fmt.Errorf("Unable to SCP to registry: %s, %v", GetCloudletRegistryFileServer(), err)
		}

	} else if checkPEMCert(certfile, fqdn) == nil {
		srcfile = fmt.Sprintf("mobiledgex@%s:files-repo/certs/%s", GetCloudletRegistryFileServer(), dkey)
		out, err = sh.Command("scp", "-o", sshOpts[0], "-o", sshOpts[1], "-i", kf, srcfile, keyfile).Output()
		if err != nil {
			log.DebugLog(log.DebugLevelMexos, "warning, failed to get cached key file", "src", srcfile, "cert", certfile, "error", err, "out", out)
		} else if checkPEMFile(keyfile) == nil {
			//because Letsencrypt complains if we get certs repeated for the same fqdn
			log.DebugLog(log.DebugLevelMexos, "got cached certs from registry", "FQDN", fqdn)
			addr, ierr := GetServerIPAddr(GetCloudletExternalNetwork(), fqdn) //XXX should just use fqdn but paranoid
			if ierr != nil {
				log.DebugLog(log.DebugLevelMexos, "failed to get server ip addr", "FQDN", fqdn, "error", ierr)
				return ierr
			}
			client, err := GetSSHClient(fqdn, GetCloudletExternalNetwork(), SSHUser)
			if err != nil {
				return fmt.Errorf("can't get ssh client for cert, %v", err)
			}
			for _, fn := range []string{certfile, keyfile} {
				out, oerr := sh.Command("scp", "-o", sshOpts[0], "-o", sshOpts[1], "-i", kf, fn, SSHUser+"@"+addr+":").CombinedOutput()
				if oerr != nil {
					return fmt.Errorf("cannot copy %s to %s, %v, %v", fn, addr, oerr, string(out))
				}
				log.DebugLog(log.DebugLevelMexos, "copied", "fn", fn, "addr", addr)
				if out, err := client.Output(fmt.Sprintf("sudo cp %s /root", fn)); err != nil {
					return fmt.Errorf("cannot copy %s to /root, %v, %s", fn, err, out)
				}
			}
			log.DebugLog(log.DebugLevelMexos, "using cached cert and key", "FQDN", fqdn)
			return nil
		}
	}
	log.DebugLog(log.DebugLevelMexos, "did not get cached cert and key files, will try to acquire new cert")
	client, err := GetSSHClient(fqdn, GetCloudletExternalNetwork(), SSHUser)
	if err != nil {
		return fmt.Errorf("can't get ssh client for acme.sh, %v", err)
	}
	fullchain := fqdn + "/fullchain.cer"
	cmd := fmt.Sprintf("ls -a %s", fullchain)
	_, err = client.Output(cmd)
	if err == nil {
		return nil
	}
	cmd = fmt.Sprintf("docker run --rm -e CF_Key=%s -e CF_Email=%s -v `pwd`:/acme.sh --net=host neilpang/acme.sh --issue -d %s --dns dns_cf", GetCloudletCFKey(), GetCloudletCFUser(), fqdn)
	log.DebugLog(log.DebugLevelMexos, "running acme.sh to get cert", "cmd", cmd)

	res, err := client.Output(cmd)
	if err != nil {
		return fmt.Errorf("error running acme.sh docker, %s, %v", res, err)
	}
	cmd = fmt.Sprintf("ls -a %s", fullchain)
	success := false
	for i := 0; i < 10; i++ {
		_, err = client.Output(cmd)
		if err == nil {
			success = true
			break
		}
		log.DebugLog(log.DebugLevelMexos, "waiting for letsencrypt...")
		time.Sleep(30 * time.Second) // ACME takes minimum 200 seconds
	}
	if !success {
		return fmt.Errorf("timeout waiting for ACME")
	}
	for _, d := range []struct{ src, dest string }{
		{fullchain, certfile},
		{dkey, keyfile},
	} {
		cmd = fmt.Sprintf("cp %s %s", d.src, d.dest)
		res, err := client.Output(cmd)
		if err != nil {
			return fmt.Errorf("fail to copy %s to %s on %s, %v, %v", d.src, d.dest, fqdn, err, res)
		}
		if out, err := client.Output(fmt.Sprintf("sudo cp %s /root", d.dest)); err != nil {
			return fmt.Errorf("cannot copy %s to /root, %v, %s", d.dest, err, out)
		}
	}
	cmd = fmt.Sprintf("scp -o %s -o %s -i id_rsa_mex -r %s mobiledgex@%s:files-repo/certs", sshOpts[0], sshOpts[1], fqdn, GetCloudletRegistryFileServer()) // XXX
	res, err = client.Output(cmd)
	if err != nil {
		return fmt.Errorf("failed to upload certs for %s, %v, %v", fqdn, err, res)
	}
	log.DebugLog(log.DebugLevelMexos, "saved acquired cert and key", "FQDN", fqdn)
	return nil
}
