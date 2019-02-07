package mexos

/*
func CreateDockerSwarm(clusterName, rootLBName) error {
	//TODO independent swarm cluster without k8s
	log.DebugLog(log.DebugLevelMexos, "creating docker swarm", "name", clusterName)
	name, err := FindClusterWithKey(clusterName)
	if err != nil {
		return err
	}
	client, err := GetSSHClient(rootLB.Name, GetCloudletExternalNetwork(), sshUser)
	if err != nil {
		return fmt.Errorf("can't get ssh client for docker swarm, %v", err)
	}
	masteraddr, err := FindNodeIP(name)
	if err != nil {
		return err
	}
	cmd := fmt.Sprintf("ssh -o %s -o %s -o %s -i id_rsa_mex %s@%s docker swarm init --advertise-addr %s", sshOpts[0], sshOpts[1], sshOpts[2], sshUser, masteraddr, masteraddr)
	log.DebugLog(log.DebugLevelMexos, "running docker swarm init", "cmd", cmd)
	out, err := client.Output(cmd)
	if err != nil {
		log.DebugLog(log.DebugLevelMexos, "error, docker swarm init", "out", out, "err", err)
		return fmt.Errorf("cannot docker swarm init, %v, %s", err, out)
	}
	cmd = fmt.Sprintf("ssh -o %s -o %s -o %s -i id_rsa_mex %s@%s docker swarm join-token worker -q", sshOpts[0], sshOpts[1], sshOpts[2], sshUser, masteraddr)
	out, err = client.Output(cmd)
	if err != nil {
		log.DebugLog(log.DebugLevelMexos, "error, docker swarm join-token", "out", out, "err", err)
		return fmt.Errorf("cannot docker swarm join-token worker, %v, %s", err, out)
	}
	token := strings.TrimSpace(out)
	if len(token) < 1 {
		return fmt.Errorf("docker join token too short")
	}
	knodes, err := GetKubernetesNodes(mf, rootLB)
	if err != nil {
		return err
	}
	nodesJoined := 0
	for _, n := range knodes {
		if n.Role == "master" {
			continue
		}
		if n.Addr == "" {
			errmsg := fmt.Sprintf("missing address for kubernetes node, %v", n)
			log.DebugLog(log.DebugLevelMexos, errmsg)
			return fmt.Errorf(errmsg)
		}
		log.DebugLog(log.DebugLevelMexos, "docker worker node join", "node", n)
		cmd = fmt.Sprintf("ssh -o %s -o %s -o %s -i id_rsa_mex %s@%s docker swarm join --token %s %s:2377", sshOpts[0], sshOpts[1], sshOpts[2], sshUser, n.Addr, token, masteraddr)
		out, err = client.Output(cmd)
		if err != nil {
			errmsg := fmt.Sprintf("cannot docker swarm join, %v, %s, cmd %s", err, out, cmd)
			log.DebugLog(log.DebugLevelMexos, errmsg)
			return fmt.Errorf(errmsg)
		}
		nodesJoined++
	}
	log.DebugLog(log.DebugLevelMexos, "ok, docker swarm nodes joined", "num worker nodes", nodesJoined)
	return nil
}


//TODO make it support full docker-compose file spec.

type DockerService struct {
	Image string   `json:"image"`
	Build string   `json:"build"`
	Ports []string `json:"ports"`
}

type DockerCompose struct {
	Version  string                   `json:"version"`
	Services map[string]DockerService `json:"services"`
}


func CreateDockerSwarmAppManifest(mf *Manifest) error {
	log.DebugLog(log.DebugLevelMexos, "create docker-swarm app")
	rootLB, err := getRootLB(mf.Spec.RootLB)
	if err != nil {
		return err
	}
	if rootLB == nil {
		return fmt.Errorf("docker swarm app manifest, rootLB is null")
	}
	name, err := FindClusterWithKey(mf, mf.Spec.Key)
	if err != nil {
		return fmt.Errorf("can't find cluster with key %s, %v", mf.Spec.Key, err)
	}
	masteraddr, err := FindNodeIP(name)
	if err != nil {
		return err
	}
	var cmd string
	if GetCloudletDockerPass() == "" {
		return fmt.Errorf("empty docker registry password environment variable")
	}
	client, err := GetSSHClient(rootLB.Name, GetCloudletExternalNetwork(), sshUser)
	if err != nil {
		return err
	}
	base := rootLB.PlatConf.Base
	if base == "" {
		log.DebugLog(log.DebugLevelMexos, "base is empty, using default")
		base = GetDefaultRegistryBase(mf, base)
	}
	mani := mf.Config.ConfigDetail.Manifest
	fn := fmt.Sprintf("%s/%s", base, mani)
	res, err := GetURIFile(mf, fn)
	if err != nil {
		return fmt.Errorf("error getting docker compose manifest, %v", err)
	}
	dc := &DockerCompose{}
	if err := yaml.Unmarshal(res, dc); err != nil {
		return fmt.Errorf("cannot unmarshal docker compose file, %v", err)
	}
	dcfn := fmt.Sprintf("docker-compose-%s.yaml", mf.Metadata.Name)
	log.DebugLog(log.DebugLevelMexos, "writing docker-compose file", "fn", dcfn)
	cmd = fmt.Sprintf("cat <<'EOF'> %s \n%s\nEOF", dcfn, string(res))
	out, err := client.Output(cmd)
	if err != nil {
		return fmt.Errorf("error writing docker-compose yaml, %s, %v", out, err)
	}
	cmd = fmt.Sprintf("scp -i id_rsa_mex %s %s:", dcfn, masteraddr)
	out, err = client.Output(cmd)
	if err != nil {
		return fmt.Errorf("error copying docker-compose yaml, %s, %v", out, err)
	}
	log.DebugLog(log.DebugLevelMexos, "deploying docker stack", "name", mf.Metadata.Name)
	cmd = fmt.Sprintf("ssh -i id_rsa_mex %s docker stack deploy --compose-file %s %s", masteraddr, dcfn, mf.Metadata.Name)
	out, err = client.Output(cmd)
	if err != nil {
		return fmt.Errorf("error deploying docker-swarm app, %s, %s, %v", cmd, out, err)
	}
	if err := DockerComposePorts(mf, dc); err != nil {
		return err
	}
	log.DebugLog(log.DebugLevelMexos, "adding proxy and security rules", "name", mf.Metadata.Name)
	if err = AddProxySecurityRules(rootLB, mf, masteraddr); err != nil {
		log.DebugLog(log.DebugLevelMexos, "cannot create security rules", "error", err)
		return err
	}
	log.DebugLog(log.DebugLevelMexos, "ok, docker stack deployed", "name", mf.Metadata.Name, "fn", dcfn, "ports", mf.Spec.Ports)
	// TODO add custom DNS entries per app service endpoints
	return nil
}

func DockerComposePorts(mf *Manifest, dc *DockerCompose) error {
	//TODO more complete syntax support for docker swarm ports
	//    https://docs.docker.com/compose/compose-file/#ports
	mf.Spec.Ports = make([]PortDetail, 0)
	for k, svc := range dc.Services {
		if svc.Ports != nil {
			for _, pp := range svc.Ports {
				ps := strings.Split(pp, ":")
				if len(ps) != 2 {
					return fmt.Errorf("malformed port pair in docker swarm svc ports, %s", pp)
				}
				intp, err := strconv.Atoi(ps[0])
				if err != nil {
					return fmt.Errorf("cannot convert internalport, %s", pp)
				}
				pubp, err := strconv.Atoi(ps[1])
				if err != nil {
					return fmt.Errorf("cannot convert publicport, %s", pp)
				}
				pd := PortDetail{
					Name:         fmt.Sprintf("%s%d", k, pubp),
					MexProto:     "LProtoTCP", //XXX
					Proto:        "TCP",       //XXX
					InternalPort: intp,
					PublicPort:   pubp,
				}
				mf.Spec.Ports = append(mf.Spec.Ports, pd)
			}
		}
	}
	return nil
}

func DeleteDockerSwarmAppManifest(mf *Manifest) error {
	log.DebugLog(log.DebugLevelMexos, "delete docker-swarm app")
	rootLB, err := getRootLB(mf.Spec.RootLB)
	if err != nil {
		return err
	}
	if rootLB == nil {
		return fmt.Errorf("docker swarm app manifest, rootLB is null")
	}
	name, err := FindClusterWithKey(mf, mf.Spec.Key)
	if err != nil {
		return fmt.Errorf("can't find cluster with key %s, %v", mf.Spec.Key, err)
	}
	masteraddr, err := FindNodeIP(name)
	if err != nil {
		return err
	}
	var cmd string
	if GetCloudletDockerPass() == "" {
		return fmt.Errorf("empty docker registry password environment variable")
	}
	client, err := GetSSHClient(rootLB.Name, GetCloudletExternalNetwork(), sshUser)
	if err != nil {
		return err
	}
	base := rootLB.PlatConf.Base
	if base == "" {
		log.DebugLog(log.DebugLevelMexos, "base is empty, using default")
		base = GetDefaultRegistryBase(mf, base)
	}
	mani := mf.Config.ConfigDetail.Manifest
	fn := fmt.Sprintf("%s/%s", base, mani)
	res, err := GetURIFile(mf, fn)
	if err != nil {
		return fmt.Errorf("error getting docker compose manifest, %v", err)
	}
	dc := &DockerCompose{}
	if err := yaml.Unmarshal(res, dc); err != nil {
		return fmt.Errorf("cannot unmarshal docker compose file, %v", err)
	}
	log.DebugLog(log.DebugLevelMexos, "removing docker stack", "name", mf.Metadata.Name)
	cmd = fmt.Sprintf("ssh -i id_rsa_mex %s docker stack rm  %s", masteraddr, mf.Metadata.Name)
	out, err := client.Output(cmd)
	if err != nil {
		return fmt.Errorf("error removing docker-swarm app, %s, %s, %v", cmd, out, err)
	}
	if err := DockerComposePorts(mf, dc); err != nil {
		return err
	}
	log.DebugLog(log.DebugLevelMexos, "removing proxy and security rules", "name", mf.Metadata.Name)
	if err = DeleteProxySecurityRules(rootLB, mf, masteraddr, appInst); err != nil {
		log.DebugLog(log.DebugLevelMexos, "cannot create security rules", "error", err)
		return err
	}
	log.DebugLog(log.DebugLevelMexos, "ok, docker stack removed", "name", mf.Metadata.Name)
	// TODO add custom DNS entries per app service endpoints
	return nil
}
*/
