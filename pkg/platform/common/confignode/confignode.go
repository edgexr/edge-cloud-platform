package confignode

import (
	"bytes"
	"text/template"

	"github.com/edgexr/edge-cloud-platform/api/edgeproto"
	"github.com/edgexr/edge-cloud-platform/pkg/cloudcommon"
	"github.com/edgexr/edge-cloud-platform/pkg/mc/ormutil"
	"github.com/edgexr/edge-cloud-platform/pkg/objstore"
)

const CloudletNameHeader = "cloudlet-name"
const CloudletOrgHeader = "cloudlet-org"

type ConfigureNodeVars struct {
	Key                 edgeproto.CloudletNodeKey
	NodeType            cloudcommon.NodeType
	NodeRole            cloudcommon.NodeRole
	OwnerKey            objstore.ObjKey
	Password            string
	BasicAuth           string // for script only
	AnsiblePublicAddr   string
	ConfigureNodeScript string
}

var ConfigureNodeScript = `#!/bin/bash
set -e
echo $( date ) Running configure node
cd $( dirname $0 )
wgetargs=(-nv "--header=` + CloudletNameHeader + `: {{ .Key.CloudletKey.Name }}" "--header=` + CloudletOrgHeader + `: {{ .Key.CloudletKey.Organization }}" "--header=Authorization: {{ .BasicAuth }}")
echo "Checking ansible.tar.gz checksum"
wget "${wgetargs[@]}" -O ansible.tar.gz.md5 {{ .AnsiblePublicAddr }}/confignode/ansible.tar.gz.md5
cat ansible.tar.gz.md5
download=true
run_ansible=false
if [[ -f "ansible.tar.gz" ]]; then
    echo "Checking md5 for ansible.tar.gz"
    if md5sum -c ansible.tar.gz.md5; then
        echo "ansible.tar.gz md5 matches, skipping download"
        download=false
    else
        echo "ansible.tar.gz md5 mismatch, will download"
    fi
else
    echo "No local ansible.tar.gz, will download"
fi
if [[ $download == true ]]; then
    echo "Downloading ansible.tar.gz"
    wget "${wgetargs[@]}" -O ansible.tar.gz {{ .AnsiblePublicAddr }}/confignode/ansible.tar.gz
    echo "Clean up old directory"
    rm -Rf ./ansible
    echo "Expanding ansible archive"
    tar -xpf ansible.tar.gz
    run_update=true
fi
echo "Checking vars.yaml checksum"
wget "${wgetargs[@]}" -O vars.yaml.md5 {{ .AnsiblePublicAddr }}/confignode/vars.yaml.md5
cat vars.yaml.md5
download=true
if [[ -f "vars.yaml" ]]; then
    echo "Checking md5 for vars.yaml"
    if md5sum -c vars.yaml.md5; then
        echo "vars.yaml md5 matches, skipping download"
        download=false
    else
        echo "vars.yaml md5 mismatch, will download"
    fi
else
    echo "No local vars.yaml, will download"
fi
if [[ $download == true ]]; then
    echo "Downloading vars.yaml"
    wget "${wgetargs[@]}" -O vars.yaml {{ .AnsiblePublicAddr }}/confignode/vars.yaml
    run_update=true
    cp vars.yaml ansible/vars.yml
	cat ansible/vars.yml
fi
if [[ ! -f ansible_run_ok ]]; then
    echo "Ansible has not succeeded, will run"
    run_update=true
fi
if [[ ${run_update} == true ]]; then
    echo "Running update"
    if [[ -z "${ANSIBLE_PLAYBOOK_BIN}" ]]; then
        ANSIBLE_PLAYBOOK_BIN=ansible-playbook
    fi
    if ${ANSIBLE_PLAYBOOK_BIN} -e @ansible/vars.yml ./ansible/playbook.yml -v; then
        touch ansible_run_ok
    else
        rm -f ansible_run_ok
        exit 1
    fi
else
    echo "No update needed"
fi
`

var configureNodeScriptT = template.Must(template.New("configureNodeScript").Parse(ConfigureNodeScript))

func (s *ConfigureNodeVars) GenScript() error {
	s.BasicAuth = ormutil.EncodeBasicAuth(s.Key.Name, s.Password)

	buf := bytes.Buffer{}
	err := configureNodeScriptT.Execute(&buf, s)
	if err != nil {
		return err
	}
	s.ConfigureNodeScript = buf.String()
	return nil
}
