#! /bin/bash
# Copyright 2022 MobiledgeX, Inc
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.


# If getting_started_vars.yml is not there, create it
if [[ ! -f getting_started_vars.yml ]]; then
cat <<EOF >getting_started_vars.yml
golang_package_cache: /tmp/golang
golang_version: 1.12.13
golang_checksum: sha256:6d3de6f7d7c0e8162aaa009128839fa5afcba578dcbd6ff034a82419d82480e9 
EOF
fi 

cat <<EOF >inventory
[localhost]
127.0.0.1  ansible_connection=local
EOF

# Check if brew is installed
which brew &> /dev/null  
if [[ ! $? -eq 0  ]]; then
    echo brew not installed, installing it 
    # echo /usr/bin/ruby -e "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/master/install)"
    /usr/bin/ruby -e "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/master/install)"
else
    echo brew is installed
fi

#Check if pip is installed
which pip &> /dev/null
if [[ ! $? -eq 0  ]]; then
#    echo pip not installed, installing it
#    curl https://bootstrap.pypa.io/get-pip.py -o get-pip.py
#    python get-pip.py
    brew install python@2
else
    echo pip is installed
fi

# Check if Ansible is installed
which ansible &> /dev/null
if [[ ! $? -eq 0  ]]; then
    echo ansible not installed, installing it
    brew install ansible
else
    echo ansible is installed
fi
# genrate golang.yml playbook
cat <<EOF >golang.yml
- hosts: localhost
  vars_files:
    - getting_started_vars.yml
  
  tasks: 

  - name: Create golang package directory
    file:
      path:  '{{golang_package_cache}}'
      state: directory

  - name: Download golang
    get_url:
      url: 'https://dl.google.com/go/go{{golang_version}}.darwin-amd64.tar.gz'
      dest: '{{golang_package_cache}}/go{{golang_version}}.darwin-amd64.tar.gz'
      checksum: '{{golang_checksum}}'

  - name: Install golang
    unarchive:
      src: '{{golang_package_cache}}/go{{golang_version}}.darwin-amd64.tar.gz'
      dest: /usr/local
      remote_src: true
    become: true
EOF
# install golang if needed
which go &> /dev/null
if [[ ! $? -eq 0  ]]; then
    echo go not installed, installing it. Supply root password if you are prompted for password
    sudo ansible-playbook  golang.yml 
else
    echo go is installed
fi

which git &> /dev/null
if [[ ! $? -eq 0  ]]; then
    echo git not installed, installing it.
    brew install git
else
    echo git is installed
fi

# Generate brew.yml

cat <<EOF >brew.yml
- hosts: localhost
  vars_files:
    - getting_started_vars.yml
  
  tasks: 
  - homebrew:
      name:  "{{ item }}"
      state: present
    loop: 
      - protobuf
      - etcd
      - influxdb
      - postgres
      - vault
      - wget
      - md5sha1sum
      - kubernetes-helm
EOF

# Install brew packages
ansible-playbook -i inventory brew.yml

# Generate pip.yml
cat <<EOF >pip.yml
- hosts: localhost
  vars_files:
    - getting_started_vars.yml
  
  tasks: 
  - name: Install python openstackclient, heatclient and gnocchiclient using pip
    pip:
      name:  "{{ item }}"
      state: present
    loop: 
      - python-openstackclient 
      - python-heatclient
      - gnocchiclient
EOF

# Install pip packages
echo "Invoking pip.yml ansible playbook."
ansible-playbook -i inventory pip.yml

# Generate git.yml
cat <<EOF >git.yml
- hosts: localhost
  vars_files:
    - getting_started_vars.yml
  
  tasks: 
  - name: Add env variables to user profile
    lineinfile:
      path: "{{ item.name }}"
      line: "{{ item.value }}"
    with_items:
      - { name: '~/.bash_profile', value: 'export GOROOT=/usr/local/go' }
      - { name: '~/.bash_profile', value: 'export GOPATH=~/go' }
      - { name: '~/.bash_profile', value: 'export PATH=\$PATH:\$GOROOT/bin' }
      - { name: '~/.bash_profile', value: 'export PATH=\$PATH:\$GOPATH/bin' }
      - { name: '~/.bash_profile', value: 'export GO111MODULE=on' }

  - name: Install Go tools
    shell:
      cmd: "cd /tmp; go get -u github.com/pseudomuto/protoc-gen-doc/cmd/protoc-gen-doc"


  - name: Clone edge-cloud, edge-cloud-infra, edge-proto, grpc-gateway directories
    debug:
      msg:  "In the next step, If git clone succeeds please ignore this message. Otherwise If git clone failed because of existing changes, please do a manual merge or checkin if you need the changes or git stash them if you do not and rerun."


  - name: Clone edge-cloud, edge-cloud-infra, edge-proto, grpc-gateway directories
    git:
      name:  "{{ item.name }}"
      dest: "{{ item.handle }}"
      clone: yes
      update: yes
    loop: 
      - { name: 'https://github.com/mobiledgex/edge-cloud.git', handle: '~/go/src/github.com/mobiledgex/edge-cloud' }
      - { name: 'https://github.com/mobiledgex/edge-cloud-infra.git', handle: '~/go/src/github.com/mobiledgex/edge-cloud-infra' }
      - { name: 'https://github.com/mobiledgex/edge-proto.git', handle: '~/go/src/github.com/mobiledgex/edge-proto' }
      - { name: 'https://github.com/mobiledgex/grpc-gateway.git', handle: '~/go/src/github.com/grpc-ecosystem/grpc-gateway' }
    
  
  - name: Run go mod download and make tools in edge-cloud directory
    shell:
      cmd:  "cd ~/go/src/github.com/mobiledgex/edge-cloud; GO111MODULE=on go mod download; make tools"

  - name: Run make , make unit-test  in edge-cloud-infra directory
    shell:
      cmd:  "cd ~/go/src/github.com/mobiledgex/edge-cloud-infra;  make ;  make unit-test"

  - name: Run  make test in edge-cloud-infra directory. This takes time as there are lots of tests.
    shell:
      cmd:  "cd ~/go/src/github.com/mobiledgex/edge-cloud-infra;   make test"

  - name: Run make install-dind in edge-cloud directory
    shell:
      cmd:  "cd ~/go/src/github.com/mobiledgex/edge-cloud; make install-dind"
EOF
# Install git packages
echo "Invoking git.yml ansible playbook."
ansible-playbook -i inventory git.yml

