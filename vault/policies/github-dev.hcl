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

# Allow read access to ansible secrets
path "secret/data/ansible/*" {
	capabilities = ["read", "list"]
}

path "secret/metadata/ansible/*" {
	capabilities = ["list"]
}

# Restrict read access to ansible secrets for "main", "prod", and "interna;"
path "secret/data/ansible/main/*" {
	capabilities = []
}

path "secret/metadata/ansible/main/*" {
	capabilities = []
}

path "secret/data/ansible/prod/*" {
	capabilities = []
}

path "secret/metadata/ansible/prod/*" {
	capabilities = []
}

path "secret/data/ansible/internal/*" {
	capabilities = []
}

path "secret/metadata/ansible/internal/*" {
	capabilities = []
}

# Allow read access to registry creds
path "secret/data/registry/*" {
	capabilities = ["read", "list"]
}

path "secret/metadata/registry/*" {
	capabilities = ["list"]
}

# Allow read access to cloudlet creds (openrc)
path "secret/data/cloudlet/*" {
	capabilities = ["read", "list"]
}

path "secret/metadata/cloudlet/*" {
	capabilities = ["list"]
}

path "secret/metadata/*" {
	capabilities = ["list"]
}

path "secret/metadata/+/cloudlet/*" {
	capabilities = ["list"]
}

path "secret/data/+/cloudlet/openstack/*" {
	capabilities = ["read", "list"]
}

path "secret/metadata/+/cloudlet/openstack/*" {
	capabilities = ["list"]
}

# Allow access to certs (including access to cert creation)
path "certs/*" {
	capabilities = ["read"]
}

# Allow access to the SSH OTPs
path "ssh/creds/otp" {
	capabilities = ["update"]
}
