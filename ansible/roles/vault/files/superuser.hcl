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

path "*" {
	capabilities = ["read", "list"]
}

path "+/jwtkeys/*" {
	capabilities = ["create", "read", "update", "delete", "list"]
}

path "+/jwtkeys/*" {
	capabilities = ["create", "read", "update", "delete", "list"]
}

path "jwtkeys/*" {
	capabilities = ["create", "read", "update", "delete", "list"]
}

path "secret/*" {
	capabilities = ["create", "read", "update", "delete", "list"]
}

path "certs/*" {
	capabilities = ["read"]
}

path "auth/github/map/users/+" {
	capabilities = ["create", "read", "update", "delete", "list"]
}

# Override limitations set in the github-dev policy
path "secret/data/ansible/*" {
	capabilities = ["create", "read", "update", "delete", "list"]
}

path "secret/metadata/ansible/*" {
	capabilities = ["create", "read", "update", "delete", "list"]
}

path "secret/data/ansible/main/*" {
	capabilities = ["create", "read", "update", "delete", "list"]
}

path "secret/metadata/ansible/main/*" {
	capabilities = ["create", "read", "update", "delete", "list"]
}

path "secret/data/ansible/prod/*" {
	capabilities = ["create", "read", "update", "delete", "list"]
}

path "secret/metadata/ansible/prod/*" {
	capabilities = ["create", "read", "update", "delete", "list"]
}

path "secret/data/ansible/internal/*" {
	capabilities = ["create", "read", "update", "delete", "list"]
}

path "secret/metadata/ansible/internal/*" {
	capabilities = ["create", "read", "update", "delete", "list"]
}
