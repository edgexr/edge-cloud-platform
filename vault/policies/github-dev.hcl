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
