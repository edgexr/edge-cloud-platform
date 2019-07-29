path "secret/data/ansible/*" {
	capabilities = ["read", "list"]
}

path "secret/metadata/ansible/*" {
	capabilities = ["list"]
}

path "secret/data/ansible/main/*" {
	capabilities = ["deny"]
}

path "secret/metadata/ansible/main/*" {
	capabilities = ["deny"]
}

path "secret/data/ansible/prod/*" {
	capabilities = ["deny"]
}

path "secret/metadata/ansible/prod/*" {
	capabilities = ["deny"]
}

path "secret/data/ansible/internal/*" {
	capabilities = ["deny"]
}

path "secret/metadata/ansible/internal/*" {
	capabilities = ["deny"]
}
