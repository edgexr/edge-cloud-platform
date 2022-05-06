module letsencrypt-plugin

go 1.12

replace letsencrypt => ./letsencrypt

require (
	github.com/hashicorp/vault/api v1.0.4
	github.com/hashicorp/vault/sdk v0.1.13
	github.com/pkg/errors v0.8.1 // indirect
	letsencrypt v0.0.0-00010101000000-000000000000
)
