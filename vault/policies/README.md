## Vault Policies

### Github Auth for Devs

This allows devs to log in using their Github personal access tokens and access Ansible secrets.

#### Usage

   * Create a [Github personal access token](https://help.github.com/en/articles/creating-a-personal-access-token-for-the-command-line)
       * You only need "read:org" permissions for the personal access token to use it for Vault auth.
   * Login using the token:
   * ```
       export VAULT_ADDR=https://vault.mobiledgex.net
       vault login -method=github token="MY_TOKEN"
       vault kv list secret/ansible/stage
     ```

#### Setup

```
vault auth enable github
vault write auth/github/config organization=mobiledgex ttl=15m max_ttl=15m

vault policy write github-dev github-dev.hcl
vault write auth/github/map/teams/edge-cloud-development-team value=github-dev
```
