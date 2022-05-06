## Creating an API key for esproxy

```
TAG=dev
http --auth elastic POST https://3dd88757c3df44ac8960e53fc6a9a2d5.us-central1.gcp.cloud.es.io:9243/_security/api_key <<EOT
{
  "name": "esproxy-${TAG}",
  "role_descriptors": {
    "esproxy-${TAG}": {
      "cluster": [ "manage_index_templates", "monitor" ],
      "index": [
        {
          "names": [ "events-log-${TAG}-*" ],
          "privileges": [
            "create",
            "create_index",
            "write",
            "read",
            "monitor"
          ]
        }
      ]
    }
  }
}
EOT

ID=...
API_KEY=...
AUTH=$( echo -n "${ID}:${API_KEY}" | base64 )
vault kv put secret/ansible/common/accounts/esproxy apikey="$AUTH"
```

## Creating an API key for esproxy index management and cleanup

```
TAG=dev
http --auth elastic POST https://3dd88757c3df44ac8960e53fc6a9a2d5.us-central1.gcp.cloud.es.io:9243/_security/api_key <<EOT
{
  "name": "esproxy-cleanup-${TAG}",
  "role_descriptors": {
    "esproxy-cleanup-${TAG}": {
      "cluster": [],
      "index": [
        {
          "names": [ "events-log-${TAG}-*" ],
          "privileges": [
            "delete_index",
            "view_index_metadata"
          ]
        }
      ]
    }
  }
}
EOT

ID=...
API_KEY=...
AUTH=$( echo -n "${ID}:${API_KEY}" | base64 )
vault kv put secret/ansible/common/accounts/esproxy_cleanup apikey="$AUTH"
```
