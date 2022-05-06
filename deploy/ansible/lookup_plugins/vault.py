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

from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

DOCUMENTATION = """
lookup: vault
short_description: look up key values in Hashicorp vault
description:
  - Look up kv secret values from a Hashicorp vault
options:
  _terms:
    description:
        - Paths of the secrets to look up in the vault
        - Values returned in a dict with the key being the basename of path,
          with dashes replaced by underscores
        - Key can be overridden by specifying lookup in the form of "path:key"
        - Specific versions can be retrieved by adding "@version" to the path.
    required: True
  vault_addr:
    description: The vault to connect to
    default: The "vault_address" ansible variable
    required: False
  token:
    description: Vault token to use to look up secret
    default: The "vault_token" ansible variable
    required: False
  role_id:
    description: Vault role ID to generate the login token for; used if token is not provided
    default: The "VAULT_ROLE_ID" environment variable
    required: False
  secret_id:
    description: Vault secret ID of the role to generate the login token for; used if token is not provided
    default: The "VAULT_SECRET_ID" environment variable
    required: False
"""

EXAMPLES="""
  - name: Look up influx DB creds and GCP service account
    set_fact:
      vault_lookup: "{{ lookup('vault', influxdb_path, gcp_path, some_secret_version) }}"
    vars:
      influxdb_path: "secret/EU/accounts/influxdb"
      gcp_path: "secret/ansible/main/gcp-registry-reader-service-account:gcp"
      some_secret_version: "secret/some/thing@3:thing_3"

  - debug: var=vault_lookup.influxdb.data
  - debug: var=vault_lookup.gcp.data
  - debug: var=vault_lookup.thing_3.data
"""

from ansible.errors import AnsibleError, AnsibleParserError
from ansible.plugins.lookup import LookupBase
from ansible.utils.display import Display

import json
import os
import re
import time

try:
    import requests
    HAS_REQUESTS = True
except ImportError as e:
    HAS_REQUESTS = False

display = Display()

class LookupModule(LookupBase):

    def _lookup_path(self, vault_addr, path, version, token):
        url = "{0}/v1/{1}".format(vault_addr, path)
        if version:
            url += '?version={0}'.format(version)
        retries = 10
        while retries > 0:
            retries -= 1
            r = requests.get(url, headers={'X-Vault-Token': token})
            if r.status_code == requests.codes.ok:
                break
            if r.status_code == 502:
                # This is vault's status code for errors with third-party services,
                # for instance, when Azure's token generation takes too long.
                # Retry after a wait for these.
                time.sleep(5)
                continue
        else:
            raise AnsibleError("Vault lookup of path \"{0}\" returned response code \"{1}\"".format(
                url, r.status_code))

        try:
            resp = r.json()['data']
        except Exception as e:
            raise AnsibleError("Failed to retrieve vault data: {0}: {1}".format(
                path, e))

        return resp

    def run(self, terms, variables=None, **kwargs):
        if not HAS_REQUESTS:
            raise AnsibleError(
                'python requests package is required for vault lookups')

        if variables is not None:
            self._templar.available_variables = variables
        myvars = getattr(self._templar, '_available_variables', {})

        ret = []

        if len(terms) < 1:
            raise AnsibleError('vault lookup needs at least one path argument')

        try:
          paths = [ re.sub(r'^secret/(?:data/)?', 'secret/data/', x) for x in terms ]
        except Exception as e:
          raise AnsibleError("Error loading lookup paths; undefined variable in list, perhaps?")

        vault_addr_key = 'vault_address'
        try:
            vault_addr = kwargs.get(vault_addr_key, myvars[vault_addr_key])
        except KeyError:
            raise AnsibleError("Could not find vault address variable: {0}".format(vault_addr_key))
        display.vv("Vault address: {0}".format(vault_addr))

        version = kwargs.get('version', None)

        token = kwargs.get('token', os.getenv("VAULT_TOKEN"))
        if not token:
            vault_auth = {}
            for p in ('role_id', 'secret_id'):
                try:
                    vault_auth[p] = kwargs.get(p, None)
                    if not vault_auth[p]:
                        envvar = "VAULT_{0}".format(p.upper())
                        vault_auth[p] = os.environ[envvar]
                except KeyError:
                    raise AnsibleError("Unable to fetch vault \"{0}\" from lookup params or \"{1}\" environment variable".format(
                        p, envvar))

            url = "{0}/v1/auth/approle/login".format(vault_addr)
            r = requests.post(url, data=json.dumps(vault_auth))
            display.vvv("Vault login response: {0}".format(r.text))
            if r.status_code != requests.codes.ok:
                raise AnsibleError("Vault lookup return response code: {0}".format(r.status_code))

            try:
                token = r.json()['auth']['client_token']
            except Exception as e:
                raise AnsibleError("Failed to retrieve client token: {0}".format(e))

        display.vvv("Vault token: {0}".format(token))

        resp = {}
        for item in paths:
            tokens = item.split(':', 1)
            path = tokens.pop(0)
            key = None
            if tokens:
                key = tokens.pop()

            vers = path.split('@', 1)
            if len(vers) > 1 and int(vers[1]) > 0:
                path = vers[0]
                version = int(vers[1])
            else:
                version = None

            if not key:
                key = os.path.basename(path).replace('-', '_')

            resp[key] = self._lookup_path(vault_addr, path, version, token)

        ret.append(resp)

        return ret
