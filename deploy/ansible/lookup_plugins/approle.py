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
lookup: approle
short_description: get app role credentials for given role
description:
  - Get app role ID and secret for given role
  - Also invalidate any existing secrets for the same role instance
options:
  _terms:
    description: Name of the role to look up in vault
    required: True
  vault_addr:
    description: The vault to connect to
    default: The "vault_address" ansible variable
    required: False
  vault_token:
    description: Token to use for vault access
    default: The "vault_token" ansible variable
    required: False
  id:
    description: ID for the vault approle
    default: The role name
    required: False
  scope:
    description: Variable to use to scope the token
    default: None
    required: False
"""

EXAMPLES="""
  - name: Get EU DME role ID and secret
    set_fact:
      role_lookup: "{{ lookup('approle', 'eu.dme') }}"
"""

from ansible.errors import AnsibleError, AnsibleParserError
from ansible.plugins.lookup import LookupBase
from ansible.utils.display import Display

import json
import os
import re

try:
    import requests
    HAS_REQUESTS = True
except ImportError as e:
    HAS_REQUESTS = False

display = Display()

class LookupModule(LookupBase):

    def _validate_operation(self, op, resp):
        """Helper function to validate vault API responses"""
        if resp.status_code not in (requests.codes.ok, requests.codes.no_content):
            raise AnsibleError("Failed operation: {0}: {1}: {2} {3}".format(
                op, resp.request.url, resp.status_code, resp.text))
        display.vvv("{0} => {1} {2}".format(resp.request.url, resp.status_code, resp.text))

    def _role_creds(self, vault_addr, vault_token, role_name):
        """Return a closure to look up approle ID and secret for given role name"""
        url_base = "{0}/v1/auth/approle/role/{1}".format(vault_addr, role_name)
        headers = {'X-Vault-Token': vault_token}
        method_map = {
            'role-id': 'GET',
            'secret-id': 'POST',
        }
        display.vvv("Vault approle URL base: {0}".format(url_base))

        def lookup(item):
            if item not in method_map:
                raise AnsibleError("Unknown lookup type: {0}".format(item))
            r = requests.request(method_map[item], url_base + '/' + item, headers=headers)
            self._validate_operation("Lookup \"{0}\"".format(item), r)
            try:
                return r.json()['data']
            except Exception as e:
                raise AnsibleError("Lookup error: {0}: {1}".format(item, e))

        return lookup

    def _store_accessor(self, vault_addr, vault_token, role_name, accessor, lookup_id):
        """Invalidate old role secret and store current secret accessor"""
        url = "{0}/v1/secret/data/approle/accessors/{1}".format(vault_addr, lookup_id)
        headers = {'X-Vault-Token': vault_token}
        display.vvv("Vault accessor store URL: {0}".format(url))

        r = requests.get(url, headers=headers)
        if r.status_code == requests.codes.not_found:
            display.vv("No older role secrets to invalidate")
        else:
            self._validate_operation("Lookup accessor", r)

            old_accessor = r.json()['data']['data']['value']
            display.vv("Invalidating old accessor: {0}".format(old_accessor))
            destroy_url = "{0}/v1/auth/approle/role/{1}/secret-id-accessor/destroy".format(
                        vault_addr, role_name)
            display.vvv("Vault secret ID destroy URL: {0}".format(destroy_url))
            r = requests.post(destroy_url,
                              headers=headers,
                              json={'secret_id_accessor': old_accessor})
            if r.status_code not in (requests.codes.ok, requests.codes.no_content):
                display.warning("Failed to invalidate old accessor: {0} {1}".format(
                    r.status_code, r.text))
            display.vvv("{0} => {1} {2}".format(r.request.url, r.status_code, r.text))

        display.vvv("Storing accessor: {0}".format(accessor))
        r = requests.post(url, headers=headers, json={'data': {'value': accessor}})
        self._validate_operation("Store accessor", r)

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

        role_name = terms[0]
        display.debug("Role name: {0}".format(role_name))

        # Load defaults
        vault_addr_key = 'vault_address'
        try:
            vault_addr = kwargs.get(vault_addr_key, myvars[vault_addr_key])
        except KeyError:
            raise AnsibleError("Could not find vault address variable: {0}".format(vault_addr_key))
        display.vv("Vault address: {0}".format(vault_addr))

        vault_token_key = 'vault_token'
        try:
            vault_token = kwargs.get(vault_token_key, myvars[vault_token_key])
        except Exception as e:
            raise AnsibleError("Failed to retrieve vault token: {0}: {1}".format(vault_token_key, e))
        display.vvv("Vault token: {0}".format(vault_token))

        lookup_id = kwargs.get('id', role_name)
        revoke_old = kwargs.get('revoke_old', 'yes')
        token_scope = kwargs.get('scope', None)
        if token_scope:
            scope_val = self._templar.template(myvars.get(token_scope))
            display.vv("Token scope: {0} ({1})".format(token_scope, scope_val))
            lookup_id = scope_val + "_" + lookup_id
        display.v("Lookup unique ID: {0}".format(lookup_id))

        lookup = self._role_creds(vault_addr, vault_token, role_name)
        resp = lookup('role-id')
        resp.update(lookup('secret-id'))

        accessor = resp.pop('secret_id_accessor')
        if revoke_old == 'yes':
            # Revoke old secret and store accessor for current
            self._store_accessor(vault_addr, vault_token, role_name, accessor, lookup_id)
        else:
            display.v("NOT storing accessor or revoking old secret")

        ret.append(resp)

        return ret
