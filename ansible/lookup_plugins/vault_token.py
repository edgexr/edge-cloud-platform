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
lookup: vault_token
short_description: look up token details in Hashicorp vault
description:
  - Look up vault token details in Hashicorp vault
options:
  _terms:
    description:
        - Token to look up
    required: True
  vault_addr:
    description: The vault to connect to
    default: The "vault_address" ansible variable
    required: False
"""

EXAMPLES="""
  - name: Look up token details
    set_fact:
      vault_token_lookup: "{{ lookup('vault_token', token) }}"
    vars:
      token: "{{ lookup('env', 'VAULT_TOKEN') }}"

  - debug: var=vault_token_lookup
"""

from ansible.errors import AnsibleError, AnsibleParserError
from ansible.plugins.lookup import LookupBase
from ansible.utils.display import Display

try:
    import requests
    HAS_REQUESTS = True
except ImportError as e:
    HAS_REQUESTS = False

display = Display()

class LookupModule(LookupBase):

    def run(self, terms, variables=None, **kwargs):
        if not HAS_REQUESTS:
            raise AnsibleError(
                'python requests package is required for vault lookups')

        if variables is not None:
            self._templar.available_variables = variables
        myvars = getattr(self._templar, '_available_variables', {})

        ret = []

        if len(terms) < 1:
            raise AnsibleError('Token to look up not provided')

        vault_addr_key = 'vault_address'
        try:
            vault_addr = kwargs.get(vault_addr_key, myvars[vault_addr_key])
        except KeyError:
            raise AnsibleError("Could not find vault address variable: {0}".format(vault_addr_key))

        url = "{0}/v1/auth/token/lookup-self".format(vault_addr)
        display.vv("Vault API: {0}".format(url))
        r = requests.get(url, headers={"X-Vault-Token": terms[0]})
        if r.status_code != requests.codes.ok:
            display.vvv("Request: {0}".format(r.request.__dict__))
            raise AnsibleError("Vault lookup return response code: {0}".format(r.status_code))

        return r.json()
