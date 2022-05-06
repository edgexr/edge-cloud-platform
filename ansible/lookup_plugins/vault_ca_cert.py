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
lookup: vault_ca_cert
short_description: return vault CA cert chain
description:
  - return a vault CA cert chain for the list of vault PKI mounts
options:
  _terms:
    description:
        - list of vault pki mount points
    required: True
"""

EXAMPLES="""
  - set_fact:
      ca_chain: "{{ query('vault_ca_cert', 'pki-global', 'pki') }}"
  - debug: var=ca_chain
"""

from ansible.errors import AnsibleError, AnsibleParserError
from ansible.plugins.lookup import LookupBase
from ansible.utils.display import Display

from OpenSSL import crypto

try:
    import requests
    HAS_REQUESTS = True
except ImportError as e:
    HAS_REQUESTS = False

display = Display()

class LookupModule(LookupBase):

    def run(self, terms, variables=None, **kwargs):
        if variables is not None:
            self._templar.available_variables = variables
        myvars = getattr(self._templar, '_available_variables', {})

        if len(terms) < 1:
            raise AnsibleError('PKI mounts to look up not provided')

        vault_addr_key = 'vault_address'
        try:
            vault_addr = kwargs.get(vault_addr_key, myvars[vault_addr_key])
        except KeyError:
            raise AnsibleError("Could not find vault address variable: {0}".format(vault_addr_key))

        ca_chain = []
        has_root_ca = False

        for pki in terms:
            url = "{0}/v1/{1}/ca/pem".format(vault_addr, pki)
            display.vv("CA URL: {0}".format(url))
            r = requests.get(url)
            if r.status_code != requests.codes.ok:
                display.vvv("Request: {0}".format(r.request.__dict__))
                raise AnsibleError("Vault CA cert lookup return response code: {0}".format(r.status_code))
            display.vvv("CA cert: {0}".format(r.text))
            ca_cert = r.text
            ca_chain.append(ca_cert)

            c = crypto.load_certificate(crypto.FILETYPE_PEM, ca_cert)
            if c.get_subject() == c.get_issuer():
                has_root_ca = True

        return ({
            "ca_chain": ca_chain,
            "has_root_ca": has_root_ca,
        })
