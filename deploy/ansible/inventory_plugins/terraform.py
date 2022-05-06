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

EXAMPLES = r'''
    # ansible-playbook -i staging.tf.yml mexplay.yml
'''

import json
import os
import subprocess

from ansible.errors import AnsibleError, AnsibleParserError
from ansible.plugins.inventory import BaseInventoryPlugin

class InventoryModule(BaseInventoryPlugin):

    NAME = 'terraform'

    def verify_file(self, path):
        valid = False
        if super(InventoryModule, self).verify_file(path):
            if path.endswith('.tf.yml'):
                valid = True
        return valid

    def parse(self, inventory, loader, path, cache=True):
        super(InventoryModule, self).parse(inventory, loader, path, cache)

        config = self._read_config_data(path)
        tfdir = os.path.join(os.path.dirname(os.path.realpath(__file__)), '../../terraform', config['dir'])
        key = config['key']

        self.inventory.add_group(key)

        p = subprocess.Popen(['terraform', 'output', '-json'], stdout=subprocess.PIPE, cwd=tfdir)
        (out, err) = p.communicate()
        tfoutput = json.loads(out)
        if key not in tfoutput:
            raise AnsibleError("Key not found in terraform output: {0}".format(key))

        for entry in tfoutput[key]['value']:
            self.inventory.add_host(entry['hostname'], group=config['key'])
