#!/usr/bin/python
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


from ansible.module_utils.basic import *
from ansible.module_utils.vault import vault_request

PARAM_DEFAULTS = {
    "max_lease_ttl": 259200, # 72h
}

vault_addr = None

def vault_pki_present(vault, data, check_mode=False):
    has_changed = False
    actions = []

    path = data.pop("path")
    pki_mount = path + "/"

    description = data.pop("description")
    max_lease_ttl = data.pop("max_lease_ttl")

    mounts = vault("sys/mounts")

    if pki_mount not in mounts:
        config = {"type": "pki"}
        if description:
            config["description"] = description
        vault("sys/mounts/{0}".format(path), method="POST", json=config,
              success_code=204)
        has_changed = True
        actions.append("Mount created: {0}".format(path))

        mounts = vault("sys/mounts")
    assert mounts[pki_mount]["type"] == "pki"

    curr_ttl = mounts[pki_mount]["config"]["max_lease_ttl"]
    if curr_ttl != max_lease_ttl:
        vault("sys/mounts/{0}/tune".format(path), method="POST",
              json={"max_lease_ttl": max_lease_ttl},
              success_code=204)
        has_changed = True
        actions.append("Max lease TTL configured")

    urls = {
        "issuing_certificates": "{0}/v1/{1}/ca".format(vault_addr, path),
        "crl_distribution_points": "{0}/v1/{1}/crl".format(vault_addr, path),
    }

    try:
        curr_urls = vault("{0}/config/urls".format(path))["data"]
    except Exception as e:
        curr_urls = {}

    for key in urls:
        if key not in curr_urls or curr_urls[key][0] != urls[key]:
            vault("{0}/config/urls".format(path), method="POST", json=urls,
                  success_code=204)
            has_changed = True
            actions.append("URLs configured")
            break

    return (has_changed, {"actions": actions})

def vault_pki_absent(vault, data, check_mode=False):
    has_changed = False
    actions = []

    path = data.pop("path")
    pki_mount = path + "/"

    mounts = vault("sys/mounts")
    if pki_mount in mounts:
        vault("sys/mounts/{0}".format(path), method="DELETE",
              success_code=204)
        has_changed = True
        actions.append("Mount deleted: {0}".format(path))

    return (has_changed, {"actions": actions})

def main():
    global vault_addr

    fields = {
        "path": {"required": True, "type": "str"},
        "description": {"type": "str"},
        "max_lease_ttl": {"type": "int", "default": PARAM_DEFAULTS["max_lease_ttl"]},
        "vault_addr": {"required": True, "type": "str"},
        "vault_token": {"required": True, "type": "str"},
        "state": {
            "default": "present",
            "choices": ["present", "absent"],
            "type": "str",
        },
    }
    choice_map = {
        "present": vault_pki_present,
        "absent": vault_pki_absent,
    }

    module = AnsibleModule(argument_spec=fields, supports_check_mode=True)
    vault_addr = module.params.pop("vault_addr")
    vault = vault_request(vault_addr, module.params.pop("vault_token"))
    has_changed, result = choice_map.get(module.params.pop("state"))(
        vault, data=module.params, check_mode=module.check_mode)
    module.exit_json(changed=has_changed, meta=result)

if __name__ == '__main__':
    main()
