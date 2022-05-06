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

def vault_policy_present(vault, data, check_mode=False):
    has_changed = True

    policy = data["name"]
    content = data["content"]
    meta = {}

    r = vault("sys/policies/acl", method="LIST")
    if policy in r["data"]["keys"]:
        r = vault("sys/policies/acl/{0}".format(policy))
        current_policy = r["data"]["policy"]
        if current_policy == content:
            has_changed = False

    if has_changed:
        if check_mode:
            meta["msg"] = "skipped, running in check mode"
        else:
            r = vault("sys/policies/acl/{0}".format(policy), method="PUT",
                      success_code=204,
                      json={"policy": content})
            meta["msg"] = "policy updated"
    else:
        meta["msg"] = "no change"

    return (has_changed, meta)

def vault_policy_absent(vault, data=None, check_mode=False):
    has_changed = False

    policy = data["name"]
    meta = {}

    r = vault("sys/policies/acl", method="LIST")
    if policy in r["data"]["keys"]:
        has_changed = True

    if has_changed:
        if check_mode:
            meta["msg"] = "skipped, running in check mode"
        else:
            r = vault("sys/policies/acl/{0}".format(policy), method="DELETE",
                      success_code=204)
            meta["msg"] = "policy deleted"

    return (has_changed, meta)

def main():
    fields = {
        "name": {"required": True, "type": "str"},
        "content": {"type": "str"},
        "vault_addr": {"required": True, "type": "str"},
        "vault_token": {"required": True, "type": "str"},
        "state": {
            "default": "present",
            "choices": ["present", "absent"],
            "type": "str",
        },
    }
    choice_map = {
        "present": vault_policy_present,
        "absent": vault_policy_absent,
    }

    module = AnsibleModule(argument_spec=fields,
                           supports_check_mode=True,
                           required_if=[
                               ["state", "present", ["content"]],
                           ])
    vault = vault_request(module.params["vault_addr"], module.params["vault_token"])
    has_changed, result = choice_map.get(module.params["state"])(
        vault, data=module.params, check_mode=module.check_mode)
    module.exit_json(changed=has_changed, meta=result)

if __name__ == '__main__':
    main()
