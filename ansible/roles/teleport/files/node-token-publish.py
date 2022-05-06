#!/usr/bin/python3
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


import argparse
import base64
import json
import logging
import os
import re
import requests
import subprocess
import sys
from tempfile import TemporaryDirectory

TOKEN_TTL = "6h"
TOKEN_RE = re.compile(r'invite token: (.+)\.$')
CA_PIN_RE = re.compile(r'--ca-pin=(sha256:[^\s]+)')

def vault_upload_api(vault_config):
    vault_addr = vault_config["vault_addr"]
    r = requests.post(f"{vault_addr}/v1/auth/approle/login",
                      json={
                          "role_id": vault_config["role_id"],
                          "secret_id": vault_config["secret_id"],
                      })
    if r.status_code != requests.codes.ok:
        raise Exception(f"Failed to generate vault token: {vault_addr}: {r.status_code} {r.text}")

    token = r.json()["auth"]["client_token"]

    def post(node_token, ca_pin):
        r = requests.post(f"{vault_addr}/v1/secret/data/ansible/common/teleport-node-token",
                          headers={"X-Vault-Token": token},
                          json={
                              "data": {
                                  "value": node_token,
                                  "ca_pin": ca_pin,
                              },
                          })
        if r.status_code != requests.codes.ok:
            raise Exception(f"Failed to upload teleport-node-token: {r.status_code} {r.text}")

        # Clean out older versions of the tokens
        rv = requests.post(f"{vault_addr}/v1/secret/metadata/ansible/common/teleport-node-token",
                          headers={"X-Vault-Token": token},
                          json={
                              "max_versions": 6,
                          })
        if rv.status_code != requests.codes.no_content:
            logging.warning(f"Failed to set max_versions for teleport-node-token: {rv.status_code} {rv.text}")

        return r.json()

    return post

def get_token(setup):
    command = ["/usr/local/bin/tctl", "nodes", "add",
               f"--ttl={TOKEN_TTL}",
               "--roles=node"]
    logging.debug(command)

    p = subprocess.run(command, stdout=subprocess.PIPE,
                       stderr=subprocess.PIPE, timeout=30, text=True)
    if p.returncode != 0:
        raise Exception(f"{command}: rc={p.returncode} stdout={p.stdout} "
                        f"stderr={p.stderr}")

    # Unfortunately, teleport does not have a machine-readable output format
    token = ca_pin = None
    for line in p.stdout.splitlines():
        m = TOKEN_RE.search(line)
        if m:
            token = m.group(1)
            continue

        m = CA_PIN_RE.search(line)
        if m:
            ca_pin = m.group(1)
            continue

    if not token or not ca_pin:
        raise Exception(f"Failed to extract token and CA pin: {p.stdout}")

    return token, ca_pin

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("setup", help="Setup")
    parser.add_argument("--config", help="Config file")
    parser.add_argument("--debug", help="Print debug output", action="store_true")
    args = parser.parse_args()

    log_level = logging.DEBUG if args.debug else logging.INFO
    logging.basicConfig(level=log_level)

    if not args.config:
        args.config = os.path.join("/etc/vault_roles", f"{args.setup}.json")

    with open(args.config) as f:
        vault_config = json.load(f)

    try:
        upload = vault_upload_api(vault_config)
        token, ca_pin = get_token(args.setup)
        r = upload(token, ca_pin)
        logging.debug(f"Upload response: {r}")
    except Exception as e:
        logging.exception(f"Error uploading token: {e}")
        sys.exit(2)
